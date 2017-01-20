/**
 * Copyright 2016 Yahoo Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yahoo.athenz.zms;

import java.io.File;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpHeaderValue;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.Slf4jRequestLog;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.rewrite.handler.HeaderPatternRule;
import org.eclipse.jetty.rewrite.handler.RewriteHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.glassfish.jersey.servlet.ServletContainer;

import com.yahoo.athenz.common.server.filters.DefaultMediaTypeFilter;
import com.yahoo.athenz.common.server.log.AthenzRequestLog;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.rest.HttpContainer;
import com.yahoo.athenz.common.server.rest.RestCoreResourceConfig;

public class ZMSJettyContainer extends HttpContainer {
    
    AuditLogger auditLogger = null;
    
    private static final Logger LOG = LoggerFactory.getLogger(ZMSJettyContainer.class);
    
    static final String ZMS_DEFAULT_EXCLUDED_CIPHER_SUITES = "SSL_RSA_WITH_DES_CBC_SHA,"
            + "SSL_DHE_RSA_WITH_DES_CBC_SHA,SSL_DHE_DSS_WITH_DES_CBC_SHA,"
            + "SSL_RSA_EXPORT_WITH_RC4_40_MD5,SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,"
            + "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
    static final String ZMS_DEFAULT_EXCLUDED_PROTOCOLS = "SSLv2,SSLv3";

    public ZMSJettyContainer(AuditLogger auditLog) {
        
        auditLogger = auditLog;
    }
    
    public void addRequestLogHandler(String rootDir) {
        
        RequestLogHandler requestLogHandler = new RequestLogHandler();
        
        // check to see if have a slf4j logger name specified. if we don't
        // then we'll just use our NCSARequestLog extended Athenz logger
        // when using the slf4j logger we don't have the option to pass
        // our audit logger to keep track of unauthenticated requests
        
        String accessSlf4jLogger = System.getProperty(ZMSConsts.ZMS_PROP_ACCESS_SLF4J_LOGGER);
        if (accessSlf4jLogger != null && !accessSlf4jLogger.isEmpty()) {
            
            Slf4jRequestLog requestLog = new Slf4jRequestLog();
            requestLog.setLoggerName(accessSlf4jLogger);
            requestLog.setExtended(true);
            requestLog.setPreferProxiedForAddress(true);
            requestLog.setLogTimeZone("GMT");
            requestLogHandler.setRequestLog(requestLog);
            
        } else {

            String logDir = System.getProperty(ZMSConsts.ZMS_PROP_ACCESS_LOG_DIR, rootDir + "/logs/zms_server");
            String logName = System.getProperty(ZMSConsts.ZMS_PROP_ACCESS_LOG_NAME, "access.yyyy_MM_dd.log");

            AthenzRequestLog requestLog = new AthenzRequestLog(logDir + File.separator + logName, auditLogger);
            requestLog.setAppend(true);
            requestLog.setExtended(true);
            requestLog.setPreferProxiedForAddress(true);
            requestLog.setLogTimeZone("GMT");
        
            String retainDays = System.getProperty(ZMSConsts.ZMS_PROP_ACCESS_LOG_RETAIN_DAYS, "31");
            int days = Integer.parseInt(retainDays);
            if (days > 0) {
                requestLog.setRetainDays(days);
            }
            requestLogHandler.setRequestLog(requestLog);
        }
        
        getHandlers().addHandler(requestLogHandler);
    }

    public void addServletHandlers(String serverHostName) {
        
        RewriteHandler rewriteHandler = new RewriteHandler();
        
        // Check whether or not to disable Keep-Alive support in Jetty.
        // This will be the first handler in our array so we always set
        // the appropriate header in response. However, since we're now
        // behind ATS, we want to keep the connections alive so ATS
        // can re-use them as necessary
        
        boolean keepAlive = Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_KEEP_ALIVE, "true"));

        if (!keepAlive) {
            HeaderPatternRule disableKeepAliveRule = new HeaderPatternRule();
            disableKeepAliveRule.setPattern("/*");
            disableKeepAliveRule.setName(HttpHeader.CONNECTION.asString());
            disableKeepAliveRule.setValue(HttpHeaderValue.CLOSE.asString());
            rewriteHandler.addRule(disableKeepAliveRule);
        }
        
        // Return a Host field in the response so during debugging
        // we know what server was handling request
        
        HeaderPatternRule hostNameRule = new HeaderPatternRule();
        hostNameRule.setPattern("/*");
        hostNameRule.setName(HttpHeader.HOST.asString());
        hostNameRule.setValue(serverHostName);
        rewriteHandler.addRule(hostNameRule);
        
        getHandlers().addHandler(rewriteHandler);

        // this sets up the default return media type when client accepts
        // any type of media
        addContainerRequestFilter(DefaultMediaTypeFilter.class);

        // setup application configuration for delegates

        RestCoreResourceConfig rconf = new RestCoreResourceConfig(resources, singletons);
        rconf.registerAll();

        // now setup our servlet handler
        //
        ServletContextHandler servletCtxHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        servletCtxHandler.setContextPath("/");

        ServletHolder holder = new ServletHolder(new ServletContainer(rconf));
        servletCtxHandler.addServlet(holder, "/*");

        getHandlers().addHandler(servletCtxHandler);
    }

    public HttpConfiguration newHttpConfiguration(int httpsPort) {

        // HTTP Configuration
        
        boolean sendServerVersion = Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_SEND_SERVER_VERSION, "false"));
        boolean sendDateHeader = Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_SEND_DATE_HEADER, "false"));
        int outputBufferSize = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_OUTPUT_BUFFER_SIZE, "32768"));
        int requestHeaderSize = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_REQUEST_HEADER_SIZE, "8192"));
        int responseHeaderSize = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_RESPONSE_HEADER_SIZE, "8192"));
        
        HttpConfiguration httpConfig = new HttpConfiguration();
        
        if (httpsPort > 0) {
            httpConfig.setSecureScheme("https");
            httpConfig.setSecurePort(httpsPort);
        }
        
        httpConfig.setOutputBufferSize(outputBufferSize);
        httpConfig.setRequestHeaderSize(requestHeaderSize);
        httpConfig.setResponseHeaderSize(responseHeaderSize);
        httpConfig.setSendServerVersion(sendServerVersion);
        httpConfig.setSendDateHeader(sendDateHeader);

        return httpConfig;
    }
    
    SslContextFactory createSSLContextObject() {
        
        String keyStorePath = System.getProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PATH);
        String keyStorePassword = System.getProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PASSWORD);
        String keyStoreType = System.getProperty(ZMSConsts.ZMS_PROP_KEYSTORE_TYPE, "PKCS12");
        String keyManagerPassword = System.getProperty(ZMSConsts.ZMS_PROP_KEYMANAGER_PASSWORD);
        String trustStorePath = System.getProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PATH);
        String trustStorePassword = System.getProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PASSWORD);
        String trustStoreType = System.getProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        String excludedCipherSuites = System.getProperty(ZMSConsts.ZMS_PROP_EXCLUDED_CIPHER_SUITES,
                ZMS_DEFAULT_EXCLUDED_CIPHER_SUITES);
        String excludedProtocols = System.getProperty(ZMSConsts.ZMS_PROP_EXCLUDED_PROTOCOLS,
                ZMS_DEFAULT_EXCLUDED_PROTOCOLS);
        
        SslContextFactory sslContextFactory = new SslContextFactory();
        if (keyStorePath != null) {
            LOG.info("Using SSL KeyStore path: " + keyStorePath);
            sslContextFactory.setKeyStorePath(keyStorePath);
        }
        if (keyStorePassword != null) {
            sslContextFactory.setKeyStorePassword(keyStorePassword);
        }
        sslContextFactory.setKeyStoreType(keyStoreType);

        if (keyManagerPassword != null) {
            sslContextFactory.setKeyManagerPassword(keyManagerPassword);
        }
        if (trustStorePath != null) {
            LOG.info("Using SSL TrustStore path: " + trustStorePath);
            sslContextFactory.setTrustStorePath(trustStorePath);
        }
        if (trustStorePassword != null) {
            sslContextFactory.setTrustStorePassword(trustStorePassword);
        }
        sslContextFactory.setTrustStoreType(trustStoreType);

        if (excludedCipherSuites.length() != 0) {
            sslContextFactory.setExcludeCipherSuites(excludedCipherSuites.split(","));
        }
        
        if (excludedProtocols.length() != 0) {
            sslContextFactory.setExcludeProtocols(excludedProtocols.split(","));
        }

        return sslContextFactory;
    }
    
    public void addHTTPConnectors(HttpConfiguration httpConfig, int httpPort, int httpsPort) {

        int idleTimeout = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_IDLE_TIMEOUT, "30000"));
        String listenHost = System.getProperty(ZMSConsts.ZMS_PROP_LISTEN_HOST);

        // HTTP Connector
        
        if (httpPort > 0) {
            ServerConnector connector = new ServerConnector(server, new HttpConnectionFactory(httpConfig));
            if (listenHost != null) {
                connector.setHost(listenHost);
            }
            connector.setPort(httpPort);
            connector.setIdleTimeout(idleTimeout);
            server.addConnector(connector);
        }
        
        // HTTPS Connector
        
        if (httpsPort > 0) {
            
            // SSL Context Factory

            SslContextFactory sslContextFactory = createSSLContextObject();

            // SSL HTTP Configuration
            
            HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
            httpsConfig.addCustomizer(new SecureRequestCustomizer());

            // SSL Connector
            
            ServerConnector sslConnector = new ServerConnector(server,
                    new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(httpsConfig));
            sslConnector.setPort(httpsPort);
            sslConnector.setIdleTimeout(idleTimeout);
            server.addConnector(sslConnector);
        }
    }
}
