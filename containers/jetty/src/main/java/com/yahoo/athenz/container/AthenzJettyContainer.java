/*
 * Copyright The Athenz Authors
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

package com.yahoo.athenz.container;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.server.log.jetty.AthenzConnectionListener;
import com.yahoo.athenz.common.server.log.jetty.AthenzRequestLog;
import com.yahoo.athenz.common.server.log.jetty.JettyConnectionLogger;
import com.yahoo.athenz.common.server.log.jetty.JettyConnectionLoggerFactory;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import com.yahoo.athenz.common.server.util.config.providers.ConfigProviderAwsParametersStore;
import com.yahoo.athenz.common.server.util.config.providers.ConfigProviderFile;
import com.yahoo.athenz.container.filter.HealthCheckFilter;
import jakarta.servlet.DispatcherType;
import org.eclipse.jetty.deploy.DeploymentManager;
import org.eclipse.jetty.deploy.providers.ContextProvider;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpHeaderValue;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.rewrite.handler.HeaderPatternRule;
import org.eclipse.jetty.rewrite.handler.RewriteHandler;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.StatisticsHandler;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.ee9.servlet.FilterHolder;
import org.eclipse.jetty.ee9.servlet.ServletContextHandler;
import org.eclipse.jetty.util.StringUtil;
import org.eclipse.jetty.util.ssl.KeyStoreScanner;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.InetAddress;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

public class AthenzJettyContainer {
    
    private static final Logger LOG = LoggerFactory.getLogger(AthenzJettyContainer.class);
    private static String ROOT_DIR;
    private static final String DEFAULT_WEBAPP_DESCRIPTOR = "/etc/webdefault.xml";

    static final String ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS = "SSLv2,SSLv3";

    private Server server = null;
    private String banner = null;
    private ContextHandlerCollection handlers = null;
    private PrivateKeyStore privateKeyStore;
    private final AthenzConnectionListener connectionListener = new AthenzConnectionListener();
    private final JettyConnectionLoggerFactory jettyConnectionLoggerFactory = new JettyConnectionLoggerFactory();
    
    public AthenzJettyContainer() {
        loadServicePrivateKey();
    }
    
    Server getServer() {
        return server;
    }
    
    ContextHandlerCollection getHandlers() {
        return handlers;
    }
    
    static String getServerHostName() {
        
        String serverHostName = System.getProperty(AthenzConsts.ATHENZ_PROP_HOSTNAME);
        if (StringUtil.isEmpty(serverHostName)) {
            try {
                InetAddress localhost = java.net.InetAddress.getLocalHost();
                serverHostName = localhost.getCanonicalHostName();
            } catch (java.net.UnknownHostException e) {
                LOG.info("Unable to determine local hostname: {}", e.getMessage());
                serverHostName = "localhost";
            }
        }
        
        return serverHostName;
    }
    
    public static String getRootDir() {
        
        if (ROOT_DIR == null) {
            ROOT_DIR = System.getProperty(AthenzConsts.ATHENZ_PROP_ROOT_DIR, AthenzConsts.STR_DEF_ROOT);
        }

        return ROOT_DIR;
    }
    
    public void addRequestLogHandler() {

        // check to see if we have a slf4j logger name specified. if we don't
        // then we'll just use our NCSARequestLog extended Athenz logger
        // when using the slf4j logger we don't have the option to pass
        // our audit logger to keep track of unauthenticated requests
        
        String accessSlf4jLogger = System.getProperty(AthenzConsts.ATHENZ_PROP_ACCESS_SLF4J_LOGGER);
        if (!StringUtil.isEmpty(accessSlf4jLogger)) {

            Slf4jRequestLogWriter slf4jRequestLogWriter = new Slf4jRequestLogWriter();
            slf4jRequestLogWriter.setLoggerName(accessSlf4jLogger);

            CustomRequestLog customRequestLog = new CustomRequestLog(slf4jRequestLogWriter, CustomRequestLog.EXTENDED_NCSA_FORMAT);
            server.setRequestLog(customRequestLog);

        } else {

            String logDir = System.getProperty(AthenzConsts.ATHENZ_PROP_ACCESS_LOG_DIR,
                    getRootDir() + "/logs/athenz");
            String logName = System.getProperty(AthenzConsts.ATHENZ_PROP_ACCESS_LOG_NAME,
                    "access.yyyy_MM_dd.log");
            boolean logForwardedForAddr = Boolean.parseBoolean(
                    System.getProperty(AthenzConsts.ATHENZ_PROP_LOG_FORWARDED_FOR_ADDR, "false"));

            RequestLogWriter logWriter = new RequestLogWriter(logDir + File.separator + logName);
            logWriter.setTimeZone("GMT");
            String retainDays = System.getProperty(AthenzConsts.ATHENZ_PROP_ACCESS_LOG_RETAIN_DAYS, "31");
            int days = Integer.parseInt(retainDays);
            if (days > 0) {
                logWriter.setRetainDays(days);
            }

            AthenzRequestLog requestLog = new AthenzRequestLog(logWriter);
            requestLog.setLogForwardedForAddr(logForwardedForAddr);
            server.setRequestLog(requestLog);
        }
    }
    
    public void addServletHandlers(String serverHostName) {

        // Handler Structure
        
        RewriteHandler rewriteHandler = new RewriteHandler();
        
        // Check whether to disable Keep-Alive support in Jetty.
        // This will be the first handler in our array, so we always set
        // the appropriate header in response. However, since we're now
        // behind ATS, we want to keep the connections alive so ATS
        // can re-use them as necessary
        
        boolean keepAlive = Boolean.parseBoolean(System.getProperty(AthenzConsts.ATHENZ_PROP_KEEP_ALIVE, "true"));

        if (!keepAlive) {
            HeaderPatternRule disableKeepAliveRule = new HeaderPatternRule();
            disableKeepAliveRule.setPattern("/*");
            disableKeepAliveRule.setHeaderName(HttpHeader.CONNECTION.asString());
            disableKeepAliveRule.setHeaderName(HttpHeaderValue.CLOSE.asString());
            rewriteHandler.addRule(disableKeepAliveRule);
        }
        
        // Add response-headers, according to configuration

        final String responseHeadersJson = System.getProperty(AthenzConsts.ATHENZ_PROP_RESPONSE_HEADERS_JSON);
        if (!StringUtil.isEmpty(responseHeadersJson)) {
            HashMap<String, String> responseHeaders;
            try {
                responseHeaders = new ObjectMapper().readValue(responseHeadersJson, new TypeReference<>() {
                });
            } catch (Exception exception) {
                throw new RuntimeException("System-property \"" + AthenzConsts.ATHENZ_PROP_RESPONSE_HEADERS_JSON + "\" must be a JSON object with string values. System property's value: " + responseHeadersJson);
            }

            for (Map.Entry<String, String>  responseHeader : responseHeaders.entrySet()) {
                HeaderPatternRule rule = new HeaderPatternRule();
                rule.setPattern("/*");
                rule.setHeaderName(responseHeader.getKey());
                rule.setHeaderValue(responseHeader.getValue());
                rewriteHandler.addRule(rule);
            }
        }

        // Return a Host field in the response so during debugging
        // we know what server was handling request
        
        HeaderPatternRule hostNameRule = new HeaderPatternRule();
        hostNameRule.setPattern("/*");
        hostNameRule.setHeaderName(HttpHeader.HOST.asString());
        hostNameRule.setHeaderValue(serverHostName);
        rewriteHandler.addRule(hostNameRule);
        
        handlers.addHandler(rewriteHandler);

        ContextHandlerCollection contexts = new ContextHandlerCollection();

        // check to see if gzip support is enabled

        boolean gzipSupport = Boolean.parseBoolean(System.getProperty(AthenzConsts.ATHENZ_PROP_GZIP_SUPPORT, "false"));

        if (gzipSupport) {
            int gzipMinSize = Integer.parseInt(
                    System.getProperty(AthenzConsts.ATHENZ_PROP_GZIP_MIN_SIZE, "1024"));

            GzipHandler gzipHandler = new GzipHandler();
            gzipHandler.setMinGzipSize(gzipMinSize);
            gzipHandler.setIncludedMimeTypes("application/json");
            gzipHandler.setHandler(contexts);

            handlers.addHandler(gzipHandler);
        }

        // check to see if graceful shutdown support is enabled

        boolean gracefulShutdown = Boolean.parseBoolean(
                System.getProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN, "false"));
        if (gracefulShutdown) {
            server.setStopAtShutdown(true);

            long stopTimeout = Long.parseLong(
                    System.getProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN_TIMEOUT, "30000"));
            server.setStopTimeout(stopTimeout);

            StatisticsHandler statisticsHandler = new StatisticsHandler();
            statisticsHandler.setHandler(contexts);

            handlers.addHandler(statisticsHandler);
        }

        handlers.addHandler(contexts);

        // now setup our default servlet handler for filters
        
        ServletContextHandler servletCtxHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        servletCtxHandler.setContextPath("/");
        
        FilterHolder filterHolder = new FilterHolder(HealthCheckFilter.class);
        final String healthCheckPath = System.getProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_PATH,
                getRootDir());
        filterHolder.setInitParameter(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_PATH, healthCheckPath);

        final String checkList = System.getProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST);

        if (!StringUtil.isEmpty(checkList)) {
            String[] checkUriArray = checkList.split(",");
            for (String checkUri : checkUriArray) {
                servletCtxHandler.addFilter(filterHolder, checkUri.trim(), EnumSet.of(DispatcherType.REQUEST));
            }
        }
        contexts.addHandler(servletCtxHandler);

        DeploymentManager deployer = new DeploymentManager();
        deployer.setContexts(contexts);

        final String jettyHome = System.getProperty(AthenzConsts.ATHENZ_PROP_JETTY_HOME, getRootDir());
        ContextProvider webappProvider = new ContextProvider();
        webappProvider.setEnvironmentName("ee9");
        webappProvider.setMonitoredDirName(jettyHome + "/webapps");
        webappProvider.setScanInterval(60);
        webappProvider.setExtractWars(true);
        webappProvider.setParentLoaderPriority(true);

        // set up a Default web.xml file.  file is applied to a Web application
        // before its own WEB_INF/web.xml

        setDefaultsDescriptor(webappProvider, jettyHome);

        deployer.addAppProvider(webappProvider);
        server.addBean(deployer);
    }

    private void setDefaultsDescriptor(ContextProvider webappProvider, String jettyHome) {

        // set up a Default web.xml file. file is applied to a Web application before
        // its own WEB_INF/web.xml. check for file existence

        String webDefaultXML = jettyHome + DEFAULT_WEBAPP_DESCRIPTOR;
        File file = new File(webDefaultXML);
        if (!file.exists()) {
            throw new RuntimeException("webdefault.xml not found in " + webDefaultXML);
        } 
        webappProvider.setDefaultsDescriptor(webDefaultXML);
    }
    
    public HttpConfiguration newHttpConfiguration() {

        // HTTP Configuration
        
        boolean sendServerVersion = Boolean.parseBoolean(
                System.getProperty(AthenzConsts.ATHENZ_PROP_SEND_SERVER_VERSION, "false"));
        boolean sendDateHeader = Boolean.parseBoolean(
                System.getProperty(AthenzConsts.ATHENZ_PROP_SEND_DATE_HEADER, "false"));
        int outputBufferSize = Integer.parseInt(
                System.getProperty(AthenzConsts.ATHENZ_PROP_OUTPUT_BUFFER_SIZE, "32768"));
        int requestHeaderSize = Integer.parseInt(
                System.getProperty(AthenzConsts.ATHENZ_PROP_REQUEST_HEADER_SIZE, "8192"));
        int responseHeaderSize = Integer.parseInt(
                System.getProperty(AthenzConsts.ATHENZ_PROP_RESPONSE_HEADER_SIZE, "8192"));
        
        HttpConfiguration httpConfig = new HttpConfiguration();
        
        httpConfig.setOutputBufferSize(outputBufferSize);
        httpConfig.setRequestHeaderSize(requestHeaderSize);
        httpConfig.setResponseHeaderSize(responseHeaderSize);
        httpConfig.setSendServerVersion(sendServerVersion);
        httpConfig.setSendDateHeader(sendDateHeader);

        return httpConfig;
    }
    
    void loadServicePrivateKey() {
        String pkeyFactoryClass = System.getProperty(AthenzConsts.ATHENZ_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                AthenzConsts.ATHENZ_PKEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid PrivateKeyStoreFactory class: {}", pkeyFactoryClass, ex);
            throw new IllegalArgumentException("Invalid private key store");
        }
        this.privateKeyStore = pkeyFactory.create();
    }
    
    SslContextFactory.Server createSSLContextObject(boolean needClientAuth) {
        
        final String keyStorePath = System.getProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH);
        final String keyStorePasswordAppName = System.getProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD_APPNAME);
        final String keyStorePasswordKeygroupName = System.getProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD_KEYGROUPNAME);
        final String keyStorePassword = System.getProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD);
        final String keyStoreType = System.getProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        final String keyManagerPassword = System.getProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD);
        final String keyManagerPasswordAppName = System.getProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD_APPNAME);
        final String keyManagerPasswordKeygroupName = System.getProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD_KEYGROUPNAME);
        final String trustStorePath = System.getProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH);
        final String trustStorePassword = System.getProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD);
        final String trustStorePasswordAppName = System.getProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD_APPNAME);
        final String trustStorePasswordKeygroupName = System.getProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD_KEYGROUPNAME);
        final String trustStoreType = System.getProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        final String includedCipherSuites = System.getProperty(AthenzConsts.ATHENZ_PROP_INCLUDED_CIPHER_SUITES);
        final String excludedCipherSuites = System.getProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_CIPHER_SUITES);
        final String excludedProtocols = System.getProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_PROTOCOLS, ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS);
        final boolean renegotiationAllowed = Boolean.parseBoolean(System.getProperty(AthenzConsts.ATHENZ_PROP_RENEGOTIATION_ALLOWED, "false"));

        SslContextFactory.Server sslContextFactory = new AthenzSslContextFactory();
        sslContextFactory.setEndpointIdentificationAlgorithm(null);

        if (!StringUtil.isEmpty(keyStorePath)) {
            LOG.info("Using SSL KeyStore path: {}", keyStorePath);
            sslContextFactory.setKeyStorePath(keyStorePath);
        }
        if (!StringUtil.isEmpty(keyStorePassword)) {
            //default implementation should just return the same
            sslContextFactory.setKeyStorePassword(String.valueOf(this.privateKeyStore.getSecret(keyStorePasswordAppName, keyStorePasswordKeygroupName, keyStorePassword)));
        }
        sslContextFactory.setKeyStoreType(keyStoreType);

        if (!StringUtil.isEmpty(keyManagerPassword)) {
            sslContextFactory.setKeyManagerPassword(String.valueOf(this.privateKeyStore.getSecret(keyManagerPasswordAppName, keyManagerPasswordKeygroupName, keyManagerPassword)));
        }
        if (!StringUtil.isEmpty(trustStorePath)) {
            LOG.info("Using SSL TrustStore path: {}", trustStorePath);
            sslContextFactory.setTrustStorePath(trustStorePath);
        }
        if (!StringUtil.isEmpty(trustStorePassword)) {
            sslContextFactory.setTrustStorePassword(String.valueOf(this.privateKeyStore.getSecret(trustStorePasswordAppName, trustStorePasswordKeygroupName, trustStorePassword)));
        }
        sslContextFactory.setTrustStoreType(trustStoreType);

        if (!StringUtil.isEmpty(includedCipherSuites)) {
            sslContextFactory.setIncludeCipherSuites(includedCipherSuites.split(","));
        }
        
        if (!StringUtil.isEmpty(excludedCipherSuites)) {
            sslContextFactory.setExcludeCipherSuites(excludedCipherSuites.split(","));
        }
        
        if (!excludedProtocols.isEmpty()) {
            sslContextFactory.setExcludeProtocols(excludedProtocols.split(","));
        }
        
        if (needClientAuth) {
            sslContextFactory.setNeedClientAuth(true);
        } else {
            sslContextFactory.setWantClientAuth(true);
        }

        sslContextFactory.setRenegotiationAllowed(renegotiationAllowed);
        sslContextFactory.setSniRequired(false);

        return sslContextFactory;
    }
    
    void addHTTPConnector(HttpConfiguration httpConfig, int httpPort, boolean proxyProtocol,
            String listenHost, int idleTimeout) {
        
        ServerConnector connector;
        if (proxyProtocol) {
            connector = new ServerConnector(server, new ProxyConnectionFactory(), new HttpConnectionFactory(httpConfig));
        } else {
            connector = new ServerConnector(server, new HttpConnectionFactory(httpConfig));
        }
        if (!StringUtil.isEmpty(listenHost)) {
            connector.setHost(listenHost);
        }
        connector.setPort(httpPort);
        connector.setIdleTimeout(idleTimeout);
        server.addConnector(connector);
    }
    
    void addHTTPSConnector(HttpConfiguration httpsConfig, int httpsPort, boolean proxyProtocol,
            String listenHost, int idleTimeout, boolean needClientAuth, JettyConnectionLogger connectionLogger) {
        
        // SSL Context Factory
    
        SslContextFactory.Server sslContextFactory = createSSLContextObject(needClientAuth);

        // SSL Connector
        
        ServerConnector sslConnector;
        if (proxyProtocol) {
            sslConnector = new ServerConnector(server, new ProxyConnectionFactory(),
                    new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(httpsConfig));
        } else {
            sslConnector = new ServerConnector(server,
                    new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(httpsConfig));
        }
        sslConnector.setPort(httpsPort);
        sslConnector.setIdleTimeout(idleTimeout);
        if (listenHost != null) {
            sslConnector.setHost(listenHost);
        }
        if (connectionLogger != null) {
            sslConnector.addBean(connectionLogger);
        }
        
        // Listen to when HTTP connections open/close/handshake.

        sslConnector.addBean(connectionListener);
        server.addConnector(sslConnector);

        // Reload the key-store if the file is changed

        final int reloadSslContextSeconds = Integer.parseInt(System.getProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_RELOAD_SEC, "0"));
        if ((reloadSslContextSeconds > 0) && (sslContextFactory.getKeyStorePath() != null)) {
            try {
                KeyStoreScanner keystoreScanner = new KeyStoreScanner(sslContextFactory);
                keystoreScanner.setScanInterval(reloadSslContextSeconds);
                server.addBean(keystoreScanner);
            } catch (IllegalArgumentException exception) {
                LOG.error("Keystore can't be automatically reloaded when \"{}\" is changed: {}",
                        sslContextFactory.getKeyStorePath(), exception.getMessage());
                throw exception;
            }
        }
    }

    HttpConfiguration getHttpsConfig(HttpConfiguration httpConfig, int httpsPort, boolean sniRequired, boolean sniHostCheck) {
        HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
        httpsConfig.setSecureScheme("https");
        httpsConfig.setSecurePort(httpsPort);
        httpsConfig.addCustomizer(new SecureRequestCustomizer(sniRequired, sniHostCheck, -1L, false));
        return httpsConfig;
    }

    public void addHTTPConnectors(HttpConfiguration httpConfig, int httpPort, int httpsPort,
            int oidcPort, int statusPort) {

        int idleTimeout = Integer.parseInt(
                System.getProperty(AthenzConsts.ATHENZ_PROP_IDLE_TIMEOUT, "30000"));
        String listenHost = System.getProperty(AthenzConsts.ATHENZ_PROP_LISTEN_HOST);
        boolean proxyProtocol = Boolean.parseBoolean(
                System.getProperty(AthenzConsts.ATHENZ_PROP_PROXY_PROTOCOL, "false"));

        // HTTP Connector
        
        if (httpPort > 0) {
            addHTTPConnector(httpConfig, httpPort, proxyProtocol, listenHost, idleTimeout);
        }

        // check to see if we need to create our connection logger
        // for TLS connection failures

        boolean logSSLFailures = Boolean.parseBoolean(
                System.getProperty(AthenzConsts.ATHENZ_PROP_SSL_LOG_FAILURES, "false"));
        JettyConnectionLogger connectionLogger = null;
        if (logSSLFailures) {
            connectionLogger = jettyConnectionLoggerFactory.create();
        }

        boolean sniRequired = Boolean.parseBoolean(
                System.getProperty(AthenzConsts.ATHENZ_PROP_SNI_REQUIRED, "false"));
        boolean sniHostCheck = Boolean.parseBoolean(
                System.getProperty(AthenzConsts.ATHENZ_PROP_SNI_HOSTCHECK, "true"));
        boolean needClientAuth = Boolean.parseBoolean(
                System.getProperty(AthenzConsts.ATHENZ_PROP_CLIENT_AUTH, "false"));

        // HTTPS Connector

        if (httpsPort > 0) {
            HttpConfiguration httpsConfig = getHttpsConfig(httpConfig, httpsPort, sniRequired, sniHostCheck);
            addHTTPSConnector(httpsConfig, httpsPort, proxyProtocol, listenHost,
                    idleTimeout, needClientAuth, connectionLogger);
        }

        // OIDC Connector - only if it's different from HTTPS

        if (oidcPort > 0 && oidcPort != httpsPort) {
            HttpConfiguration httpsConfig = getHttpsConfig(httpConfig, oidcPort, sniRequired, sniHostCheck);
            addHTTPSConnector(httpsConfig, oidcPort, proxyProtocol, listenHost,
                    idleTimeout, needClientAuth, connectionLogger);
        }

        // Status Connector - only if it's different from HTTP/HTTPS
        
        if (statusPort > 0 && statusPort != httpPort && statusPort != httpsPort) {
            if (httpsPort > 0) {
                HttpConfiguration httpsConfig = getHttpsConfig(httpConfig, httpsPort, false, false);
                addHTTPSConnector(httpsConfig, statusPort, false, listenHost, idleTimeout, false, connectionLogger);
            } else if (httpPort > 0) {
                addHTTPConnector(httpConfig, statusPort, false, listenHost, idleTimeout);
            }
        }
    }

    /**
     * Set the banner that get displayed when server is started up.
     * @param banner Banner text to be displayed
     */
    public void setBanner(String banner) {
        this.banner = banner;
    }
    
    public void createServer(int maxThreads) {
        
        // Setup Thread pool
        
        QueuedThreadPool threadPool = new QueuedThreadPool();
        threadPool.setMaxThreads(maxThreads);

        server = new Server(threadPool);
        handlers = new ContextHandlerCollection();
        server.setHandler(handlers);
    }
    
    public static AthenzJettyContainer createJettyContainer() {

        // retrieve our http and https port numbers
        
        int httpPort = ConfigProperties.getPortNumber(AthenzConsts.ATHENZ_PROP_HTTP_PORT,
                AthenzConsts.ATHENZ_HTTP_PORT_DEFAULT);
        int httpsPort = ConfigProperties.getPortNumber(AthenzConsts.ATHENZ_PROP_HTTPS_PORT,
                AthenzConsts.ATHENZ_HTTPS_PORT_DEFAULT);

        // extract the port for oidc requests if one is configured

        int oidcPort = ConfigProperties.getPortNumber(AthenzConsts.ATHENZ_PROP_OIDC_PORT, 0);

        // for status port we'll use the protocol specified for the regular http
        // port. if both http and https are provided then https will be picked
        // it could also be either one of the values specified as well
        
        int statusPort = ConfigProperties.getPortNumber(AthenzConsts.ATHENZ_PROP_STATUS_PORT, 0);
        
        String serverHostName = getServerHostName();

        AthenzJettyContainer container = new AthenzJettyContainer();
        container.setBanner("http://" + serverHostName + " http port: " +
                httpPort + " https port: " + httpsPort + " status port: " +
                statusPort + " oidc port: " + oidcPort);

        int maxThreads = Integer.parseInt(System.getProperty(AthenzConsts.ATHENZ_PROP_MAX_THREADS,
                Integer.toString(AthenzConsts.ATHENZ_HTTP_MAX_THREADS)));
        container.createServer(maxThreads);

        HttpConfiguration httpConfig = container.newHttpConfiguration();
        container.addHTTPConnectors(httpConfig, httpPort, httpsPort, oidcPort, statusPort);
        container.addServletHandlers(serverHostName);
        
        container.addRequestLogHandler();
        return container;
    }

    public static void initConfigManager() {

        // We're going to configure any dynamic config sources first since those parameters
        // will take precedence over parameters configured in the properties file. These
        // config sources must be specified as part of the server startup script

        // Manage AWS parameter store configurations as the first config source

        final String awsParameterStorePath = System.getProperty(AthenzConsts.ATHENZ_PROP_AWS_PARAM_STORE_PATH);
        if (!StringUtil.isEmpty(awsParameterStorePath)) {
            CONFIG_MANAGER.addConfigSource(ConfigProviderAwsParametersStore.PROVIDER_DESCRIPTION_PREFIX + awsParameterStorePath);
        }

        // Manage properties file configurations

        final String propFile = System.getProperty(AthenzConsts.ATHENZ_PROP_FILE_NAME,
                getRootDir() + "/conf/athenz/athenz.properties");
        CONFIG_MANAGER.addConfigSource(ConfigProviderFile.PROVIDER_DESCRIPTION_PREFIX + propFile);
    }

    public void run() {
        try {
            server.start();
            System.out.println("Jetty server running at " + banner);
            server.join();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void stop() {
        try {
            connectionListener.shutdown();
            server.stop();
        } catch (Exception ignored) {
        }
    }

    public static void main(String [] args) {

        initConfigManager();

        try {
            AthenzJettyContainer container = createJettyContainer();
            container.run();
        } catch (Exception exc) {
            
            // log that we are shutting down, re-throw the exception
            
            LOG.error("Startup failure. Shutting down", exc);
            throw exc;
        }
    }
}
