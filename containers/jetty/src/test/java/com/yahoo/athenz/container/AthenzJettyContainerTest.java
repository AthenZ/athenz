/*
 * Copyright 2017 Yahoo Inc.
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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.Slf4jRequestLog;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.ThreadPool;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.container.log.AthenzRequestLog;

public class AthenzJettyContainerTest {

    private static final String DEFAULT_EXCLUDED_CIPHERS = "^_(MD5|SHA|SHA1)$";
    private static final String DEFAULT_INCLUDED_CIPHERS = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    
    @BeforeClass
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        System.setProperty(AthenzConsts.ATHENZ_PROP_JETTY_HOME, "conf");
    }
    
    @AfterMethod
    public void cleanup() {
        System.clearProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_CIPHER_SUITES);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_INCLUDED_CIPHER_SUITES);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_PROTOCOLS);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_IDLE_TIMEOUT);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_SEND_SERVER_VERSION);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_SEND_DATE_HEADER);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_OUTPUT_BUFFER_SIZE);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_REQUEST_HEADER_SIZE);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_RESPONSE_HEADER_SIZE);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_MAX_THREADS);
    }
    
    @AfterClass
    public void cleanUpAfterClass() {
        System.clearProperty(AthenzConsts.ATHENZ_PROP_JETTY_HOME);
    }

    @Test
    public void testContainerThreadPool() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_MAX_THREADS, "100");
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        Server server = container.getServer();
        assertNotNull(server);
        
        ThreadPool threadPool = server.getThreadPool();
        assertNotNull(threadPool);
        
        // at this point we have no threads so the value is 0
        assertEquals(threadPool.getThreads(), 0);
        assertEquals(threadPool.getIdleThreads(), 0);
    }
    
    @Test
    public void testRequestLogHandler() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_ACCESS_LOG_RETAIN_DAYS, "3");
        System.setProperty(AthenzConsts.ATHENZ_PROP_MAX_THREADS, "100");

        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        container.addRequestLogHandler();

        // now retrieve the request log handler
        
        Handler[] handlers = container.getHandlers().getHandlers();
        RequestLogHandler logHandler = null;
        for (Handler handler : handlers) {
            if (handler instanceof RequestLogHandler) {
                logHandler = (RequestLogHandler) handler;
                break;
            }
        }
        
        assertNotNull(logHandler);
        
        RequestLog reqLog = logHandler.getRequestLog();
        assertNotNull(reqLog);
        assertEquals(reqLog.getClass(), AthenzRequestLog.class);
    }
    
    @Test
    public void testSlf4jRequestLogHandler() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_ACCESS_SLF4J_LOGGER, "AthenzAccessLogger");
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        container.addRequestLogHandler();
        
        // now retrieve the request log handler
        
        Handler[] handlers = container.getHandlers().getHandlers();
        RequestLogHandler logHandler = null;
        for (Handler handler : handlers) {
            if (handler instanceof RequestLogHandler) {
                logHandler = (RequestLogHandler) handler;
                break;
            }
        }
        
        assertNotNull(logHandler);
        
        RequestLog reqLog = logHandler.getRequestLog();
        assertNotNull(reqLog);
        assertEquals(reqLog.getClass(), Slf4jRequestLog.class);
        assertEquals(((Slf4jRequestLog) reqLog).getLoggerName(), "AthenzAccessLogger");
        System.clearProperty(AthenzConsts.ATHENZ_PROP_ACCESS_SLF4J_LOGGER);
    }
    
    @Test
    public void testAddServletHandlers() {
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEEP_ALIVE, "false");
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        container.addServletHandlers("localhost");
    }
    
    @Test
    public void testHttpConfigurationValidHttpsPort() {
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_SEND_SERVER_VERSION, "true");
        System.setProperty(AthenzConsts.ATHENZ_PROP_SEND_DATE_HEADER, "false");
        System.setProperty(AthenzConsts.ATHENZ_PROP_OUTPUT_BUFFER_SIZE, "128");
        System.setProperty(AthenzConsts.ATHENZ_PROP_REQUEST_HEADER_SIZE, "256");
        System.setProperty(AthenzConsts.ATHENZ_PROP_RESPONSE_HEADER_SIZE, "512");
        
        HttpConfiguration httpConfig = container.newHttpConfiguration();
        assertNotNull(httpConfig);
        
        assertEquals(httpConfig.getOutputBufferSize(), 128);
        assertFalse(httpConfig.getSendDateHeader());
        assertTrue(httpConfig.getSendServerVersion());
        assertEquals(httpConfig.getRequestHeaderSize(), 256);
        assertEquals(httpConfig.getResponseHeaderSize(), 512);
        
        // it defaults to https even if we have no value specified
        assertEquals(httpConfig.getSecureScheme(), "https");
    }
    
    @Test
    public void testHttpConfigurationNoHttpsPort() {
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_SEND_SERVER_VERSION, "false");
        System.setProperty(AthenzConsts.ATHENZ_PROP_SEND_DATE_HEADER, "true");
        System.setProperty(AthenzConsts.ATHENZ_PROP_OUTPUT_BUFFER_SIZE, "64");
        System.setProperty(AthenzConsts.ATHENZ_PROP_REQUEST_HEADER_SIZE, "128");
        System.setProperty(AthenzConsts.ATHENZ_PROP_RESPONSE_HEADER_SIZE, "256");
        
        HttpConfiguration httpConfig = container.newHttpConfiguration();
        assertNotNull(httpConfig);
        
        assertEquals(httpConfig.getOutputBufferSize(), 64);
        assertTrue(httpConfig.getSendDateHeader());
        assertFalse(httpConfig.getSendServerVersion());
        assertEquals(httpConfig.getRequestHeaderSize(), 128);
        assertEquals(httpConfig.getResponseHeaderSize(), 256);
        assertEquals(httpConfig.getSecurePort(), 0);
        
        // it defaults to https even if we have no value specified
        assertEquals(httpConfig.getSecureScheme(), "https");
    }
    
    @Test
    public void testHttpConnectorsBoth() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "/tmp/keystore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "/tmp/truststore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_IDLE_TIMEOUT, "10001");
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration();
        container.addHTTPConnectors(httpConfig, 8081, 8082, 0);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 2);
        
        assertEquals(connectors[0].getIdleTimeout(), 10001);
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        
        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testHttpConnectorsHttpsOnly() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_IDLE_TIMEOUT, "10001");
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration();
        container.addHTTPConnectors(httpConfig, 0, 8082, 0);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertTrue(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testHttpConnectorsHttpOnly() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_IDLE_TIMEOUT, "10001");
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration();
        container.addHTTPConnectors(httpConfig, 8081, 0, 0);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertEquals(connectors[0].getIdleTimeout(), 10001);
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertFalse(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testServletContextHandler() {
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        container.addServletHandlers("localhost");
        
        Handler[] handlers = container.getHandlers().getHandlers();
        ServletContextHandler srvHandler = null;
        for (Handler handler : handlers) {
            if (handler instanceof ContextHandlerCollection) {
                ContextHandlerCollection ctxHandlerCollection = (ContextHandlerCollection) handler;
                for (Handler ctxHandler: ctxHandlerCollection.getHandlers()) {
                    if (ctxHandler instanceof ServletContextHandler) {
                        srvHandler = (ServletContextHandler) ctxHandler;
                        break;
                    }
                }
            }
        }
        assertNotNull(srvHandler);
        assertEquals(srvHandler.getContextPath(), "/");
    }
    
    @Test
    public void testCreateSSLContextObject() {
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_CIPHER_SUITES, DEFAULT_EXCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_INCLUDED_CIPHER_SUITES, DEFAULT_INCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_PROTOCOLS, AthenzJettyContainer.ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS);
        
        SslContextFactory.Server sslContextFactory = container.createSSLContextObject(true);
        assertNotNull(sslContextFactory);
        assertEquals(sslContextFactory.getKeyStorePath(), "file:///tmp/keystore");
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getTrustStoreResource().toString(), "file:///tmp/truststore");
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getExcludeCipherSuites(), DEFAULT_EXCLUDED_CIPHERS.split(","));
        assertEquals(sslContextFactory.getIncludeCipherSuites(), DEFAULT_INCLUDED_CIPHERS.split(","));
        assertEquals(sslContextFactory.getExcludeProtocols(), AthenzJettyContainer.ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS.split(","));
        assertTrue(sslContextFactory.getNeedClientAuth());
    }
    
    @Test
    public void testCreateSSLContextObjectNoValues() {
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        SslContextFactory.Server sslContextFactory = container.createSSLContextObject(false);
        
        assertNotNull(sslContextFactory);
        assertNull(sslContextFactory.getKeyStoreResource());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertNull(sslContextFactory.getTrustStoreResource());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertTrue(sslContextFactory.getWantClientAuth());
        assertFalse(sslContextFactory.getNeedClientAuth());
    }
    
    @Test
    public void testCreateSSLContextObjectNoKeyStore() {
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_CIPHER_SUITES, DEFAULT_EXCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_INCLUDED_CIPHER_SUITES, DEFAULT_INCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_PROTOCOLS, AthenzJettyContainer.ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS);
        
        SslContextFactory.Server sslContextFactory = container.createSSLContextObject(true);
        assertNotNull(sslContextFactory);
        assertNull(sslContextFactory.getKeyStoreResource());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getTrustStoreResource().toString(), "file:///tmp/truststore");
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getExcludeCipherSuites(), DEFAULT_EXCLUDED_CIPHERS.split(","));
        assertEquals(sslContextFactory.getIncludeCipherSuites(), DEFAULT_INCLUDED_CIPHERS.split(","));
        assertEquals(sslContextFactory.getExcludeProtocols(), AthenzJettyContainer.ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS.split(","));
    }
    
    @Test
    public void testCreateSSLContextObjectNoTrustStore() {
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_CIPHER_SUITES, DEFAULT_EXCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_INCLUDED_CIPHER_SUITES, DEFAULT_INCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_PROTOCOLS, AthenzJettyContainer.ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS);
        
        SslContextFactory.Server sslContextFactory = container.createSSLContextObject(false);
        assertNotNull(sslContextFactory);
        assertEquals(sslContextFactory.getKeyStorePath(), "file:///tmp/keystore");
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertNull(sslContextFactory.getTrustStore());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getExcludeCipherSuites(), DEFAULT_EXCLUDED_CIPHERS.split(","));
        assertEquals(sslContextFactory.getIncludeCipherSuites(), DEFAULT_INCLUDED_CIPHERS.split(","));
        assertEquals(sslContextFactory.getExcludeProtocols(), AthenzJettyContainer.ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS.split(","));
    }
    
    @Test
    public void testGetServerHostNamePropertySet() {
        System.setProperty(AthenzConsts.ATHENZ_PROP_HOSTNAME, "MyTestHost");
        assertEquals(AthenzJettyContainer.getServerHostName(), "MyTestHost");
    }

    @Test
    public void testGetServerHostNameNoProperty() {
        assertNotNull(AthenzJettyContainer.getServerHostName());
    }
    
    @Test
    public void initContainerValidPorts() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "4443");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 2);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        
        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));
    }
    
    @Test
    public void initContainerOnlyHTTPSPort() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "0");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "4443");
        System.setProperty("yahoo.zms.debug.user_authority", "true");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertTrue(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void initContainerOnlyHTTPPort() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "0");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertFalse(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void initContainerInvalidHTTPPort() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "-10");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "4443");
        
        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 2);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        
        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));
    }
    
    @Test
    public void initContainerInvalidHTTPSPort() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "-10");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 2);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        
        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));
    }
}
