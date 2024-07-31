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

import org.eclipse.jetty.rewrite.handler.RewriteHandler;
import org.eclipse.jetty.rewrite.handler.Rule;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.StatisticsHandler;
import org.eclipse.jetty.ee9.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.ThreadPool;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.log.jetty.AthenzRequestLog;

import static org.testng.Assert.*;

public class AthenzJettyContainerTest {

    private static final String DEFAULT_EXCLUDED_CIPHERS = "^_(MD5|SHA|SHA1)$";
    private static final String DEFAULT_INCLUDED_CIPHERS = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    
    @BeforeClass
    public void setUp() {
        MockitoAnnotations.openMocks(this);
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
        System.clearProperty(AthenzConsts.ATHENZ_PROP_GZIP_SUPPORT);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_GZIP_MIN_SIZE);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_DEBUG);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_PROXY_PROTOCOL);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_LISTEN_HOST);
        System.clearProperty((AthenzConsts.ATHENZ_PROP_STATUS_PORT));
        System.clearProperty(AthenzConsts.ATHENZ_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_KEEP_ALIVE);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN_TIMEOUT);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_SSL_LOG_FAILURES);
        System.clearProperty(AthenzConsts.ATHENZ_PROP_SERVER_POOL_SET_ENABLED);
    }
    
    @AfterClass
    public void cleanUpAfterClass() {
        System.clearProperty(AthenzConsts.ATHENZ_PROP_JETTY_HOME);
    }

    @Test
    public void testContainerThreadPool() {

        System.setProperty(AthenzConsts.ATHENZ_PROP_MAX_THREADS, "100");
        System.setProperty(AthenzConsts.ATHENZ_PROP_SERVER_POOL_SET_ENABLED, "true");

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

        // negative number should be ignored
        System.setProperty(AthenzConsts.ATHENZ_PROP_ACCESS_LOG_RETAIN_DAYS, "-3");
        System.setProperty(AthenzConsts.ATHENZ_PROP_MAX_THREADS, "100");
        System.setProperty(AthenzConsts.ATHENZ_PROP_SSL_LOG_FAILURES, "true");

        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        container.addRequestLogHandler();

        RequestLog reqLog = container.getServer().getRequestLog();
        assertNotNull(reqLog);
        assertEquals(reqLog.getClass(), AthenzRequestLog.class);
    }
    
    @Test
    public void testSlf4jRequestLogHandler() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_ACCESS_SLF4J_LOGGER, "AthenzAccessLogger");
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        container.addRequestLogHandler();

        RequestLog reqLog = container.getServer().getRequestLog();
        assertNotNull(reqLog);
        assertEquals(reqLog.getClass(), CustomRequestLog.class);
        assertEquals(((Slf4jRequestLogWriter) ((CustomRequestLog) reqLog).getWriter()).getLoggerName(), "AthenzAccessLogger");
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
        container.stop();
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

        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "src/test/resources/keystore.pkcs12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "src/test/resources/truststore.jks");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_RELOAD_SEC, "3600");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_IDLE_TIMEOUT, "10001");

        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);

        HttpConfiguration httpConfig = container.newHttpConfiguration();
        container.addHTTPConnectors(httpConfig, 8081, 8082, 443, 0);

        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 3);

        assertEquals(connectors[0].getIdleTimeout(), 10001);
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));

        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));

        assertTrue(connectors[2].getProtocols().contains("http/1.1"));
        assertTrue(connectors[2].getProtocols().contains("ssl"));
    }

    @Test
    public void testNonExistantKeyStore() {

        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "non-existant-keystore.pkcs12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "src/test/resources/truststore.jks");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_RELOAD_SEC, "3600");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_IDLE_TIMEOUT, "10001");

        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);

        HttpConfiguration httpConfig = container.newHttpConfiguration();
        try {
            // This should throw
            container.addHTTPConnectors(httpConfig, 8081, 8082, 0, 0);
            fail();
        } catch (IllegalArgumentException exception) {
            // as expected
        }
    }

    @Test
    public void testHttpConnectorsHttpsOnly() {

        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "src/test/resources/keystore.pkcs12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "src/test/resources/truststore.jks");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_IDLE_TIMEOUT, "10001");
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration();
        container.addHTTPConnectors(httpConfig, 0, 8082, 0, 0);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertTrue(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testHttpConnectorsHttpOnly() {

        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "src/test/resources/keystore.pkcs12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "src/test/resources/truststore.jks");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_IDLE_TIMEOUT, "10001");
        
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration();
        container.addHTTPConnectors(httpConfig, 8081, 0, 0, 0);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertEquals(connectors[0].getIdleTimeout(), 10001);
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertFalse(connectors[0].getProtocols().contains("ssl"));
    }
    
//    @Test
//    public void testServletContextHandler() {
//
//        AthenzJettyContainer container = new AthenzJettyContainer();
//        container.createServer(100);
//        container.addServletHandlers("localhost");
//
//        Handler[] handlers = container.getHandlers().getHandlers();
//        ServletContextHandler srvHandler = null;
//        for (Handler handler : handlers) {
//            if (handler instanceof ContextHandlerCollection) {
//                ContextHandlerCollection ctxHandlerCollection = (ContextHandlerCollection) handler;
//                for (Handler ctxHandler: ctxHandlerCollection.getHandlers()) {
//                    if (ctxHandler instanceof ServletContextHandler) {
//                        srvHandler = (ServletContextHandler) ctxHandler;
//                        break;
//                    }
//                }
//            }
//        }
//        assertNotNull(srvHandler);
//        assertEquals(srvHandler.getContextPath(), "/");
//    }
    
    @Test
    public void testCreateSSLContextObject() {
        
        AthenzJettyContainer container = new AthenzJettyContainer();

        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "src/test/resources/keystore.pkcs12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "src/test/resources/truststore.jks");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_CIPHER_SUITES, DEFAULT_EXCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_INCLUDED_CIPHER_SUITES, DEFAULT_INCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_PROTOCOLS, AthenzJettyContainer.ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS);
        
        SslContextFactory.Server sslContextFactory = container.createSSLContextObject(true);
        assertNotNull(sslContextFactory);
        assertTrue(sslContextFactory.getKeyStorePath().endsWith("src/test/resources/keystore.pkcs12"));
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertTrue(sslContextFactory.getTrustStoreResource().toString().endsWith("src/test/resources/truststore.jks"));
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

        System.setProperty(AthenzConsts.ATHENZ_PROP_TRUSTSTORE_PATH, "src/test/resources/truststore.jks");
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
        assertTrue(sslContextFactory.getTrustStoreResource().toString().endsWith("src/test/resources/truststore.jks"));
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getExcludeCipherSuites(), DEFAULT_EXCLUDED_CIPHERS.split(","));
        assertEquals(sslContextFactory.getIncludeCipherSuites(), DEFAULT_INCLUDED_CIPHERS.split(","));
        assertEquals(sslContextFactory.getExcludeProtocols(), AthenzJettyContainer.ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS.split(","));
    }
    
    @Test
    public void testCreateSSLContextObjectNoTrustStore() {
        
        AthenzJettyContainer container = new AthenzJettyContainer();

        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PATH, "src/test/resources/keystore.pkcs12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_CIPHER_SUITES, DEFAULT_EXCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_INCLUDED_CIPHER_SUITES, DEFAULT_INCLUDED_CIPHERS);
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_PROTOCOLS, AthenzJettyContainer.ATHENZ_DEFAULT_EXCLUDED_PROTOCOLS);
        
        SslContextFactory.Server sslContextFactory = container.createSSLContextObject(false);
        assertNotNull(sslContextFactory);
        assertTrue(sslContextFactory.getKeyStorePath().endsWith("src/test/resources/keystore.pkcs12"));
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
    public void testInitContainerValidPorts() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "4443");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 3);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        
        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testInitContainerOnlyHTTPSPort() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "0");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "4443");
        System.setProperty(AthenzConsts.ATHENZ_PROP_OIDC_PORT, "8443");
        System.setProperty("yahoo.zms.debug.user_authority", "true");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 2);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertTrue(connectors[0].getProtocols().contains("ssl"));

        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testInitContainerOnlyHTTPPort() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "0");
        System.setProperty(AthenzConsts.ATHENZ_PROP_OIDC_PORT, "0");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertFalse(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testInitContainerInvalidHTTPPort() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "-10");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "4443");
        System.setProperty(AthenzConsts.ATHENZ_PROP_OIDC_PORT, "443");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 3);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        
        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));

        assertTrue(connectors[2].getProtocols().contains("http/1.1"));
        assertTrue(connectors[2].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testInitContainerInvalidHTTPSPort() {
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "-10");
        System.setProperty(AthenzConsts.ATHENZ_PROP_OIDC_PORT, "0");

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
    public void testInitContainerOptionalFeatures() {

        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "4443");
        System.setProperty(AthenzConsts.ATHENZ_PROP_OIDC_PORT, "4443");
        System.setProperty(AthenzConsts.ATHENZ_PROP_DEBUG, "true");
        System.setProperty(AthenzConsts.ATHENZ_PROP_GZIP_SUPPORT, "true");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST, "/status.html");
        System.setProperty(AthenzConsts.ATHENZ_PROP_PROXY_PROTOCOL, "true");
        System.setProperty(AthenzConsts.ATHENZ_PROP_LISTEN_HOST, "127.0.0.1");
        System.setProperty(AthenzConsts.ATHENZ_PROP_EXCLUDED_PROTOCOLS, "");
        System.setProperty(AthenzConsts.ATHENZ_PROP_KEEP_ALIVE, "false");

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
    public void testInitContainerStatusPortHTTPS() {

        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "4443");
        System.setProperty(AthenzConsts.ATHENZ_PROP_OIDC_PORT, "8443");
        System.setProperty(AthenzConsts.ATHENZ_PROP_STATUS_PORT, "4444");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
    }

    @Test
    public void testInitContainerStatusPortHTTP() {

        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "0");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_STATUS_PORT, "4444");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
    }

    @Test
    public void testInitContainerStatusPortNoHTTP() {

        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTPS_PORT, "0");
        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "0");
        System.setProperty(AthenzConsts.ATHENZ_PROP_STATUS_PORT, "4444");

        AthenzJettyContainer container = AthenzJettyContainer.createJettyContainer();
        assertNotNull(container);
    }

    @Test
    public void testLoadServicePrivateKeyInvalid() {

        System.setProperty(AthenzConsts.ATHENZ_PROP_HTTP_PORT, "4080");
        System.setProperty(AthenzConsts.ATHENZ_PROP_STATUS_PORT, "4444");
        System.setProperty(AthenzConsts.ATHENZ_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS, "invalid-class");

        try {
            AthenzJettyContainer.createJettyContainer();
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }
    }

    @Test
    public void testInvalidJettyHomeDir() {
        System.setProperty(AthenzConsts.ATHENZ_PROP_JETTY_HOME, "unknown");
        try {
            AthenzJettyContainer.createJettyContainer();
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof RuntimeException);
        }
        // reset to expected conf directory
        System.setProperty(AthenzConsts.ATHENZ_PROP_JETTY_HOME, "conf");
    }

    @Test
    public void testGracefulShutdown() {
        AthenzJettyContainer container;
        Server server;
        long stopTimeout;
        boolean stopAtShutdown;

        // If the athenz.graceful_shutdown is not true.
        container = new AthenzJettyContainer();
        container.createServer(100);
        container.addServletHandlers("localhost");

        server = container.getServer();
        assertNotNull(server);

        stopTimeout = server.getStopTimeout();
        stopAtShutdown = server.getStopAtShutdown();

        assertEquals(stopTimeout, 0);
        assertFalse(stopAtShutdown);

        cleanup();

        // If the athenz.graceful_shutdown is not true,
        // the ahtenz.graceful_shutdown_timeout is invalid.
        System.setProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN, "false");
        System.setProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN_TIMEOUT, "60000");

        container = new AthenzJettyContainer();
        container.createServer(100);
        container.addServletHandlers("localhost");

        server = container.getServer();
        assertNotNull(server);

        stopTimeout = server.getStopTimeout();
        stopAtShutdown = server.getStopAtShutdown();

        assertEquals(stopTimeout, 0);
        assertFalse(stopAtShutdown);

        cleanup();

        // If the athenz.graceful_shutdown is true.
        System.setProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN, "true");

        container = new AthenzJettyContainer();
        container.createServer(100);
        container.addServletHandlers("localhost");

        server = container.getServer();
        assertNotNull(server);

        stopTimeout = server.getStopTimeout();
        stopAtShutdown = server.getStopAtShutdown();

        assertEquals(stopTimeout, 30000);
        assertTrue(stopAtShutdown);

        cleanup();

        // If the athenz.graceful_shutdown is true and
        // the athenz.graceful_shutdown_timeout is also set
        System.setProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN, "true");
        System.setProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN_TIMEOUT, "60000");

        container = new AthenzJettyContainer();
        container.createServer(100);
        container.addServletHandlers("localhost");

        server = container.getServer();
        assertNotNull(server);

        stopTimeout = server.getStopTimeout();
        stopAtShutdown = server.getStopAtShutdown();

        assertEquals(stopTimeout, 60000);
        assertTrue(stopAtShutdown);
    }

    @Test
    public void testStatisticsHandler() {
        ContextHandlerCollection contextHandlerCollection = null;
        StatisticsHandler statisticsHandler = null;

        System.setProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN, "false");
        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        container.addServletHandlers("localhost");

        contextHandlerCollection = container.getHandlers();
        for (Handler handler : contextHandlerCollection.getHandlers()) {
            if (handler instanceof ContextHandlerCollection) {
                contextHandlerCollection = (ContextHandlerCollection) handler;
            } else if (handler instanceof StatisticsHandler) {
                statisticsHandler = (StatisticsHandler) handler;
            }
        }

        assertNotNull(contextHandlerCollection);
        assertNull(statisticsHandler);

        cleanup();

        System.setProperty(AthenzConsts.ATHENZ_PROP_GRACEFUL_SHUTDOWN, "true");
        container = new AthenzJettyContainer();
        container.createServer(100);
        container.addServletHandlers("localhost");

        contextHandlerCollection = container.getHandlers();
        for (Handler handler : contextHandlerCollection.getHandlers()) {
            if (handler instanceof ContextHandlerCollection) {
                contextHandlerCollection = (ContextHandlerCollection) handler;
            } else if (handler instanceof StatisticsHandler) {
                statisticsHandler = (StatisticsHandler) handler;
            }
        }

        assertNotNull(contextHandlerCollection);
        assertNotNull(statisticsHandler);
    }

    @Test
    public void testHttpResponseHeaders() {
        System.setProperty(AthenzConsts.ATHENZ_PROP_RESPONSE_HEADERS_JSON, "{\"Header-1\":\"Value-1\",\"Header-2\":\"Value-2\"}");

        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);
        container.addServletHandlers("localhost");

        boolean header1Handled = false;
        boolean header2Handled = false;
        ContextHandlerCollection handlers = container.getHandlers();
        for (Handler handler : handlers.getHandlers()) {
            if (handler instanceof RewriteHandler) {
                RewriteHandler rewriteHandler = (RewriteHandler) handler;
                for (Rule rule : rewriteHandler.getRules()) {
                    final String ruleString = rule.toString();
                    if (ruleString.startsWith("HeaderPatternRule@")) {
                        if (ruleString.endsWith("[terminating=false][pattern=/*][header:Header-1=Value-1]")) {
                            header1Handled = true;
                        } else if (ruleString.endsWith("[terminating=false][pattern=/*][header:Header-2=Value-2]")) {
                            header2Handled = true;
                        }
                    }
                }
            }
        }
        assertTrue(header1Handled);
        assertTrue(header2Handled);

        System.clearProperty(AthenzConsts.ATHENZ_PROP_RESPONSE_HEADERS_JSON);
    }

    @Test
    public void testHttpResponseHeadersInvalidJson() {
        System.setProperty(AthenzConsts.ATHENZ_PROP_RESPONSE_HEADERS_JSON, "invalid-json");

        AthenzJettyContainer container = new AthenzJettyContainer();
        container.createServer(100);

        try {
            container.addServletHandlers("localhost");
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("must be a JSON object with string values"));
        }

        System.clearProperty(AthenzConsts.ATHENZ_PROP_RESPONSE_HEADERS_JSON);
    }

    @Test
    public void testInitConfigManager() {
        System.setProperty(AthenzConsts.ATHENZ_PROP_FILE_NAME, "./src/test/resources/athenz.properties");
        AthenzJettyContainer.initConfigManager();
        System.clearProperty(AthenzConsts.ATHENZ_PROP_FILE_NAME);
    }
}
