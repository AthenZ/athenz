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

import static org.testng.Assert.*;


import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.Slf4jRequestLog;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.ThreadPool;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.log.AthenzRequestLog;
import com.yahoo.athenz.common.server.log.AuditLogFactory;

public class ZMSJettyContainerTest {

    @Mock ZMSHandler  mockImpl;

    @BeforeClass
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }
    
    @AfterMethod
    public void cleanup() {
        System.clearProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PATH);
        System.clearProperty(ZMSConsts.ZMS_PROP_KEYSTORE_TYPE);
        System.clearProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PASSWORD);
        System.clearProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PATH);
        System.clearProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_TYPE);
        System.clearProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PASSWORD);
        System.clearProperty(ZMSConsts.ZMS_PROP_KEYMANAGER_PASSWORD);
        System.clearProperty(ZMSConsts.ZMS_PROP_EXCLUDED_CIPHER_SUITES);
        System.clearProperty(ZMSConsts.ZMS_PROP_EXCLUDED_PROTOCOLS);
        System.clearProperty(ZMSConsts.ZMS_PROP_IDLE_TIMEOUT);
        System.clearProperty(ZMSConsts.ZMS_PROP_SEND_SERVER_VERSION);
        System.clearProperty(ZMSConsts.ZMS_PROP_SEND_DATE_HEADER);
        System.clearProperty(ZMSConsts.ZMS_PROP_OUTPUT_BUFFER_SIZE);
        System.clearProperty(ZMSConsts.ZMS_PROP_REQUEST_HEADER_SIZE);
        System.clearProperty(ZMSConsts.ZMS_PROP_RESPONSE_HEADER_SIZE);
        System.clearProperty(ZMSConsts.ZMS_PROP_MAX_THREADS);
    }
    
    @Test
    public void testContainerThreadPool() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_MAX_THREADS, "100");
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
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
        
        System.setProperty(ZMSConsts.ZMS_PROP_ACCESS_LOG_RETAIN_DAYS, "3");
        System.setProperty(ZMSConsts.ZMS_PROP_MAX_THREADS, "100");

        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.createServer(100);
        
        container.addRequestLogHandler("/tmp/zms_log");

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
        
        System.setProperty(ZMSConsts.ZMS_PROP_ACCESS_SLF4J_LOGGER, "AthenzAccessLogger");
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.resource(ZMSResources.class);
        container.delegate(ZMSHandler.class, mockImpl);
        container.createServer(100);
        
        container.addRequestLogHandler("/tmp/zms_log");
        
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
        System.clearProperty(ZMSConsts.ZMS_PROP_ACCESS_SLF4J_LOGGER);
    }
    
    @Test
    public void testAddServletHandlers() {
        System.setProperty(ZMSConsts.ZMS_PROP_KEEP_ALIVE, "false");
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.resource(ZMSResources.class);
        container.delegate(ZMSHandler.class, mockImpl);
        container.createServer(100);
        container.addServletHandlers("localhost");
    }
    
    @Test
    public void testPrimaryContext() {
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.resource(ZMSResources.class);
        container.delegate(ZMSHandler.class, mockImpl);
        container.createServer(100);
        container.addServletHandlers("localhost");
        
        Handler[] handlers = container.getHandlers().getHandlers();
        ServletContextHandler srvHandler = null;
        for (Handler handler : handlers) {
            if (handler instanceof ServletContextHandler) {
                srvHandler = (ServletContextHandler) handler;
                break;
            }
        }
        
        assertNotNull(srvHandler);
        assertEquals(srvHandler.getContextPath(), "/");
    }
    
    @Test
    public void testHttpConfigurationValidHttpsPort() {
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.createServer(100);
        
        System.setProperty(ZMSConsts.ZMS_PROP_SEND_SERVER_VERSION, "true");
        System.setProperty(ZMSConsts.ZMS_PROP_SEND_DATE_HEADER, "false");
        System.setProperty(ZMSConsts.ZMS_PROP_OUTPUT_BUFFER_SIZE, "128");
        System.setProperty(ZMSConsts.ZMS_PROP_REQUEST_HEADER_SIZE, "256");
        System.setProperty(ZMSConsts.ZMS_PROP_RESPONSE_HEADER_SIZE, "512");
        
        int httpsPort = 443;
        
        HttpConfiguration httpConfig = container.newHttpConfiguration(httpsPort);
        assertNotNull(httpConfig);
        
        assertEquals(httpConfig.getOutputBufferSize(), 128);
        assertFalse(httpConfig.getSendDateHeader());
        assertTrue(httpConfig.getSendServerVersion());
        assertEquals(httpConfig.getRequestHeaderSize(), 256);
        assertEquals(httpConfig.getResponseHeaderSize(), 512);
        assertEquals(httpConfig.getSecurePort(), httpsPort);
        assertEquals(httpConfig.getSecureScheme(), "https");
    }
    
    @Test
    public void testHttpConfigurationNoHttpsPort() {
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.createServer(100);
        
        System.setProperty(ZMSConsts.ZMS_PROP_SEND_SERVER_VERSION, "false");
        System.setProperty(ZMSConsts.ZMS_PROP_SEND_DATE_HEADER, "true");
        System.setProperty(ZMSConsts.ZMS_PROP_OUTPUT_BUFFER_SIZE, "64");
        System.setProperty(ZMSConsts.ZMS_PROP_REQUEST_HEADER_SIZE, "128");
        System.setProperty(ZMSConsts.ZMS_PROP_RESPONSE_HEADER_SIZE, "256");
        
        HttpConfiguration httpConfig = container.newHttpConfiguration(0);
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
        
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PATH, "/tmp/keystore");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PATH, "/tmp/truststore");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_IDLE_TIMEOUT, "10001");
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.createServer(100);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration(8082);
        container.addHTTPConnectors(httpConfig, 8081, 8082);
        
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
        
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_IDLE_TIMEOUT, "10001");
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.createServer(100);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration(8082);
        container.addHTTPConnectors(httpConfig, 0, 8082);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertTrue(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testHttpConnectorsHttpOnly() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_IDLE_TIMEOUT, "10001");
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.createServer(100);
        
        HttpConfiguration httpConfig = container.newHttpConfiguration(0);
        container.addHTTPConnectors(httpConfig, 8081, 0);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertEquals(connectors[0].getIdleTimeout(), 10001);
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertFalse(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testFilter() {
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        container.resource(ZMSResources.class);
        container.delegate(ZMSHandler.class, mockImpl);
        container.createServer(100);
        container.addServletHandlers("localhost");
        
        Handler[] handlers = container.getHandlers().getHandlers();
        ServletContextHandler srvHandler = null;
        for (Handler handler : handlers) {
            if (handler instanceof ServletContextHandler) {
                srvHandler = (ServletContextHandler) handler;
                break;
            }
        }
        assertNotNull(srvHandler);
    }
    
    @Test
    public void testCreateSSLContextObject() {
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_EXCLUDED_CIPHER_SUITES, ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_CIPHER_SUITES);
        System.setProperty(ZMSConsts.ZMS_PROP_EXCLUDED_PROTOCOLS, ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_PROTOCOLS);
        
        SslContextFactory sslContextFactory = container.createSSLContextObject();
        assertNotNull(sslContextFactory);
        assertEquals(sslContextFactory.getKeyStorePath(), "file:///tmp/keystore");
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getTrustStoreResource().toString(), "file:///tmp/truststore");
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getExcludeCipherSuites(), ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_CIPHER_SUITES.split(","));
        assertEquals(sslContextFactory.getExcludeProtocols(), ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_PROTOCOLS.split(","));
    }
    
    @Test
    public void testCreateSSLContextObjectNoValues() {
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        SslContextFactory sslContextFactory = container.createSSLContextObject();
        
        assertNotNull(sslContextFactory);
        assertNull(sslContextFactory.getKeyStoreResource());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertNull(sslContextFactory.getTrustStoreResource());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
    }
    
    @Test
    public void testCreateSSLContextObjectNoKeyStore() {
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_EXCLUDED_CIPHER_SUITES, ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_CIPHER_SUITES);
        System.setProperty(ZMSConsts.ZMS_PROP_EXCLUDED_PROTOCOLS, ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_PROTOCOLS);
        
        SslContextFactory sslContextFactory = container.createSSLContextObject();
        assertNotNull(sslContextFactory);
        assertNull(sslContextFactory.getKeyStoreResource());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getTrustStoreResource().toString(), "file:///tmp/truststore");
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getExcludeCipherSuites(), ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_CIPHER_SUITES.split(","));
        assertEquals(sslContextFactory.getExcludeProtocols(), ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_PROTOCOLS.split(","));
    }
    
    @Test
    public void testCreateSSLContextObjectNoTrustStore() {
        
        ZMSJettyContainer container = new ZMSJettyContainer(AuditLogFactory.getLogger());
        
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(ZMSConsts.ZMS_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(ZMSConsts.ZMS_PROP_EXCLUDED_CIPHER_SUITES, ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_CIPHER_SUITES);
        System.setProperty(ZMSConsts.ZMS_PROP_EXCLUDED_PROTOCOLS, ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_PROTOCOLS);
        
        SslContextFactory sslContextFactory = container.createSSLContextObject();
        assertNotNull(sslContextFactory);
        assertEquals(sslContextFactory.getKeyStorePath(), "file:///tmp/keystore");
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertNull(sslContextFactory.getTrustStore());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getExcludeCipherSuites(), ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_CIPHER_SUITES.split(","));
        assertEquals(sslContextFactory.getExcludeProtocols(), ZMSJettyContainer.ZMS_DEFAULT_EXCLUDED_PROTOCOLS.split(","));
    }
}
