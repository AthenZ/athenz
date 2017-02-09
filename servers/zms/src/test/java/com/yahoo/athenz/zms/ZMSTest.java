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
import org.eclipse.jetty.server.Server;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;

public class ZMSTest {
    
    public static final String ZMS_PROP_PUBLIC_KEY = "athenz.zms.publickey";

    @BeforeClass
    public void setUp() throws Exception {
        System.setProperty(ZMSConsts.ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/zms_private.pem");
        System.setProperty(ZMS_PROP_PUBLIC_KEY, "src/test/resources/zms_public.pem");
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN, "user.testadminuser");
    }
    
    @AfterMethod
    public void cleanup() {
        System.clearProperty(ZMSConsts.ZMS_PROP_HOME);
        System.clearProperty(ZMSConsts.ZMS_PROP_HOSTNAME);
        System.clearProperty(ZMSConsts.ZMS_PROP_HTTP_PORT);
        System.clearProperty(ZMSConsts.ZMS_PROP_HTTPS_PORT);
    }
    
    @Test
    public void testGetAuditLogger() {
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOGGER_CLASS, "zmsclass");
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOGGER_CLASS_PARAM, "zmsparam");
        ZMS.getAuditLogger();
    }
    
    @Test
    public void testGetServerHostNamePropertySet() {
        System.setProperty(ZMSConsts.ZMS_PROP_HOSTNAME, "MyTestHost");
        assertEquals(ZMS.getServerHostName(), "MyTestHost");
    }

    @Test
    public void testGetServerHostNameNoProperty() {
        assertNotNull(ZMS.getServerHostName());
    }
    
    @Test
    public void initContainerValidPorts() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_HOME, "/tmp/zms_server");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, "4080");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTPS_PORT, "4443");

        ZMSJettyContainer container = ZMS.createJettyContainer();
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
        
        System.setProperty(ZMSConsts.ZMS_PROP_HOME, "/tmp/zms_server");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, "0");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTPS_PORT, "4443");
        System.setProperty("yahoo.zms.debug.user_authority", "true");

        ZMSJettyContainer container = ZMS.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertTrue(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void initContainerOnlyHTTPPort() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_HOME, "/tmp/zms_server");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, "4080");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTPS_PORT, "0");

        ZMSJettyContainer container = ZMS.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertFalse(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void initContainerInvalidHTTPPort() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_HOME, "/tmp/zms_server");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, "-10");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTPS_PORT, "4443");
        
        ZMSJettyContainer container = ZMS.createJettyContainer();
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
        
        System.setProperty(ZMSConsts.ZMS_PROP_HOME, "/tmp/zms_server");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, "4080");
        System.setProperty(ZMSConsts.ZMS_PROP_HTTPS_PORT, "-10");

        ZMSJettyContainer container = ZMS.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertFalse(connectors[0].getProtocols().contains("ssl"));
    }
    
    @Test
    public void testGetPortNumberDefault() {
        assertEquals(ZMS.getPortNumber("NotExistantProperty", 4080), 4080);
    }
    
    @Test
    public void testGetPortNumberValid() {
        System.setProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, "4085");
        assertEquals(ZMS.getPortNumber(ZMSConsts.ZMS_PROP_HTTP_PORT, 4080), 4085);
    }
    
    @Test
    public void testGetPortNumberInvalidFormat() {
        System.setProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, "abc");
        assertEquals(ZMS.getPortNumber(ZMSConsts.ZMS_PROP_HTTP_PORT, 4080), 4080);
    }
    
    @Test
    public void testGetPortNumberOutOfRangeNegative() {
        System.setProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, "-1");
        assertEquals(ZMS.getPortNumber(ZMSConsts.ZMS_PROP_HTTP_PORT, 4080), 4080);
    }
    
    @Test
    public void testGetPortNumberOutOfRangePositive() {
        System.setProperty(ZMSConsts.ZMS_PROP_HTTP_PORT, "65536");
        assertEquals(ZMS.getPortNumber(ZMSConsts.ZMS_PROP_HTTP_PORT, 4080), 4080);
    }
}
