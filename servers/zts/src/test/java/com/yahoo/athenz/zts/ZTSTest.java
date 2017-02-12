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

package com.yahoo.athenz.zts;

import static org.testng.Assert.*;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;

public class ZTSTest {

    private static final String ZTS_CHANGE_LOG_STORE_FACTORY_CLASS =
            "com.yahoo.athenz.zts.store.file.MockZMSFileChangeLogStoreFactory";
    private static final String ZTS_SELF_CERT_SIGNER_STORE_FACTORY_CLASS =
            "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory";

    @BeforeClass
    public void setUp() throws Exception {
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/zts_private.pem");
        System.setProperty(ZTSConsts.ZTS_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
    }
    
    @BeforeMethod
    public void prepare() {
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");
    }

    @AfterMethod
    public void cleanup() {
        System.clearProperty(ZTSConsts.ZTS_PROP_HOME);
        System.clearProperty(ZTSConsts.ZTS_PROP_HOSTNAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_HTTP_PORT);
        System.clearProperty(ZTSConsts.ZTS_PROP_HTTPS_PORT);
    }
    
    @Test
    public void testGetServerHostNamePropertySet() {
        System.setProperty(ZTSConsts.ZTS_PROP_HOSTNAME, "MyTestHost");
        assertEquals(ZTS.getServerHostName(), "MyTestHost");
    }

    @Test
    public void testGetServerHostNameNoProperty() {
        assertNotNull(ZTS.getServerHostName());
    }
    
    @Test
    public void initContainerValidPorts() {
        System.setProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS,
                ZTS_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                ZTS_SELF_CERT_SIGNER_STORE_FACTORY_CLASS);

        System.setProperty(ZTSConsts.ZTS_PROP_HOME, "/tmp/zts_server");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, "4080");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTPS_PORT, "4443");
        
        ZTSJettyContainer container = ZTS.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 2);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        
        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));
        
        System.clearProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);

    }
    
    @Test
    public void initContainerOnlyHTTPSPort() {
        System.setProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS,
                ZTS_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                ZTS_SELF_CERT_SIGNER_STORE_FACTORY_CLASS);

        System.setProperty(ZTSConsts.ZTS_PROP_HOME, "/tmp/zts_server");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, "0");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTPS_PORT, "4443");
        
        ZTSJettyContainer container = ZTS.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertTrue(connectors[0].getProtocols().contains("ssl"));
        
        System.clearProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);
    }
    
    @Test
    public void initContainerOnlyHTTPPort() {
        System.setProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS,
                ZTS_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                ZTS_SELF_CERT_SIGNER_STORE_FACTORY_CLASS);

        System.setProperty(ZTSConsts.ZTS_PROP_HOME, "/tmp/zts_server");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, "4080");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTPS_PORT, "0");
        
        ZTSJettyContainer container = ZTS.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertFalse(connectors[0].getProtocols().contains("ssl"));
        
        System.clearProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);
    }
    
    @Test
    public void initContainerInvalidHTTPPort() {
        System.setProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS,
                ZTS_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                ZTS_SELF_CERT_SIGNER_STORE_FACTORY_CLASS);

        System.setProperty(ZTSConsts.ZTS_PROP_HOME, "/tmp/zts_server");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, "-10");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTPS_PORT, "4443");
        
        ZTSJettyContainer container = ZTS.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 2);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        
        assertTrue(connectors[1].getProtocols().contains("http/1.1"));
        assertTrue(connectors[1].getProtocols().contains("ssl"));
        
        System.clearProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);
    }
    
    @Test
    public void initContainerInvalidHTTPSPort() {
        System.setProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS,
                ZTS_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                ZTS_SELF_CERT_SIGNER_STORE_FACTORY_CLASS);

        System.setProperty(ZTSConsts.ZTS_PROP_HOME, "/tmp/zts_server");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, "4080");
        System.setProperty(ZTSConsts.ZTS_PROP_HTTPS_PORT, "-10");
        
        ZTSJettyContainer container = ZTS.createJettyContainer();
        assertNotNull(container);
        
        Server server = container.getServer();
        Connector[] connectors = server.getConnectors();
        assertEquals(connectors.length, 1);
        
        assertTrue(connectors[0].getProtocols().contains("http/1.1"));
        assertFalse(connectors[0].getProtocols().contains("ssl"));
        
        System.clearProperty(ZTSConsts.ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);
    }
    
    @Test
    public void testGetPortNumberDefault() {
        assertEquals(ZTS.getPortNumber("NotExistantProperty", 4080), 4080);
    }
    
    @Test
    public void testGetPortNumberValid() {
        System.setProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, "4085");
        assertEquals(ZTS.getPortNumber(ZTSConsts.ZTS_PROP_HTTP_PORT, 4080), 4085);
    }
    
    @Test
    public void testGetPortNumberInvalidFormat() {
        System.setProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, "abc");
        assertEquals(ZTS.getPortNumber(ZTSConsts.ZTS_PROP_HTTP_PORT, 4080), 4080);
    }
    
    @Test
    public void testGetPortNumberOutOfRangeNegative() {
        System.setProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, "-1");
        assertEquals(ZTS.getPortNumber(ZTSConsts.ZTS_PROP_HTTP_PORT, 4080), 4080);
    }
    
    @Test
    public void testGetPortNumberOutOfRangePositive() {
        System.setProperty(ZTSConsts.ZTS_PROP_HTTP_PORT, "65536");
        assertEquals(ZTS.getPortNumber(ZTSConsts.ZTS_PROP_HTTP_PORT, 4080), 4080);
    }
}
