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
package com.yahoo.athenz.zts.utils;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.zts.Identity;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.CertSigner;
import com.yahoo.athenz.zts.utils.ZTSUtils;

public class ZTSUtilsTest {
    
    @AfterMethod
    public void cleanup() {
        System.clearProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PATH);
        System.clearProperty(ZTSConsts.ZTS_PROP_KEYSTORE_TYPE);
        System.clearProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PASSWORD);
        System.clearProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PATH);
        System.clearProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_TYPE);
        System.clearProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PASSWORD);
        System.clearProperty(ZTSConsts.ZTS_PROP_KEYMANAGER_PASSWORD);
        System.clearProperty(ZTSConsts.ZTS_PROP_EXCLUDED_CIPHER_SUITES);
        System.clearProperty(ZTSConsts.ZTS_PROP_EXCLUDED_PROTOCOLS);
        System.clearProperty(ZTSConsts.ZTS_PROP_WANT_CLIENT_CERT);
    }
    
    @Test
    public void testRetrieveConfigSetting() {
        
        System.setProperty("prop1", "1001");
        assertEquals(1001, ZTSUtils.retrieveConfigSetting("prop1", 99));
        assertEquals(99, ZTSUtils.retrieveConfigSetting("prop2", 99));

        System.setProperty("prop1", "-101");
        assertEquals(99, ZTSUtils.retrieveConfigSetting("prop1", 99));

        System.setProperty("prop1", "0");
        assertEquals(99, ZTSUtils.retrieveConfigSetting("prop1", 99));
        
        System.setProperty("prop1", "abc");
        assertEquals(99, ZTSUtils.retrieveConfigSetting("prop1", 99));
    }
    
    @Test
    public void testCreateSSLContextObject() {
        
        System.setProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(ZTSConsts.ZTS_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(ZTSConsts.ZTS_PROP_KEYMANAGER_PASSWORD, "pass123");
        System.setProperty(ZTSConsts.ZTS_PROP_EXCLUDED_CIPHER_SUITES, ZTSUtils.ZTS_DEFAULT_EXCLUDED_CIPHER_SUITES);
        System.setProperty(ZTSConsts.ZTS_PROP_EXCLUDED_PROTOCOLS, ZTSUtils.ZTS_DEFAULT_EXCLUDED_PROTOCOLS);
        System.setProperty(ZTSConsts.ZTS_PROP_WANT_CLIENT_CERT, "true");
        
        SslContextFactory sslContextFactory = ZTSUtils.createSSLContextObject(null);
        assertNotNull(sslContextFactory);
        assertEquals(sslContextFactory.getKeyStorePath(), "file:///tmp/keystore");
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getTrustStoreResource().toString(), "file:///tmp/truststore");
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getExcludeCipherSuites(), ZTSUtils.ZTS_DEFAULT_EXCLUDED_CIPHER_SUITES.split(","));
        assertEquals(sslContextFactory.getExcludeProtocols(), ZTSUtils.ZTS_DEFAULT_EXCLUDED_PROTOCOLS.split(","));
        assertTrue(sslContextFactory.getWantClientAuth());
    }
    
    @Test
    public void testCreateSSLContextObjectNoValues() {
        
        SslContextFactory sslContextFactory = ZTSUtils.createSSLContextObject(null);
        
        assertNotNull(sslContextFactory);
        assertFalse(sslContextFactory.getWantClientAuth());
        assertNull(sslContextFactory.getKeyStoreResource());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertNull(sslContextFactory.getTrustStore());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
    }
    
    @Test
    public void testCreateSSLContextObjectNoKeyStore() {
        
        System.setProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PATH, "file:///tmp/truststore");
        System.setProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_TYPE, "PKCS12");
        System.setProperty(ZTSConsts.ZTS_PROP_TRUSTSTORE_PASSWORD, "pass123");
        System.setProperty(ZTSConsts.ZTS_PROP_KEYMANAGER_PASSWORD, "pass123");

        SslContextFactory sslContextFactory = ZTSUtils.createSSLContextObject(null);
        assertNotNull(sslContextFactory);
        assertFalse(sslContextFactory.getWantClientAuth());
        assertNull(sslContextFactory.getKeyStoreResource());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getTrustStoreResource().toString(), "file:///tmp/truststore");
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
    }
    
    @Test
    public void testCreateSSLContextObjectNoTrustStore() {
        
        System.setProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PATH, "file:///tmp/keystore");
        System.setProperty(ZTSConsts.ZTS_PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PASSWORD, "pass123");
        System.setProperty(ZTSConsts.ZTS_PROP_EXCLUDED_CIPHER_SUITES, ZTSUtils.ZTS_DEFAULT_EXCLUDED_CIPHER_SUITES);
        System.setProperty(ZTSConsts.ZTS_PROP_EXCLUDED_PROTOCOLS, ZTSUtils.ZTS_DEFAULT_EXCLUDED_PROTOCOLS);
        System.setProperty(ZTSConsts.ZTS_PROP_WANT_CLIENT_CERT, "true");

        SslContextFactory sslContextFactory = ZTSUtils.createSSLContextObject(null);
        assertNotNull(sslContextFactory);
        assertTrue(sslContextFactory.getWantClientAuth());
        assertEquals(sslContextFactory.getKeyStorePath(), "file:///tmp/keystore");
        assertEquals(sslContextFactory.getKeyStoreType(), "PKCS12");
        assertNull(sslContextFactory.getTrustStoreResource());
        // store type always defaults to PKCS12
        assertEquals(sslContextFactory.getTrustStoreType(), "PKCS12");
        assertEquals(sslContextFactory.getExcludeCipherSuites(), ZTSUtils.ZTS_DEFAULT_EXCLUDED_CIPHER_SUITES.split(","));
        assertEquals(sslContextFactory.getExcludeProtocols(), ZTSUtils.ZTS_DEFAULT_EXCLUDED_PROTOCOLS.split(","));
    }
    
    @Test
    public void testGenerateIdentityFailure() throws IOException {
        
        CertSigner certSigner = Mockito.mock(CertSigner.class);
        Mockito.when(certSigner.generateX509Certificate(Mockito.anyString())).thenReturn(null);
        
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        Identity identity = ZTSUtils.generateIdentity(certSigner, csr, "iaas.athens.syncer", "pem");
        assertNull(identity);
    }
}
