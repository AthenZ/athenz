/*
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

import com.google.common.io.Resources;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.zts.Identity;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.X509CertRecord;

import javax.net.ssl.SSLContext;

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

        System.clearProperty("athenz.ssl_key_store");
        System.clearProperty("athenz.ssl_key_store_password");
        System.clearProperty("athenz.ssl_trust_store");
        System.clearProperty("athenz.ssl_trust_store_type");
        System.clearProperty("athenz.ssl_trust_store_password");
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
        
        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.generateX509Certificate(Mockito.any(), Mockito.any(),
                Mockito.anyInt())).thenReturn(null);
        
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        Identity identity = ZTSUtils.generateIdentity(certManager, csr, "unknown.syncer", null, 0);
        assertNull(identity);
    }
    
    @Test
    public void testValidateCertReqInstanceId() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        
        boolean result = ZTSUtils.validateCertReqInstanceId(certReq, "1001");
        assertTrue(result);
        
        result = ZTSUtils.validateCertReqInstanceId(certReq, "10012");
        assertFalse(result);
    }
    
    @Test
    public void testValidateCertReqInstanceIdInvalid() throws IOException {
        Path path = Paths.get("src/test/resources/invalid_dns.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        
        boolean result = ZTSUtils.validateCertReqInstanceId(certReq, "1001");
        assertFalse(result);
    }
    
    @Test
    public void testVerifyCertificateRequest() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setService("athenz.production");
        certRecord.setInstanceId("1001");
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        boolean result = ZTSUtils.verifyCertificateRequest(certReq, "athenz", "production", certRecord);
        assertTrue(result);
        
        certRecord.setService("athenz.production");
        certRecord.setInstanceId("1001");
        result = ZTSUtils.verifyCertificateRequest(certReq, "athenz2", "production", certRecord);
        assertFalse(result);
        
        certRecord.setService("athenz2.production");
        certRecord.setInstanceId("1001");
        result = ZTSUtils.verifyCertificateRequest(certReq, "athenz", "production", certRecord);
        assertFalse(result);
        
        certRecord.setService("athenz.production");
        certRecord.setInstanceId("1002");
        result = ZTSUtils.verifyCertificateRequest(certReq, "athenz", "production", certRecord);
        assertFalse(result);
    }
    
    @Test
    public void testVerifyCertificateRequestMismatchDns() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.mismatch.cn.csr");
        String csr = new String(Files.readAllBytes(path));
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        boolean result = ZTSUtils.verifyCertificateRequest(certReq, "athenz2", "production", null);
        assertFalse(result);
    }
    
    @Test
    public void testVerifyCertificateRequestNoCertRecord() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        boolean result = ZTSUtils.verifyCertificateRequest(certReq, "athenz", "production", null);
        assertTrue(result);
        
        result = ZTSUtils.verifyCertificateRequest(certReq, "athenz2", "production", null);
        assertFalse(result);
    }
    
    @Test
    public void testValidateCertReqDNSNames() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        boolean result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz", "production");
        assertTrue(result);
        
        result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz2", "production");
        assertFalse(result);
        
        result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz2", "productio2");
        assertFalse(result);
    }
    
    @Test
    public void testValidateCertReqDNSNamesNoDNS() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        // no dns names so all are valid
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        boolean result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz", "production");
        assertTrue(result);
        
        result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz2", "production");
        assertTrue(result);
        
        result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz2", "productio2");
        assertTrue(result);
    }
    
    @Test
    public void testValidateCertReqDNSNamesUnknown() throws IOException {
        Path path = Paths.get("src/test/resources/invalid_dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        // includes www.athenz.io as dns name so it should be rejected
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        boolean result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz", "production");
        assertFalse(result);
        
        result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz", "production");
        assertFalse(result);
    }
    
    @Test
    public void testValidateCertReqDNSNamesSubdomain() throws IOException {
        Path path = Paths.get("src/test/resources/subdomain.csr");
        String csr = new String(Files.readAllBytes(path));
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        boolean result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz.domain", "production");
        assertTrue(result);
    }
    
    @Test
    public void testValidateCertReqDNSNamesSubdomainInvalid() throws IOException {
        Path path = Paths.get("src/test/resources/subdomain_invalid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        boolean result = ZTSUtils.validateCertReqDNSNames(certReq, "athenz.domain", "production");
        assertFalse(result);
    }
    
    @Test
    public void testValidateCertReqCommonNameException() {
        
        PKCS10CertificationRequest certReq = Mockito.mock(PKCS10CertificationRequest.class);
        Mockito.when(certReq.getSubject()).thenThrow(new CryptoException());
        
        assertFalse(ZTSUtils.validateCertReqCommonName(certReq, "athenz.syncer"));
    }
    
    @Test
    public void testGetApplicationSecret() {
        assertEquals(ZTSUtils.getApplicationSecret(null, "appname", "pass"), "pass");
        
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.when(keyStore.getApplicationSecret(null, "pass")).thenReturn("app234");
        assertEquals(ZTSUtils.getApplicationSecret(keyStore, null, "pass"), "app234");
        
        Mockito.when(keyStore.getApplicationSecret("appname", "passname")).thenReturn("app123");
        assertEquals(ZTSUtils.getApplicationSecret(keyStore, "appname", "passname"), "app123");
    }

    @Test
    public void testCreateSSLClientContextObject() {

        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.ssl_key_store", filePath);
        System.setProperty("athenz.ssl_key_store_password", "123456");

        filePath = Resources.getResource("truststore.jks").getFile();
        System.setProperty("athenz.ssl_trust_store", filePath);
        System.setProperty("athenz.ssl_trust_store_type", "JKS");
        System.setProperty("athenz.ssl_trust_store_password", "123456");

        SSLContext sslContext = ZTSUtils.createServerClientSSLContext(null);
        assertNotNull(sslContext);
    }

    @Test
    public void testCreateSSLClientContextObjectEmptyKeyStore() {

        // make sure we have no keystore path
        System.clearProperty("athenz.ssl_key_store");
        SSLContext sslContext = ZTSUtils.createServerClientSSLContext(null);
        assertNull(sslContext);
    }

    @Test
    public void testCreateSSLClientContextObjectEmptyTrustStore() {

        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.ssl_key_store", filePath);
        System.setProperty("athenz.ssl_key_store_password", "123456");

        // make sure we have no truststore path
        System.clearProperty("athenz.ssl_trust_store");
        SSLContext sslContext = ZTSUtils.createServerClientSSLContext(null);
        assertNull(sslContext);
    }

    @Test
    public void testCreateSSLClientContextObjectInvalidTrustPass() {

        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.ssl_key_store", filePath);
        System.setProperty("athenz.ssl_key_store_password", "123456");

        filePath = Resources.getResource("truststore.jks").getFile();
        System.setProperty("athenz.ssl_trust_store", filePath);
        System.setProperty("athenz.ssl_trust_store_type", "JKS");
        System.setProperty("athenz.ssl_trust_store_password", "invalid");

        SSLContext sslContext = ZTSUtils.createServerClientSSLContext(null);
        assertNull(sslContext);
    }

    @Test
    public void testCreateSSLClientContextObjectNullTrustPass() {

        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.ssl_key_store", filePath);
        System.setProperty("athenz.ssl_key_store_password", "123456");

        filePath = Resources.getResource("truststore.jks").getFile();
        System.setProperty("athenz.ssl_trust_store", filePath);
        System.setProperty("athenz.ssl_trust_store_type", "JKS");
        System.clearProperty("athenz.ssl_trust_store_password");

        SSLContext sslContext = ZTSUtils.createServerClientSSLContext(null);
        assertNull(sslContext);
    }

    @Test
    public void testCreateSSLClientContextObjectInvalidKeyPass() {

        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.ssl_key_store", filePath);
        System.setProperty("athenz.ssl_key_store_password", "invalid");

        filePath = Resources.getResource("truststore.jks").getFile();
        System.setProperty("athenz.ssl_trust_store", filePath);
        System.setProperty("athenz.ssl_trust_store_type", "JKS");
        System.setProperty("athenz.ssl_trust_store_password", "123456");

        SSLContext sslContext = ZTSUtils.createServerClientSSLContext(null);
        assertNull(sslContext);
    }

    @Test
    public void testCreateSSLClientContextObjectNullKeyPass() {

        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.ssl_key_store", filePath);
        System.clearProperty("athenz.ssl_key_store_password");

        filePath = Resources.getResource("truststore.jks").getFile();
        System.setProperty("athenz.ssl_trust_store", filePath);
        System.setProperty("athenz.ssl_trust_store_type", "JKS");
        System.setProperty("athenz.ssl_trust_store_password", "123456");

        SSLContext sslContext = ZTSUtils.createServerClientSSLContext(null);
        assertNull(sslContext);
    }

    @Test
    public void testCreateSSLClientContextObjectInvalidType() {

        String filePath = Resources.getResource("keystore.pkcs12").getFile();
        System.setProperty("athenz.ssl_key_store", filePath);
        System.setProperty("athenz.ssl_key_store_password", "123456");

        filePath = Resources.getResource("truststore.jks").getFile();
        System.setProperty("athenz.ssl_trust_store", filePath);
        System.setProperty("athenz.ssl_trust_store_type", "PKS12");
        System.setProperty("athenz.ssl_trust_store_password", "123456");

        SSLContext sslContext = ZTSUtils.createServerClientSSLContext(null);
        assertNull(sslContext);
    }

    @Test
    public void testGetPasswordChars() {
        char [] emptyValue = new char[0];
        char [] passValue = {'p', 'a', 's', 's'};

        assertEquals(emptyValue, ZTSUtils.getPasswordChars(null));
        assertEquals(emptyValue, ZTSUtils.getPasswordChars(""));
        assertEquals(passValue, ZTSUtils.getPasswordChars("pass"));
    }

    @Test
    public void testParseInt() {
        assertEquals(0, ZTSUtils.parseInt(null, 0));
        assertEquals(-1, ZTSUtils.parseInt("", -1));
        assertEquals(100, ZTSUtils.parseInt("100", 1));
        assertEquals(0, ZTSUtils.parseInt("abc", 0));
    }

    @Test
    public void testParseBoolean() {
        assertEquals(true, ZTSUtils.parseBoolean(null, true));
        assertEquals(false, ZTSUtils.parseBoolean(null, false));
        assertEquals(true, ZTSUtils.parseBoolean("", true));
        assertEquals(false, ZTSUtils.parseBoolean("", false));
        assertEquals(true, ZTSUtils.parseBoolean("true", false));
        assertEquals(false, ZTSUtils.parseBoolean("false", true));
        assertEquals(false, ZTSUtils.parseBoolean("unknown", false));
    }
}
