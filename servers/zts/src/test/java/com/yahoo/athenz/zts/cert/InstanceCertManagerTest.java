package com.yahoo.athenz.zts.cert;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.mockito.Matchers;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertNotNull;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.zts.InstanceIdentity;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.store.impl.ZMSFileChangeLogStore;

public class InstanceCertManagerTest {

    @BeforeMethod
    public void setup() {
        ZMSFileChangeLogStore.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
    }
    
    @Test
    public void testGenerateIdentity() {
        
        final String cert = "cert";
        final String caCert = "caCert";
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.generateX509Certificate(Mockito.anyString(), Mockito.anyObject())).thenReturn(cert);
        Mockito.when(certSigner.getCACertificate()).thenReturn(caCert);
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, certSigner);
        InstanceIdentity identity = instanceManager.generateIdentity("csr", "cn", null);
        
        assertNotNull(identity);
        assertEquals(identity.getName(), "cn");
        assertEquals(identity.getX509Certificate(), cert);
        assertEquals(identity.getX509CertificateSigner(), caCert);
    }
    
    @Test
    public void testGenerateIdentityNullCert() {
        
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.generateX509Certificate(Mockito.anyString(), Mockito.anyObject())).thenReturn(null);

        InstanceCertManager instanceManager = new InstanceCertManager(null, certSigner);
        InstanceIdentity identity = instanceManager.generateIdentity("csr", "cn", null);
        assertNull(identity);
    }
    
    @Test
    public void testGenerateIdentityEmptyCert() {
        
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.generateX509Certificate(Mockito.anyString(), Mockito.anyObject())).thenReturn("");

        InstanceCertManager instanceManager = new InstanceCertManager(null, certSigner);
        InstanceIdentity identity = instanceManager.generateIdentity("csr", "cn", null);
        assertNull(identity);
    }
    
    @Test
    public void testGetX509CertRecordWithCertificate() throws IOException {
        
        InstanceCertManager instance = new InstanceCertManager(null, null);
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        X509CertRecord x509CertRecord = new X509CertRecord();
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001")).thenReturn(x509CertRecord);
        instance.setCertStore(certStore);
        
        X509CertRecord certRecord = instance.getX509CertRecord("ostk", cert);
        assertNotNull(certRecord);
    }
    
    @Test
    public void testGetX509CertRecordWithInstanceId() throws IOException {
        
        InstanceCertManager instance = new InstanceCertManager(null, null);
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        X509CertRecord x509CertRecord = new X509CertRecord();
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001")).thenReturn(x509CertRecord);
        instance.setCertStore(certStore);
        
        X509CertRecord certRecord = instance.getX509CertRecord("ostk", "1001");
        assertNotNull(certRecord);
    }
    
    @Test
    public void testGetX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null);
        instance.setCertStore(null);
        X509CertRecord certRecord = instance.getX509CertRecord("ostk", (X509Certificate) null);
        assertNull(certRecord);
    }
    
    @Test
    public void testGetX509CertRecordNoInstanceId() throws IOException {
        
        InstanceCertManager instance = new InstanceCertManager(null, null);

        Path path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        X509CertRecord x509CertRecord = new X509CertRecord();
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001")).thenReturn(x509CertRecord);
        instance.setCertStore(certStore);

        X509CertRecord certRecord = instance.getX509CertRecord("ostk", cert);
        assertNull(certRecord);
    }
    
    @Test
    public void testGetX509CertRecordNoConnection() throws IOException {
        
        InstanceCertManager instance = new InstanceCertManager(null, null);

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        Mockito.when(certStore.getConnection()).thenReturn(null);
        instance.setCertStore(certStore);

        X509CertRecord certRecord = instance.getX509CertRecord("ostk", cert);
        assertNull(certRecord);
    }
    
    @Test
    public void testUpdateX509CertRecord() {
        InstanceCertManager instance = new InstanceCertManager(null, null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        Mockito.when(certConnection.updateX509CertRecord(Matchers.isA(X509CertRecord.class))).thenReturn(true);
        instance.setCertStore(certStore);

        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.updateX509CertRecord(x509CertRecord);
        assertTrue(result);
    }
    
    @Test
    public void testUpdateX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null);
        instance.setCertStore(null);
        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.updateX509CertRecord(x509CertRecord);
        assertFalse(result);
    }
    
    @Test
    public void testUpdateX509CertRecordNoConnection() {
        InstanceCertManager instance = new InstanceCertManager(null, null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        Mockito.when(certStore.getConnection()).thenReturn(null);
        instance.setCertStore(certStore);

        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.updateX509CertRecord(x509CertRecord);
        assertFalse(result);
    }
    
    @Test
    public void testInsertX509CertRecord() {
        InstanceCertManager instance = new InstanceCertManager(null, null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        Mockito.when(certConnection.insertX509CertRecord(Matchers.isA(X509CertRecord.class))).thenReturn(true);
        instance.setCertStore(certStore);

        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.insertX509CertRecord(x509CertRecord);
        assertTrue(result);
    }
    
    @Test
    public void testInsertX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null);
        instance.setCertStore(null);
        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.insertX509CertRecord(x509CertRecord);
        assertFalse(result);
    }
    
    @Test
    public void testInsertX509CertRecordNoConnection() {
        InstanceCertManager instance = new InstanceCertManager(null, null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        Mockito.when(certStore.getConnection()).thenReturn(null);
        instance.setCertStore(certStore);

        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.insertX509CertRecord(x509CertRecord);
        assertFalse(result);
    }
    
    @Test
    public void testDeleteX509CertRecord() {
        InstanceCertManager instance = new InstanceCertManager(null, null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        Mockito.when(certConnection.deleteX509CertRecord("provider", "instance")).thenReturn(true);
        instance.setCertStore(certStore);

        boolean result = instance.deleteX509CertRecord("provider", "instance");
        assertTrue(result);
    }
    
    @Test
    public void testDeleteX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null);
        instance.setCertStore(null);
        boolean result = instance.deleteX509CertRecord("provider", "instance");
        assertFalse(result);
    }
    
    @Test
    public void testDeleteX509CertRecordNoConnection() {
        InstanceCertManager instance = new InstanceCertManager(null, null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        Mockito.when(certStore.getConnection()).thenReturn(null);
        instance.setCertStore(certStore);

        boolean result = instance.deleteX509CertRecord("provider", "instance");
        assertFalse(result);
    }
    
    @Test
    public void testGetSshCertificateSigner() {
        
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn("ssh-host");
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn("ssh-user");

        InstanceCertManager instanceManager = new InstanceCertManager(null, certSigner);
        assertEquals(instanceManager.getSshCertificateSigner("host"), "ssh-host");
        assertEquals(instanceManager.getSshCertificateSigner("user"), "ssh-user");
        
        // second time we should not fetch from certsigner and use fetched copies
        
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn(null);
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn(null);
        assertEquals(instanceManager.getSshCertificateSigner("host"), "ssh-host");
        assertEquals(instanceManager.getSshCertificateSigner("user"), "ssh-user");
    }
    
    @Test
    public void testGenerateSshIdentityNoSsh() {
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        InstanceCertManager instanceManager = new InstanceCertManager(null, null);

        boolean result = instanceManager.generateSshIdentity(identity, null, null);
        assertTrue(result);
        assertNull(identity.getSshCertificate());
        
        result = instanceManager.generateSshIdentity(identity, "", null);
        assertTrue(result);
        assertNull(identity.getSshCertificate());
    }
    
    @Test
    public void testGenerateSshIdentityInvalidSsh() {
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        InstanceCertManager instanceManager = new InstanceCertManager(null, null);

        boolean result = instanceManager.generateSshIdentity(identity, "{\"csr\":\"csr\"}", null);
        assertFalse(result);
    }
    
    @Test
    public void testGenerateSshIdentityNullCertError() {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.generateSSHCertificate(sshCsr)).thenReturn(null);
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn("ssh-host");
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn("ssh-user");
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, certSigner);
        
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        boolean result = instanceManager.generateSshIdentity(identity, sshCsr, "host");
        assertFalse(result);
    }
    
    @Test
    public void testGenerateSshIdentityEmptyCertError() {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.generateSSHCertificate(sshCsr)).thenReturn("");
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn("ssh-host");
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn("ssh-user");
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, certSigner);
        
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        boolean result = instanceManager.generateSshIdentity(identity, sshCsr, "host");
        assertFalse(result);
    }
    
    @Test
    public void testGenerateSshIdentity() {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.generateSSHCertificate(sshCsr)).thenReturn("ssh-cert");
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn("ssh-host");
        Mockito.when(certSigner.getSSHCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn("ssh-user");
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, certSigner);
        
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        boolean result = instanceManager.generateSshIdentity(identity, sshCsr, "host");
        assertTrue(result);
        assertEquals(identity.getSshCertificate(), "ssh-cert");
        assertEquals(identity.getSshCertificateSigner(), "ssh-host");
    }
}
