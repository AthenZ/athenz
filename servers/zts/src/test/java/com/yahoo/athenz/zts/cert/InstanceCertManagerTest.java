package com.yahoo.athenz.zts.cert;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.yahoo.athenz.common.server.ssh.SSHSigner;
import com.yahoo.athenz.zts.SSHCertRequest;
import com.yahoo.athenz.zts.SSHCertificate;
import com.yahoo.athenz.zts.SSHCertificates;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.zts.InstanceIdentity;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.store.impl.ZMSFileChangeLogStore;
import com.yahoo.athenz.zts.utils.IPBlock;
import com.yahoo.athenz.auth.Principal;

public class InstanceCertManagerTest {

    @BeforeMethod
    public void setup() {
        ZMSFileChangeLogStore.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "src/test/resources/valid_cn_x509.cert");
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");
    }
    
    @Test
    public void testGenerateIdentity() {
        
        final String cert = "cert";
        final String caCert = "caCert";
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.generateX509Certificate(Mockito.any(), Mockito.any(), Mockito.anyInt())).thenReturn(cert);
        Mockito.when(certSigner.getCACertificate()).thenReturn(caCert);
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, false);
        instanceManager.setCertSigner(certSigner);
        InstanceIdentity identity = instanceManager.generateIdentity("csr", "cn", null, 0);
        
        assertNotNull(identity);
        assertEquals(identity.getName(), "cn");
        assertEquals(identity.getX509Certificate(), cert);
        assertTrue(identity.getX509CertificateSigner().contains("-----BEGIN CERTIFICATE-----"));
        instanceManager.shutdown();
    }
    
    @Test
    public void testGenerateIdentityNullCert() {
        
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.generateX509Certificate(Mockito.any(), Mockito.any(), Mockito.anyInt())).thenReturn(null);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, false);
        instanceManager.setCertSigner(certSigner);
        InstanceIdentity identity = instanceManager.generateIdentity("csr", "cn", null, 0);
        assertNull(identity);
        instanceManager.shutdown();
    }
    
    @Test
    public void testGenerateIdentityEmptyCert() {
        
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.generateX509Certificate(Mockito.any(), Mockito.any(), Mockito.anyInt())).thenReturn("");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, false);
        instanceManager.setCertSigner(certSigner);
        InstanceIdentity identity = instanceManager.generateIdentity("csr", "cn", null, 0);
        assertNull(identity);
        instanceManager.shutdown();
    }
    
    @Test
    public void testGetX509CertRecordWithCertificate() throws IOException {
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);
        instanceManager.setCertSigner(null);

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        X509CertRecord x509CertRecord = new X509CertRecord();
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001")).thenReturn(x509CertRecord);
        instanceManager.setCertStore(certStore);
        
        X509CertRecord certRecord = instanceManager.getX509CertRecord("ostk", cert);
        assertNotNull(certRecord);
        instanceManager.shutdown();
    }
    
    @Test
    public void testGetX509CertRecordWithInstanceId() {
        
        InstanceCertManager instance = new InstanceCertManager(null, null, false);
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        X509CertRecord x509CertRecord = new X509CertRecord();
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001")).thenReturn(x509CertRecord);
        instance.setCertStore(certStore);
        
        X509CertRecord certRecord = instance.getX509CertRecord("ostk", "1001");
        assertNotNull(certRecord);
        instance.shutdown();
    }
    
    @Test
    public void testGetX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, false);
        instance.setCertSigner(null);

        instance.setCertStore(null);
        X509CertRecord certRecord = instance.getX509CertRecord("ostk", (X509Certificate) null);
        assertNull(certRecord);
        instance.shutdown();
    }
    
    @Test
    public void testGetX509CertRecordNoInstanceId() throws IOException {
        
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

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
        instance.shutdown();
    }
    
    @Test
    public void testUpdateX509CertRecord() {
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        Mockito.when(certConnection.updateX509CertRecord(ArgumentMatchers.isA(X509CertRecord.class))).thenReturn(true);
        instance.setCertStore(certStore);

        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.updateX509CertRecord(x509CertRecord);
        assertTrue(result);
        instance.shutdown();
    }
    
    @Test
    public void testUpdateX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        instance.setCertStore(null);
        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.updateX509CertRecord(x509CertRecord);
        assertFalse(result);
        instance.shutdown();
    }
    
    @Test
    public void testInsertX509CertRecord() {
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        Mockito.when(certConnection.insertX509CertRecord(ArgumentMatchers.isA(X509CertRecord.class))).thenReturn(true);
        instance.setCertStore(certStore);

        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.insertX509CertRecord(x509CertRecord);
        assertTrue(result);
        instance.shutdown();
    }
    
    @Test
    public void testInsertX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        instance.setCertStore(null);
        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.insertX509CertRecord(x509CertRecord);
        assertFalse(result);
        instance.shutdown();
    }
    
    @Test
    public void testDeleteX509CertRecord() {
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        
        Mockito.when(certConnection.deleteX509CertRecord("provider", "instance")).thenReturn(true);
        instance.setCertStore(certStore);

        boolean result = instance.deleteX509CertRecord("provider", "instance");
        assertTrue(result);
        instance.shutdown();
    }
    
    @Test
    public void testDeleteX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        instance.setCertStore(null);
        boolean result = instance.deleteX509CertRecord("provider", "instance");
        assertFalse(result);
    }
    
    @Test
    public void testGetSshCertificateSigner() {
        
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn("ssh-host");
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn("ssh-user");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);
        instanceManager.setSSHSigner(sshSigner);

        assertEquals(instanceManager.getSSHCertificateSigner("host"), "ssh-host");
        assertEquals(instanceManager.getSSHCertificateSigner("user"), "ssh-user");
        
        // second time we should not fetch from certsigner and use fetched copies
        
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn(null);
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn(null);
        assertEquals(instanceManager.getSSHCertificateSigner("host"), "ssh-host");
        assertEquals(instanceManager.getSSHCertificateSigner("user"), "ssh-user");
        instanceManager.shutdown();
    }
    
    @Test
    public void testGenerateSshIdentityNoSsh() {
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);
        instanceManager.setSSHSigner(null);

        boolean result = instanceManager.generateSSHIdentity(null, identity, null, null);
        assertTrue(result);
        assertNull(identity.getSshCertificate());
        
        result = instanceManager.generateSSHIdentity(null, identity, "", null);
        assertTrue(result);
        assertNull(identity.getSshCertificate());
        instanceManager.shutdown();
    }
    
    @Test
    public void testGenerateSshIdentityInvalidSsh() {
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);
        instanceManager.setSSHSigner(sshSigner);

        boolean result = instanceManager.generateSSHIdentity(null, identity, "{\"csr\":\"csr\"}", null);
        assertFalse(result);
    }
    
    @Test
    public void testGenerateSshIdentityNullCertError() {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        Mockito.when(sshSigner.generateCertificate(null, sshRequest, "host")).thenReturn(null);
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn("ssh-host");
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn("ssh-user");
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);
        instanceManager.setSSHSigner(sshSigner);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        boolean result = instanceManager.generateSSHIdentity(null, identity, sshCsr, "host");
        assertFalse(result);
        instanceManager.shutdown();
    }
    
    @Test
    public void testGenerateSshIdentityEmptyCertError() {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        SSHCertificates certs = new SSHCertificates();
        certs.setCertificates(Collections.emptyList());
        Mockito.when(sshSigner.generateCertificate(null, sshRequest, "host")).thenReturn(certs);
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn("ssh-host");
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn("ssh-user");
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);
        instanceManager.setSSHSigner(sshSigner);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        boolean result = instanceManager.generateSSHIdentity(null, identity, sshCsr, "host");
        assertFalse(result);
        instanceManager.shutdown();
    }
    
    @Test
    public void testGenerateSshIdentity() {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        SSHCertificates certs = new SSHCertificates();
        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("ssh-cert");
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        final SSHCertificates sshCertificates = certs.setCertificates(Collections.singletonList(cert));
        Mockito.when(sshSigner.generateCertificate(null, sshRequest, "host")).thenReturn(sshCertificates);
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn("ssh-host");
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn("ssh-user");
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);
        instanceManager.setSSHSigner(sshSigner);

        boolean result = instanceManager.generateSSHIdentity(null, identity, sshCsr, "host");
        assertTrue(result);
        assertEquals(identity.getSshCertificate(), "ssh-cert");
        assertEquals(identity.getSshCertificateSigner(), "ssh-host");
        instanceManager.shutdown();
    }
    
    @Test
    public void testVerifyIPAddressAccessEmptyList() {
        
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);
        
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        // empty list matches everything
        
        assertTrue(instance.verifyInstanceCertIPAddress("11.1.3.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("11.1.9.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("11.2.3.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("11.2.9.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("10.1.3.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("10.1.9.25"));
        
        assertTrue(instance.verifyCertRefreshIPAddress("10.1.3.25"));
        assertTrue(instance.verifyCertRefreshIPAddress("10.1.9.25"));
        assertTrue(instance.verifyCertRefreshIPAddress("10.2.3.25"));
        assertTrue(instance.verifyCertRefreshIPAddress("10.2.9.25"));
        assertTrue(instance.verifyCertRefreshIPAddress("11.1.3.25"));
        assertTrue(instance.verifyCertRefreshIPAddress("11.1.9.25"));
        instance.shutdown();
    }
    
    @Test
    public void testVerifyIPAddressAccessSpecifiedList() {
        
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME,
                "src/test/resources/cert_refresh_ipblocks.txt");
        System.setProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME,
                "src/test/resources/instance_cert_ipblocks.txt");
        
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        // refresh cert
        
        // subnet/netmask: 10.1.0.0/255.255.248.0
        // address range: 10.1.0.0 - 10.1.7.255
        
        // subnet/netmask: 10.2.0.0/255.255.248.0
        // address range: 10.2.0.0 - 10.2.7.255
        
        assertTrue(instance.verifyCertRefreshIPAddress("10.1.3.25"));
        assertFalse(instance.verifyCertRefreshIPAddress("10.1.9.25"));
        assertTrue(instance.verifyCertRefreshIPAddress("10.2.3.25"));
        assertFalse(instance.verifyCertRefreshIPAddress("10.2.9.25"));
        
        assertFalse(instance.verifyCertRefreshIPAddress("11.1.3.25"));
        assertFalse(instance.verifyCertRefreshIPAddress("11.1.9.25"));
        
        // instance register and refresh 
        
        // subnet/netmask: 11.1.0.0/255.255.248.0
        // address range: 11.1.0.0 - 11.1.7.255
        
        // subnet/netmask: 11.2.0.0/255.255.248.0
        // address range: 11.2.0.0 - 11.2.7.255
        
        assertTrue(instance.verifyInstanceCertIPAddress("11.1.3.25"));
        assertFalse(instance.verifyInstanceCertIPAddress("11.1.9.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("11.2.3.25"));
        assertFalse(instance.verifyInstanceCertIPAddress("11.2.9.25"));
        
        assertFalse(instance.verifyInstanceCertIPAddress("10.1.3.25"));
        assertFalse(instance.verifyInstanceCertIPAddress("10.1.9.25"));
        instance.shutdown();
    }
    
    @Test
    public void testLoadAllowedIPAddresses() {
        
        final String propName = "test_ip_property";
        List<IPBlock> ipBlocks = new ArrayList<>();

        System.clearProperty(propName);
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        // not set property returns true
        
        assertTrue(instance.loadAllowedIPAddresses(ipBlocks, propName));
        
        // file does not exist returns failure
        
        System.setProperty(propName, "some-invalid-filename");
        assertFalse(instance.loadAllowedIPAddresses(ipBlocks, propName));

        // invalid json returns failure
        
        System.setProperty(propName, "src/test/resources/invalid_ipblocks.txt");
        assertFalse(instance.loadAllowedIPAddresses(ipBlocks, propName));
        
        // valid json with empty set returns failure
        
        System.setProperty(propName, "src/test/resources/empty_ipblocks.txt");
        assertFalse(instance.loadAllowedIPAddresses(ipBlocks, propName));

        System.clearProperty(propName);
        instance.shutdown();
    }

    @Test
    public void testLoadCAX509CertificateBundle() {

        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        assertTrue(instance.loadCAX509CertificateBundle());

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "");
        assertTrue(instance.loadCAX509CertificateBundle());

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "non-existent-file");
        assertFalse(instance.loadCAX509CertificateBundle());

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "src/test/resources/valid_cn_x509.cert");
        assertTrue(instance.loadCAX509CertificateBundle());
        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
    }

    @Test
    public void testGetSSHCertificates() {

        InstanceCertManager instanceCertManager = new InstanceCertManager(null, null, true);
        instanceCertManager.setSSHSigner(null);

        assertNull(instanceCertManager.generateSSHCertificates(null, null));

        SSHSigner signer = Mockito.mock(SSHSigner.class);

        Principal principal = Mockito.mock(Principal.class);
        SSHCertRequest certRequest = new SSHCertRequest();
        SSHCertificates certs = new SSHCertificates();
        Mockito.when(signer.generateCertificate(principal, certRequest, null)).thenReturn(certs);
        instanceCertManager.setSSHSigner(signer);

        assertEquals(certs, instanceCertManager.generateSSHCertificates(principal, certRequest));
    }

    @Test
    public void testInvalidCertSignerClass() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS, "invalid");
        try {
            InstanceCertManager instanceCertManager = new InstanceCertManager(null, null, true);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid certsigner class"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);
    }

    @Test
    public void testInvalidSSHSignerClass() {

        System.setProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS, "invalid");
        try {
            InstanceCertManager instanceCertManager = new InstanceCertManager(null, null, true);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid sshsigner class"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS);
    }

    @Test
    public void testInvalidCertRecordStoreClass() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_RECORD_STORE_FACTORY_CLASS, "invalid");
        try {
            InstanceCertManager instanceCertManager = new InstanceCertManager(null, null, true);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid cert record store factory class"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_RECORD_STORE_FACTORY_CLASS);
    }
}
