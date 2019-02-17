package com.yahoo.athenz.zts.cert;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.yahoo.athenz.common.server.ssh.SSHSigner;
import com.yahoo.athenz.zts.*;
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
import com.yahoo.athenz.zts.store.impl.ZMSFileChangeLogStore;
import com.yahoo.athenz.zts.utils.IPBlock;
import com.yahoo.athenz.auth.Principal;

public class InstanceCertManagerTest {

    @BeforeMethod
    public void setup() {
        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));
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
    public void testUpdateX509CertificateSigner() {

        final String caCert = "caCert";
        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        Mockito.when(certSigner.getCACertificate()).thenReturn(caCert);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, false);
        instanceManager.setCertSigner(certSigner);

        // first time our signer was null and we should get back the cert
        instanceManager.resetX509CertificateSigner();
        instanceManager.updateX509CertificateSigner();
        assertEquals("caCert", instanceManager.getX509CertificateSigner());

        // second time it should be a no-op
        instanceManager.updateX509CertificateSigner();
        assertEquals("caCert", instanceManager.getX509CertificateSigner());

        instanceManager.shutdown();
    }

    @Test
    public void testGetX509CertificateSigner() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, false);

        // first time our signer was null and we should get back the cert
        instanceManager.resetX509CertificateSigner();
        assertNotNull(instanceManager.getX509CertificateSigner());

        // second time it should be a no-op
        assertNotNull(instanceManager.getX509CertificateSigner());

        instanceManager.shutdown();

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD);
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
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001", "athenz.production")).thenReturn(x509CertRecord);
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
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001", "athenz.production")).thenReturn(x509CertRecord);
        instance.setCertStore(certStore);
        
        X509CertRecord certRecord = instance.getX509CertRecord("ostk", "1001", "athenz.production");
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

        certRecord = instance.getX509CertRecord("ostk", "instance-id", "athenz.production");
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
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001", "athenz.syncer")).thenReturn(x509CertRecord);
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
        
        Mockito.when(certConnection.deleteX509CertRecord("provider", "instance", "service")).thenReturn(true);
        instance.setCertStore(certStore);

        boolean result = instance.deleteX509CertRecord("provider", "instance", "service");
        assertTrue(result);
        instance.shutdown();
    }
    
    @Test
    public void testDeleteX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        instance.setCertStore(null);
        boolean result = instance.deleteX509CertRecord("provider", "instance", "service");
        assertFalse(result);
    }
    
    @Test
    public void testGetSSHCertificateSigner() {
        
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
    public void testGenerateSshIdentityExceptions() {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        Mockito.when(sshSigner.generateCertificate(null, sshRequest, "host"))
                .thenThrow(new com.yahoo.athenz.common.server.rest.ResourceException(403, "Forbidden"))
                .thenThrow(new RuntimeException("IO error"));

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);
        instanceManager.setSSHSigner(sshSigner);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");

        // first we should get the resource exception
        boolean result = instanceManager.generateSSHIdentity(null, identity, sshCsr, "host");
        assertFalse(result);

        // next we should get the io exception
        result = instanceManager.generateSSHIdentity(null, identity, sshCsr, "host");
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
        
        assertTrue(instance.verifyInstanceCertIPAddress("athenz.aws.us-west-2", "11.1.3.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("athenz.aws.us-west-2", "11.1.9.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("athenz.aws.us-west-2", "11.2.3.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("athenz.aws.us-east-1", "11.2.9.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("k8s.athenz.provider", "10.1.3.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("openstack.provider", "10.1.9.25"));
        
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

        assertTrue(instance.verifyInstanceCertIPAddress("athenz.aws.us-west-2", "11.1.3.25"));
        assertFalse(instance.verifyInstanceCertIPAddress("athenz.aws.us-west-2", "11.1.9.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("k8s.provider.cluster1", "11.2.3.25"));
        assertFalse(instance.verifyInstanceCertIPAddress("k8s.provider.cluster2", "11.2.9.25"));

        // no map file allows everything

        assertTrue(instance.verifyInstanceCertIPAddress("openstack.cluster", "10.1.3.25"));
        assertTrue(instance.verifyInstanceCertIPAddress("openstack.cluster", "10.1.9.25"));

        // invalid addresses in 10.x range

        assertFalse(instance.verifyInstanceCertIPAddress("athenz.aws.us-west-2", "10.1.3.25"));
        assertFalse(instance.verifyInstanceCertIPAddress("athenz.aws.us-west-2", "10.1.9.25"));

        // unknown domains are failure

        assertFalse(instance.verifyInstanceCertIPAddress("vespa.cluster", "10.1.3.25"));
        assertFalse(instance.verifyInstanceCertIPAddress("vespa.cluster", "10.1.9.25"));
        assertFalse(instance.verifyInstanceCertIPAddress("vespa", "10.1.3.25"));
        assertFalse(instance.verifyInstanceCertIPAddress("cluster", "10.1.9.25"));

        instance.shutdown();

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);
    }

    @Test
    public void testLoadAllowedCertIPAddressesInvalidFile() {

        System.setProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME, "invalid-file");

        try {
            InstanceCertManager instance = new InstanceCertManager(null, null, true);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Provider Allowed IP Blocks"));
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);
    }

    @Test
    public void testLoadAllowedCertIPAddressesInvalidJson() {

        System.setProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME, "src/test/resources/instance_cert_ipblocks_invalid_json.txt");

        try {
            InstanceCertManager instance = new InstanceCertManager(null, null, true);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Provider Allowed IP Blocks"));
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);
    }

    @Test
    public void testLoadAllowedCertIPAddressesInvalidIPFile() {

        System.setProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME, "src/test/resources/instance_cert_ipblocks_invalid_ip.txt");

        try {
            InstanceCertManager instance = new InstanceCertManager(null, null, true);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Provider Allowed IP Blocks"));
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);
    }

    @Test
    public void testLoadAllowedIPAddresses() {
        
        List<IPBlock> ipBlocks = new ArrayList<>();

        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertSigner(null);

        // empty or null filename returns success

        assertTrue(instance.loadAllowedIPAddresses(ipBlocks, null));
        assertTrue(instance.loadAllowedIPAddresses(ipBlocks, ""));

        // file does not exist returns failure
        
        assertFalse(instance.loadAllowedIPAddresses(ipBlocks, "some-invalid-filename"));

        // invalid json returns failure
        
        assertFalse(instance.loadAllowedIPAddresses(ipBlocks, "src/test/resources/invalid_ipblocks.txt"));
        
        // valid json with empty set returns failure
        
        assertFalse(instance.loadAllowedIPAddresses(ipBlocks, "src/test/resources/empty_ipblocks.txt"));

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
        instance.shutdown();
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
        instanceCertManager.shutdown();
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

    @Test
    public void testInitWithIncorrectCABundle() {

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "invalid-file");
        try {
            InstanceCertManager instanceCertManager = new InstanceCertManager(null, null, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(500, ex.getCode());
            assertTrue(ex.getMessage().contains("Unable to load X.509 CA Certificate bundle"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
    }

    @Test
    public void testInitWithMockSSHSigner() {

        System.setProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS, "com.yahoo.athenz.zts.cert.impl.MockSSHSignerFactory");
        InstanceCertManager instanceCertManager = new InstanceCertManager(null, null, true);
        assertNotNull(instanceCertManager);
        instanceCertManager.shutdown();
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS);
    }

    @Test
    public void testGetSSHCertificateSignerNoStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, false);
        instance.setCertSigner(null);

        assertNull(instance.getSSHCertificateSigner("host"));
        instance.shutdown();
    }

    @Test
    public void testGetSSHCertificateSignerMockStore() {
        System.setProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS, "com.yahoo.athenz.zts.cert.impl.MockSSHSignerFactory");
        InstanceCertManager instance = new InstanceCertManager(null, null, false);

        assertNull(instance.getSSHCertificateSigner("host"));
        assertNull(instance.getSSHCertificateSigner("user"));
        instance.shutdown();
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS);
    }

    @Test
    public void testUpdateSSHCertificateSigner() {

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST)).thenReturn("ssh-host");
        Mockito.when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER)).thenReturn("ssh-user");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);
        instanceManager.setSSHSigner(sshSigner);

        // first time we have nulls so we should get valid data

        instanceManager.updateSSHHostCertificateSigner();
        instanceManager.updateSSHUserCertificateSigner();

        // second time we should have no-ops

        instanceManager.updateSSHHostCertificateSigner();
        instanceManager.updateSSHUserCertificateSigner();

        assertEquals(instanceManager.getSSHCertificateSigner("host"), "ssh-host");
        assertEquals(instanceManager.getSSHCertificateSigner("user"), "ssh-user");

        instanceManager.shutdown();
    }

    @Test
    public void testExpiredX509CertRecordCleaner() {

        CertRecordStore store = Mockito.mock(CertRecordStore.class);
        Mockito.when(store.getConnection()).thenThrow(new RuntimeException("invalid connection"));

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, true);

        InstanceCertManager.ExpiredX509CertRecordCleaner cleaner =
                instanceManager.new ExpiredX509CertRecordCleaner(store, 100);

        // make sure no exceptions are thrown

        cleaner.run();
    }

    @Test
    public void testReadFileContentsException() {

        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        File file = new File("src/test/resources/athenz.conf");

        InstanceCertManager instanceManager = Mockito.spy(instance);
        Mockito.when(instanceManager.getFilePath(file))
                .thenThrow(new RuntimeException("invalid file"));

        assertNull(instanceManager.readFileContents("src/test/resources/athenz.conf"));
    }

    @Test
    public void testLogNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, true);
        instance.setCertStore(null);

        // passing all null which should typically return a NPE
        // however, with null cert store, we should never call log
        instance.log(null, null, null, null, null);
        instance.shutdown();
    }
}
