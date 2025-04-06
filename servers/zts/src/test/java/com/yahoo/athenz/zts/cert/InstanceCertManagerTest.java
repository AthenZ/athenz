package com.yahoo.athenz.zts.cert;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.server.cert.*;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.ssh.SSHRecordStore;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import com.yahoo.athenz.common.server.ssh.SSHSigner;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import com.yahoo.athenz.zts.*;
import com.yahoo.athenz.zts.cert.impl.FileSSHRecordStoreFactory;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.utils.IPBlock;
import com.yahoo.athenz.auth.Principal;

public class InstanceCertManagerTest {

    @BeforeMethod
    public void setup() {
        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_ssh_store"));
        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_workloads_store"));
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "src/test/resources/valid_cn_x509.cert");
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");
        System.setProperty(ZTSConsts.ZTS_PROP_SSH_FILE_STORE_PATH, "/tmp/zts_server_ssh_store");
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_FILE_STORE_PATH, "/tmp/zts_server_workloads_store");
        System.setProperty(ZTSConsts.ZTS_PROP_SSH_RECORD_STORE_FACTORY_CLASS, "com.yahoo.athenz.zts.cert.impl.FileSSHRecordStoreFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_RECORD_STORE_FACTORY_CLASS, "com.yahoo.athenz.zts.workload.impl.FileWorkloadRecordStoreFactory");
    }
    
    @Test
    public void testGenerateIdentity() throws ServerResourceException {
        
        final String cert = "cert";
        final String caCert = "caCert";
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        when(certSigner.generateX509Certificate(any(), any(), any(), any(), anyInt(), any(), any())).thenReturn(cert);
        when(certSigner.getCACertificate(any(), any())).thenReturn(caCert);
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instanceManager.setCertSigner(certSigner);
        InstanceIdentity identity = instanceManager.generateIdentity("aws", "us-west-2", "csr", "cn", null, 0,
                Priority.Unspecified_priority, null);
        
        assertNotNull(identity);
        assertEquals(identity.getName(), "cn");
        assertEquals(identity.getX509Certificate(), cert);
        assertTrue(identity.getX509CertificateSigner().contains("-----BEGIN CERTIFICATE-----"));
        instanceManager.shutdown();
    }

    @Test
    public void testUpdateX509CertificateSigner() throws ServerResourceException {

        final String caCert = "caCert";
        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        when(certSigner.getCACertificate("aws", null)).thenReturn(caCert);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instanceManager.setCertSigner(certSigner);

        // first time our signer was null and we should get back the cert
        instanceManager.resetX509CertificateSigner();
        assertEquals(instanceManager.getX509CertificateSigner("aws", null), "caCert");

        // second time it should be a no-op
        assertEquals(instanceManager.getX509CertificateSigner("aws", null), "caCert");

        instanceManager.shutdown();
    }

    @Test
    public void testUpdateX509CertificateSignerNullReturn() throws ServerResourceException {

        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        when(certSigner.getCACertificate("aws", null)).thenReturn(null);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instanceManager.setCertSigner(certSigner);

        assertNull(instanceManager.getX509CertificateSigner("aws", null));

        // second time it should be null again
        assertNull(instanceManager.getX509CertificateSigner("aws", null));

        instanceManager.shutdown();
    }

    @Test
    public void testGetX509CertificateSigner() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));

        // first time our signer was null and we should get back the cert
        instanceManager.resetX509CertificateSigner();
        assertNotNull(instanceManager.getX509CertificateSigner("aws", null));

        // second time it should be a no-op
        assertNotNull(instanceManager.getX509CertificateSigner("aws", null));

        instanceManager.shutdown();

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD);
    }

    @Test
    public void testGetX509CertificateSignerWhenDisabled() {

        System.setProperty(ZTSConsts.ZTS_PROP_RESP_X509_SIGNER_CERTS, "false");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));

        instanceManager.resetX509CertificateSigner();
        assertNull(instanceManager.getX509CertificateSigner("aws", null));

        instanceManager.shutdown();

        System.clearProperty(ZTSConsts.ZTS_PROP_RESP_X509_SIGNER_CERTS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD);
    }

    @Test
    public void testGenerateIdentityNullCert() throws ServerResourceException {
        
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        when(certSigner.generateX509Certificate(any(), any(), any(), any(), anyInt(), any(), any())).thenReturn(null);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instanceManager.setCertSigner(certSigner);
        InstanceIdentity identity = instanceManager.generateIdentity("aws", "us-west-2", "csr", "cn", null, 0,
                Priority.Unspecified_priority, null);
        assertNull(identity);
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateIdentityExceptions() throws ServerResourceException {

        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);

        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        when(certSigner.generateX509Certificate(any(), any(), any(), any(), anyInt(), any(), any()))
                .thenThrow(new ServerResourceException(400, "invalid get request"));
        when(certSigner.getCACertificate(any(), any()))
                .thenThrow(new ServerResourceException(400, "invalid ca request"));

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instanceManager.setCertSigner(certSigner);

        assertNull(instanceManager.generateX509Certificate("aws", "us-west-2", "csr", "sign", 0,
                Priority.Unspecified_priority, null));
        assertNull(instanceManager.getX509CertificateSigner("aws", "keyid"));
        instanceManager.shutdown();
    }
    
    @Test
    public void testGenerateIdentityEmptyCert() throws ServerResourceException {
        
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        when(certSigner.generateX509Certificate(any(), any(), any(), any(), anyInt(), any(), any())).thenReturn("");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instanceManager.setCertSigner(certSigner);
        InstanceIdentity identity = instanceManager.generateIdentity("aws", "us-west-2", "csr", "cn", null, 0,
                Priority.Unspecified_priority, null);
        assertNull(identity);
        instanceManager.shutdown();
    }
    
    @Test
    public void testGetX509CertRecordWithCertificate() throws IOException, ServerResourceException {

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instanceManager.setCertSigner(null);

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);
        
        X509CertRecord x509CertRecord = new X509CertRecord();
        when(certConnection.getX509CertRecord("ostk", "1001", "athenz.production")).thenReturn(x509CertRecord);
        instanceManager.setCertStore(certStore);
        
        X509CertRecord certRecord = instanceManager.getX509CertRecord("ostk", cert);
        assertNotNull(certRecord);
        instanceManager.shutdown();
    }
    
    @Test
    public void testGetX509CertRecordWithInstanceId() throws ServerResourceException {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);
        
        X509CertRecord x509CertRecord = new X509CertRecord();
        when(certConnection.getX509CertRecord("ostk", "1001", "athenz.production")).thenReturn(x509CertRecord);
        instance.setCertStore(certStore);
        
        X509CertRecord certRecord = instance.getX509CertRecord("ostk", "1001", "athenz.production");
        assertNotNull(certRecord);
        instance.shutdown();
    }
    
    @Test
    public void testGetX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instance.setCertSigner(null);

        instance.setCertStore(null);
        X509CertRecord certRecord = instance.getX509CertRecord("ostk", null);
        assertNull(certRecord);

        certRecord = instance.getX509CertRecord("ostk", "instance-id", "athenz.production");
        assertNull(certRecord);

        instance.shutdown();
    }
    
    @Test
    public void testGetX509CertRecordNoInstanceId() throws IOException, ServerResourceException {
        
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertSigner(null);

        Path path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);
        
        X509CertRecord x509CertRecord = new X509CertRecord();
        when(certConnection.getX509CertRecord("ostk", "1001", "athenz.syncer")).thenReturn(x509CertRecord);
        instance.setCertStore(certStore);

        X509CertRecord certRecord = instance.getX509CertRecord("ostk", cert);
        assertNull(certRecord);
        instance.shutdown();
    }
    
    @Test
    public void testUpdateX509CertRecord() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);
        
        when(certConnection.updateX509CertRecord(ArgumentMatchers.isA(X509CertRecord.class))).thenReturn(true);
        instance.setCertStore(certStore);

        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.updateX509CertRecord(x509CertRecord);
        assertTrue(result);
        instance.shutdown();
    }
    
    @Test
    public void testUpdateX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertSigner(null);

        instance.setCertStore(null);
        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.updateX509CertRecord(x509CertRecord);
        assertFalse(result);
        instance.shutdown();
    }
    
    @Test
    public void testInsertX509CertRecord() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);
        
        when(certConnection.insertX509CertRecord(ArgumentMatchers.isA(X509CertRecord.class))).thenReturn(true);
        instance.setCertStore(certStore);

        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.insertX509CertRecord(x509CertRecord);
        assertTrue(result);
        instance.shutdown();
    }
    
    @Test
    public void testInsertX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertSigner(null);

        instance.setCertStore(null);
        X509CertRecord x509CertRecord = new X509CertRecord();
        boolean result = instance.insertX509CertRecord(x509CertRecord);
        assertFalse(result);
        instance.shutdown();
    }
    
    @Test
    public void testDeleteX509CertRecord() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);
        
        when(certConnection.deleteX509CertRecord("provider", "instance", "service")).thenReturn(true);
        instance.setCertStore(certStore);

        boolean result = instance.deleteX509CertRecord("provider", "instance", "service");
        assertTrue(result);
        instance.shutdown();
    }
    
    @Test
    public void testDeleteX509CertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertSigner(null);

        instance.setCertStore(null);
        boolean result = instance.deleteX509CertRecord("provider", "instance", "service");
        assertFalse(result);
    }
    
    @Test
    public void testGetSSHCertificateSigner() throws ServerResourceException {
        
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER, null)).thenReturn("ssh-user");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertEquals(instanceManager.getSSHCertificateSigner("host", null), "ssh-host");
        assertEquals(instanceManager.getSSHCertificateSigner("user", null), "ssh-user");
        
        // second time we should not fetch from certsigner and use fetched copies
        
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn(null);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER, null)).thenReturn(null);
        assertEquals(instanceManager.getSSHCertificateSigner("host", null), "ssh-host");
        assertEquals(instanceManager.getSSHCertificateSigner("user", null), "ssh-user");
        instanceManager.shutdown();
    }

    @Test
    public void testGetSSHCertificateSignerCAFiles() {

        System.setProperty("athenz.zts.ssh_host_ca_cert_fname", "src/test/resources/ssh-host-file");
        System.setProperty("athenz.zts.ssh_user_ca_cert_fname", "src/test/resources/ssh-user-file");

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertEquals(instanceManager.getSSHCertificateSigner("host", null), "ssh-host");
        assertEquals(instanceManager.getSSHCertificateSigner("host", "key-id"), "ssh-host");

        assertEquals(instanceManager.getSSHCertificateSigner("user", null), "ssh-user");
        assertEquals(instanceManager.getSSHCertificateSigner("user", "key-id"), "ssh-user");

        instanceManager.shutdown();
        System.clearProperty("athenz.zts.ssh_host_ca_cert_fname");
        System.clearProperty("athenz.zts.ssh_user_ca_cert_fname");
    }

    @Test
    public void testGetSSHCertificateSignerFailure() throws ServerResourceException {

        System.clearProperty("athenz.zts.ssh_host_ca_cert_fname");
        System.clearProperty("athenz.zts.ssh_user_ca_cert_fname");

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null))
                .thenThrow(new ServerResourceException(400, "invalid request"));
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertNull(instanceManager.getSSHCertificateSigner("host", null));
        instanceManager.shutdown();
    }

    @Test
    public void testGetSSHCertificateSignerKeyId() throws ServerResourceException {

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, "key1")).thenReturn("ssh-host")
                .thenThrow(new ServerResourceException(403, "Forbidden"));
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER, "key2")).thenReturn("ssh-user")
                .thenThrow(new ServerResourceException(403, "Forbidden"));

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertNull(instanceManager.getSSHCertificateSigner("host", null));
        assertNull(instanceManager.getSSHCertificateSigner("user", null));

        assertEquals(instanceManager.getSSHCertificateSigner("host", "key1"), "ssh-host");
        assertNull(instanceManager.getSSHCertificateSigner("host", "key2"));

        assertEquals(instanceManager.getSSHCertificateSigner("user", "key2"), "ssh-user");
        assertNull(instanceManager.getSSHCertificateSigner("user", "key1"));

        // second time calling should return from the cache so no exceptions

        assertEquals(instanceManager.getSSHCertificateSigner("host", "key1"), "ssh-host");
        assertEquals(instanceManager.getSSHCertificateSigner("user", "key2"), "ssh-user");

        instanceManager.shutdown();
    }

    @Test
    public void testGetSSHCertificateSignerWhenDisabled() throws ServerResourceException {

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER, null)).thenReturn("ssh-user");

        System.setProperty(ZTSConsts.ZTS_PROP_RESP_SSH_SIGNER_CERTS, "false");
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertNull(instanceManager.getSSHCertificateSigner("host", null));
        assertNull(instanceManager.getSSHCertificateSigner("user", null));

        System.clearProperty(ZTSConsts.ZTS_PROP_RESP_SSH_SIGNER_CERTS);
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityNoSsh() {
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(null);

        boolean result = instanceManager.generateSSHIdentity(null, identity, null, null, null, null, null,
                true, Collections.emptySet(), null);
        assertTrue(result);
        assertNull(identity.getSshCertificate());
        
        result = instanceManager.generateSSHIdentity(null, identity, null, "", null, null, null,
                true, Collections.emptySet(), null);
        assertTrue(result);
        assertNull(identity.getSshCertificate());
        instanceManager.shutdown();
    }
    
    @Test
    public void testGenerateSshIdentityInvalidSsh() {
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        boolean result = instanceManager.generateSSHIdentity(null, identity, "host.athenz.com", "{\"csr\":\"csr\"}",
                null, new SSHCertRecord(), ZTSConsts.ZTS_SSH_HOST, true, Collections.emptySet(), null);
        assertFalse(result);
    }
    
    @Test
    public void testGenerateSshIdentityNullCertError() throws ServerResourceException {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        when(sshSigner.generateCertificate(null, sshRequest, null, "host", null)).thenReturn(null);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER, null)).thenReturn("ssh-user");
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        boolean result = instanceManager.generateSSHIdentity(null, identity, null, sshCsr,
                null, new SSHCertRecord(), "host", true, Collections.emptySet(), null);
        assertFalse(result);
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityExceptions() throws ServerResourceException {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        when(sshSigner.generateCertificate(null, sshRequest, null, "host", null))
                .thenThrow(new ServerResourceException(403, "Forbidden"))
                .thenThrow(new RuntimeException("IO error"));

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");

        // first we should get the resource exception
        boolean result = instanceManager.generateSSHIdentity(null, identity, "", sshCsr, null,
                new SSHCertRecord(), "host", true, Collections.emptySet(), null);
        assertFalse(result);

        // next we should get the io exception
        result = instanceManager.generateSSHIdentity(null, identity, "", sshCsr, null, new SSHCertRecord(),
                "host", true, Collections.emptySet(), null);
        assertFalse(result);

        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityEmptyCertError() throws ServerResourceException {
        String sshCsr = "{\"csr\":\"csr\",\"certtype\":\"host\"}";
        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        SSHCertificates certs = new SSHCertificates();
        certs.setCertificates(Collections.emptyList());
        when(sshSigner.generateCertificate(null, sshRequest, null, "host", null)).thenReturn(certs);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER, null)).thenReturn("ssh-user");
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        boolean result = instanceManager.generateSSHIdentity(null, identity, null, sshCsr,
                null, new SSHCertRecord(), "host", true, Collections.emptySet(), null);
        assertFalse(result);
        instanceManager.shutdown();
    }
    
    @Test
    public void testGenerateSshIdentityHost() throws ServerResourceException {
        String sshCsr = "{\"pubkey\":\"key\",\"certtype\":\"host\"}";
        SSHSigner sshSigner = Mockito.mock(SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        SSHCertificates certs = new SSHCertificates();
        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("ssh-cert");
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setPrincipals("127.0.0.1");
        final SSHCertificates sshCertificates = certs.setCertificates(Collections.singletonList(cert));
        when(sshSigner.generateCertificate(null, sshRequest, sshCertRecord, "host", null)).thenReturn(sshCertificates);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER, null)).thenReturn("ssh-user");
        
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertTrue(instanceManager.generateSSHIdentity(null, identity, null, sshCsr,
                null, sshCertRecord, "host", true, Collections.emptySet(), null));
        assertEquals(identity.getSshCertificate(), "ssh-cert");
        assertEquals(identity.getSshCertificateSigner(), "ssh-host");
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityHostException() throws ServerResourceException {
        String sshCsr = "{\"pubkey\":\"key\",\"certtype\":\"host\"}";
        SSHSigner sshSigner = Mockito.mock(SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("ssh-cert");
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setPrincipals("127.0.0.1");
        when(sshSigner.generateCertificate(null, sshRequest, sshCertRecord, "host", null))
                .thenThrow(new ServerResourceException(400, "invalid request"));
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER, null)).thenReturn("ssh-user");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertFalse(instanceManager.generateSSHIdentity(null, identity, null, sshCsr,
                null, sshCertRecord, "host", true, Collections.emptySet(), null));
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityUser() throws ServerResourceException {
        String sshCsr = "{\"pubkey\":\"key\",\"certtype\":\"user\"}";
        SSHSigner sshSigner = Mockito.mock(SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        SSHCertificates certs = new SSHCertificates();
        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("ssh-cert");
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setPrincipals("127.0.0.1");
        final SSHCertificates sshCertificates = certs.setCertificates(Collections.singletonList(cert));
        when(sshSigner.generateCertificate(null, sshRequest, sshCertRecord, "user", null)).thenReturn(sshCertificates);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_USER, null)).thenReturn("ssh-user");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertTrue(instanceManager.generateSSHIdentity(null, identity, null, sshCsr,
                null, sshCertRecord, "user", true, Collections.emptySet(), null));
        assertEquals(identity.getSshCertificate(), "ssh-cert");
        assertEquals(identity.getSshCertificateSigner(), "ssh-user");
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityValidPrincipals() throws IOException, ServerResourceException {
        Path path = Paths.get("src/test/resources/sshhost_valid_sample.csr");
        String sshCsr = new String(Files.readAllBytes(path));

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        SSHCertificates certs = new SSHCertificates();
        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("ssh-cert");
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setPrincipals("127.0.0.1");
        sshCertRecord.setService("athenz.service");
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        final SSHCertificates sshCertificates = certs.setCertificates(Collections.singletonList(cert));
        when(sshSigner.generateCertificate(null, sshRequest, sshCertRecord, "host", null)).thenReturn(sshCertificates);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");

        // set up the hostname resolver for our request
        String hostname = "host1.athenz.cloud";
        List<String> cnames = new ArrayList<>();
        cnames.add("cname.athenz.info");
        cnames.add("vip.athenz.info");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostCnameList(sshCertRecord.getService(), hostname,
                cnames, CertType.SSH_HOST)).thenReturn(true);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        boolean result = instanceManager.generateSSHIdentity(null, identity, hostname, sshCsr,
                null, sshCertRecord, "host", true, Collections.emptySet(), null);
        assertTrue(result);
        assertEquals(identity.getSshCertificate(), "ssh-cert");
        assertEquals(identity.getSshCertificateSigner(), "ssh-host");
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityInalidPrincipals() throws IOException, ServerResourceException {
        Path path = Paths.get("src/test/resources/sshhost_valid_sample.csr");
        String sshCsr = new String(Files.readAllBytes(path));

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCsr(sshCsr);
        SSHCertificates certs = new SSHCertificates();
        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("ssh-cert");
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        final SSHCertificates sshCertificates = certs.setCertificates(Collections.singletonList(cert));
        when(sshSigner.generateCertificate(null, sshRequest, null, "host", null)).thenReturn(sshCertificates);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");

        // set up the hostname resolver for our request
        String hostname = "host1.athenz.cloud";
        List<String> cnames = new ArrayList<>();
        cnames.add("cname.athenz.info");
        cnames.add("vip.athenz.info");

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setService("athenz.examples.httpd");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostCnameList(sshCertRecord.getService(), hostname,
                cnames, CertType.SSH_HOST)).thenReturn(false);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        boolean result = instanceManager.generateSSHIdentity(null, identity, hostname, sshCsr,
                null, new SSHCertRecord(), "host", true, Collections.emptySet(), null);
        assertFalse(result);
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityCertRequestValidPrincipals() throws ServerResourceException {

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCertRequestData(new SSHCertRequestData()
                .setPrincipals(Arrays.asList("host1.athenz.cloud", "cname.athenz.info", "vip.athenz.info", "10.1.2.3"))
                .setPublicKey("sample public key"));
        sshRequest.setCertRequestMeta(new SSHCertRequestMeta()
                .setKeyIdPrincipals(Arrays.asList("service.domain.athenz.cloud", "host1.athenz.cloud",
                        "cname.athenz.info", "vip.athenz.info", "10.1.2.3"))
                .setCertType("host")
                .setTransId("123456")
                .setOrigin("10.1.2.3"));

        SSHCertificates certs = new SSHCertificates();
        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("ssh-cert");
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setPrincipals("127.0.0.1");
        sshCertRecord.setService("athenz.service");
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        final SSHCertificates sshCertificates = certs.setCertificates(Collections.singletonList(cert));
        when(sshSigner.generateCertificate(null, sshRequest, sshCertRecord, "host", null)).thenReturn(sshCertificates);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");

        // set up the hostname resolver for our request
        String hostname = "host1.athenz.cloud";
        List<String> cnames = new ArrayList<>();
        cnames.add("cname.athenz.info");
        cnames.add("vip.athenz.info");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostCnameList(sshCertRecord.getService(), hostname, cnames,
                CertType.SSH_HOST)).thenReturn(true);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertTrue(instanceManager.generateSSHIdentity(null, identity, hostname, null,
                sshRequest, sshCertRecord, "host", true, Collections.emptySet(), null));
        assertEquals(identity.getSshCertificate(), "ssh-cert");
        assertEquals(identity.getSshCertificateSigner(), "ssh-host");
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityCertRequestNoHostname() throws ServerResourceException {

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCertRequestData(new SSHCertRequestData()
                .setPrincipals(Arrays.asList("host1.athenz.cloud", "cname.athenz.info", "vip.athenz.info", "10.1.2.3"))
                .setPublicKey("sample public key"));
        sshRequest.setCertRequestMeta(new SSHCertRequestMeta()
                .setKeyIdPrincipals(Arrays.asList("service.domain.athenz.cloud", "host1.athenz.cloud",
                        "cname.athenz.info", "vip.athenz.info", "10.1.2.3"))
                .setCertType("host")
                .setTransId("123456")
                .setOrigin("10.1.2.3"));

        SSHCertificates certs = new SSHCertificates();
        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("ssh-cert");
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setPrincipals("127.0.0.1");
        sshCertRecord.setService("athenz.service");
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        final SSHCertificates sshCertificates = certs.setCertificates(Collections.singletonList(cert));
        when(sshSigner.generateCertificate(null, sshRequest, sshCertRecord, "host", null)).thenReturn(sshCertificates);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        List<String> apiList = Arrays.asList("host1.athenz.cloud", "cname.athenz.info", "vip.athenz.info");
        when(hostnameResolver.isValidHostCnameList("athenz.service", null, apiList, CertType.SSH_HOST))
                .thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertTrue(instanceManager.generateSSHIdentity(null, identity, null, null,
                sshRequest, sshCertRecord, "host", true, Collections.emptySet(), null));
        assertEquals(identity.getSshCertificate(), "ssh-cert");
        assertEquals(identity.getSshCertificateSigner(), "ssh-host");
        instanceManager.shutdown();
    }

    @Test
    public void testGenerateSshIdentityCertRequestInValidPrincipals() throws ServerResourceException {

        SSHSigner sshSigner = Mockito.mock(com.yahoo.athenz.common.server.ssh.SSHSigner.class);
        SSHCertRequest sshRequest = new SSHCertRequest();
        sshRequest.setCertRequestData(new SSHCertRequestData()
                .setPrincipals(Arrays.asList("host1.athenz.cloud", "cname.athenz.info", "vip.athenz.info", "10.1.2.3"))
                .setPublicKey("sample public key"));
        sshRequest.setCertRequestMeta(new SSHCertRequestMeta()
                .setKeyIdPrincipals(Arrays.asList("service.domain.athenz.cloud", "host1.athenz.cloud",
                        "cname.athenz.info", "vip.athenz.info", "10.1.2.3"))
                .setCertType("host")
                .setTransId("123456")
                .setOrigin("10.1.2.3"));

        SSHCertificates certs = new SSHCertificates();
        SSHCertificate cert = new SSHCertificate();
        cert.setCertificate("ssh-cert");
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setPrincipals("127.0.0.1");
        sshCertRecord.setService("athenz.service");
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.service");
        final SSHCertificates sshCertificates = certs.setCertificates(Collections.singletonList(cert));
        when(sshSigner.generateCertificate(null, sshRequest, sshCertRecord, "host", null)).thenReturn(sshCertificates);
        when(sshSigner.getSignerCertificate(ZTSConsts.ZTS_SSH_HOST, null)).thenReturn("ssh-host");

        // set up the hostname resolver for our request
        String hostname = "host1.athenz.cloud";
        List<String> cnames = new ArrayList<>();
        cnames.add("cname.athenz.info");
        cnames.add("vip.athenz.info");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostCnameList(sshCertRecord.getService(), hostname, cnames,
                CertType.SSH_HOST)).thenReturn(false);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));
        instanceManager.setSSHSigner(sshSigner);

        assertFalse(instanceManager.generateSSHIdentity(null, identity, hostname, null,
                sshRequest, sshCertRecord, "host", true, Collections.emptySet(), null));
        instanceManager.shutdown();
    }

    @Test
    public void testValidPrincipalsBadCsr() {
        // set up the hostname resolver for our request
        String hostname = "host1.athenz.cloud";
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null,
                hostnameResolver, new DynamicConfigBoolean(true));
        SSHSigner signer = Mockito.mock(SSHSigner.class);
        instanceManager.setSSHSigner(signer);

        String sshCsr = "{\"pubkey\":\"key\",\"certtype\":\"host\"";
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.test");
        boolean result = instanceManager.generateSSHIdentity(null, identity, hostname,
                sshCsr, null, new SSHCertRecord(), ZTSConsts.ZTS_SSH_HOST, true, Collections.emptySet(), null);
        assertFalse(result);
    }

    @Test
    public void testValidPrincipalsNoXPrincipals() throws IOException {
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setService("athenz.examples.httpd");

        String sshCsr = "{\"pubkey\":\"key\",\"certtype\":\"host\"}";
        ObjectMapper objectMapper = new ObjectMapper();

        boolean result = instanceManager.validPrincipals("host1.athenz.cloud", sshCertRecord,
                objectMapper.readValue(sshCsr, SshHostCsr.class), Collections.emptySet());
        assertTrue(result);

        result = instanceManager.validPrincipals("host1.athenz.cloud", sshCertRecord,
                objectMapper.readValue("{}", SshHostCsr.class), Collections.emptySet());
        assertTrue(result);
        instanceManager.shutdown();
    }

    @Test
    public void testValidPrincipalsInvalidHostname() throws IOException {
        Path path = Paths.get("src/test/resources/sshhost_valid_sample.csr");
        String sshCsr = new String(Files.readAllBytes(path));
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setService("athenz.examples.httpd");

        // set up the hostname resolver for our request
        String hostname = "host1.athenz.cloud";
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(false);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));

        ObjectMapper objectMapper = new ObjectMapper();
        boolean result = instanceManager.validPrincipals("host1.athenz.cloud", sshCertRecord,
                objectMapper.readValue(sshCsr, SshHostCsr.class), Collections.emptySet());
        assertFalse(result);
        instanceManager.shutdown();
    }

    @Test
    public void testValidPrincipalsNoCnames() throws IOException {
        Path path = Paths.get("src/test/resources/sshhost_nocnames.csr");
        String sshCsr = new String(Files.readAllBytes(path));
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setService("athenz.examples.httpd");


        // set up the hostname resolver for our request
        String hostname = "host1.athenz.cloud";
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));

        ObjectMapper objectMapper = new ObjectMapper();
        boolean result = instanceManager.validPrincipals("host1.athenz.cloud", sshCertRecord,
                objectMapper.readValue(sshCsr, SshHostCsr.class), Collections.emptySet());

        assertTrue(result);
        instanceManager.shutdown();
    }

    @Test
    public void testValidPrincipalsHostnameAlone() {
        String hostname = "host1.athenz.cloud";
        SshHostCsr sshHostCsr = new SshHostCsr();
        sshHostCsr.setXPrincipals(new String[]{hostname});
        sshHostCsr.setPrincipals(new String[]{"service.domain.athenz.cloud", hostname});

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setService("athenz.examples.httpd");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));

        boolean result = instanceManager.validPrincipals(hostname, sshCertRecord, sshHostCsr, Collections.emptySet());
        assertTrue(result);
        instanceManager.shutdown();
    }

    @Test
    public void testValidPrincipalsIpAlone() {
        String hostname = "host1.athenz.cloud";
        SshHostCsr sshHostCsr = new SshHostCsr();
        sshHostCsr.setXPrincipals(new String[]{"10.1.2.3"});
        sshHostCsr.setPrincipals(new String[]{"service.domain.athenz.cloud", "10.1.2.3"});

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setService("athenz.examples.httpd");

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));

        boolean result = instanceManager.validPrincipals(hostname, sshCertRecord, sshHostCsr, Collections.emptySet());
        assertTrue(result);
        instanceManager.shutdown();
    }

    @Test
    public void testValidPrincipalsSSHRequestNulls() {

        final String hostname = "host1.athenz.cloud";
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setService("athenz.examples.httpd");

        SSHCertRequest sshCertRequest = new SSHCertRequest();
        assertTrue(instanceManager.validPrincipals(hostname, sshCertRecord, sshCertRequest, Collections.emptySet()));

        sshCertRequest.setCertRequestData(new SSHCertRequestData());
        sshCertRequest.setCertRequestMeta(null);
        assertTrue(instanceManager.validPrincipals(hostname, sshCertRecord, sshCertRequest, Collections.emptySet()));

        sshCertRequest.setCertRequestData(null);
        sshCertRequest.setCertRequestMeta(new SSHCertRequestMeta());
        assertTrue(instanceManager.validPrincipals(hostname, sshCertRecord, sshCertRequest, Collections.emptySet()));

        // null principals returns true

        sshCertRequest.setCertRequestData(new SSHCertRequestData());
        sshCertRequest.setCertRequestMeta(new SSHCertRequestMeta());
        assertTrue(instanceManager.validPrincipals(hostname, sshCertRecord, sshCertRequest, Collections.emptySet()));

        // empty principals list return true

        sshCertRequest.setCertRequestData(new SSHCertRequestData().setPrincipals(Collections.emptyList()));
        assertTrue(instanceManager.validPrincipals(hostname, sshCertRecord, sshCertRequest, Collections.emptySet()));

        instanceManager.shutdown();
    }

    @Test
    public void testValidateSSHHostnamesResolverTests() {

        // without resolver we get a failure

        List<String> principals = new ArrayList<>();
        principals.add("127.0.0.1");
        principals.add("cname.athenz.io");

        SSHCertRecord record = new SSHCertRecord();
        record.setService("athenz.api");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        assertFalse(instanceManager.validateSSHHostnames("host1.athenz.io", principals, record,
                Collections.emptySet(), false));
        instanceManager.shutdown();

        // now test with resolver

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostname(anyString())).thenReturn(true);
        when(hostnameResolver.isValidHostCnameList("athenz.api", "host1.athenz.io",
                Collections.singletonList("cname.athenz.io"), CertType.SSH_HOST)).thenReturn(true);

        instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));
        assertTrue(instanceManager.validateSSHHostnames("host1.athenz.io", principals, record,
                Collections.emptySet(), false));
        instanceManager.shutdown();

        // now test with attested host cert principals

        principals.add("compute.123456789000");
        principals.add("my-vm");
        principals.add("my-vm.c.my-gcp-project.internal");

        hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostname(anyString())).thenReturn(true);
        when(hostnameResolver.isValidHostCnameList("athenz.api", "host1.athenz.io",
                Collections.singletonList("cname.athenz.io"), CertType.SSH_HOST)).thenReturn(true);

        Set<String> principalSet = new HashSet<>(Arrays.asList("compute.123456789000", "my-vm",
                "my-vm.c.my-gcp-project.internal"));
        instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));
        assertTrue(instanceManager.validateSSHHostnames("host1.athenz.io", principals, record,
                principalSet, false));
        instanceManager.shutdown();

        // now test with invalid host cert principals

        hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostname(anyString())).thenReturn(true);
        when(hostnameResolver.isValidHostCnameList("athenz.api", "host1.athenz.io",
                Collections.singletonList("cname.athenz.io"), CertType.SSH_HOST)).thenReturn(true);

        instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));
        principalSet = new HashSet<>(Arrays.asList("my-vm", "my-vm.c.my-gcp-project.internal"));
        assertFalse(instanceManager.validateSSHHostnames("host1.athenz.io", principals, record,
                principalSet, false));
        instanceManager.shutdown();
    }

    @Test
    public void testValidPrincipalsSSHRequest() {

        final String hostname = "host1.athenz.cloud";
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver, new DynamicConfigBoolean(true));

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setService("athenz.examples.httpd");

        SSHCertRequest sshCertRequest = new SSHCertRequest();
        sshCertRequest.setCertRequestData(new SSHCertRequestData().setPrincipals(
                Collections.singletonList("host1.athenz.cloud")));
        sshCertRequest.setCertRequestMeta(new SSHCertRequestMeta());
        assertTrue(instanceManager.validPrincipals(hostname, sshCertRecord, sshCertRequest, Collections.emptySet()));

        instanceManager.shutdown();
    }

    @Test
    public void testVerifyIPAddressAccessEmptyList() {

        // we're going to set the filename to an invalid one, so we don't load any data

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME, "invalid-file");
        System.clearProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);
        
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
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

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME);
    }
    
    @Test
    public void testVerifyIPAddressAccessSpecifiedList() {
        
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME,
                "src/test/resources/cert_refresh_ipblocks.txt");
        System.setProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME,
                "src/test/resources/instance_cert_ipblocks.txt");
        
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
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
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
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
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
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
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Provider Allowed IP Blocks"));
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_INSTANCE_CERT_IP_FNAME);
    }

    @Test
    public void testLoadAllowedIPAddresses() {
        
        List<IPBlock> ipBlocks = new ArrayList<>();

        // empty or null filename returns success

        assertTrue(InstanceCertManager.loadAllowedIPAddresses(ipBlocks, null));
        assertTrue(InstanceCertManager.loadAllowedIPAddresses(ipBlocks, ""));

        // file does not exist returns failure
        
        assertFalse(InstanceCertManager.loadAllowedIPAddresses(ipBlocks, "some-invalid-filename"));

        // invalid json returns failure
        
        assertFalse(InstanceCertManager.loadAllowedIPAddresses(ipBlocks, "src/test/resources/invalid_ipblocks.txt"));
        
        // valid json with empty set returns failure
        
        assertFalse(InstanceCertManager.loadAllowedIPAddresses(ipBlocks, "src/test/resources/empty_ipblocks.txt"));
    }

    @Test
    public void testLoadCAX509CertificateBundle() {

        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertSigner(null);

        assertNull(instance.loadCertificateBundle("unknown_propery"));

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "");
        assertNull(instance.loadCertificateBundle(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME));

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "non-existent-file");
        try {
            instance.loadCertificateBundle(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "src/test/resources/valid_cn_x509.cert");
        assertNotNull(instance.loadCertificateBundle(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME));
        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
        instance.shutdown();
    }

    @Test
    public void testGetSSHCertificates() throws ServerResourceException {

        InstanceCertManager instanceCertManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceCertManager.setSSHSigner(null);

        assertNull(instanceCertManager.generateSSHCertificates(null, null, null));

        SSHSigner signer = Mockito.mock(SSHSigner.class);

        Principal principal = Mockito.mock(Principal.class);
        SSHCertRequest certRequest = new SSHCertRequest();
        certRequest.setCertRequestMeta(new SSHCertRequestMeta());
        SSHCertificates certs = new SSHCertificates();
        when(signer.generateCertificate(principal, certRequest, null, null, null)).thenReturn(certs);
        instanceCertManager.setSSHSigner(signer);

        assertEquals(certs, instanceCertManager.generateSSHCertificates(principal, certRequest, null));
        instanceCertManager.shutdown();
    }

    @Test
    public void testGetSSHCertificatesException() throws ServerResourceException {

        InstanceCertManager instanceCertManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instanceCertManager.setSSHSigner(null);

        SSHSigner signer = Mockito.mock(SSHSigner.class);
        Principal principal = Mockito.mock(Principal.class);
        SSHCertRequest certRequest = new SSHCertRequest();
        certRequest.setCertRequestMeta(new SSHCertRequestMeta());
        SSHCertificates certs = new SSHCertificates();
        when(signer.generateCertificate(principal, certRequest, null, null, null))
                .thenThrow(new ServerResourceException(400, "Invalid request"));
        instanceCertManager.setSSHSigner(signer);

        try {
            instanceCertManager.generateSSHCertificates(principal, certRequest, null);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid request"));
        }
        instanceCertManager.shutdown();
    }

    @Test
    public void testInvalidCertSignerClass() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS, "invalid");
        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
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
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
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
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid cert record store factory class"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_RECORD_STORE_FACTORY_CLASS);
    }

    @Test
    public void testInvalidSSHRecordStoreClass() {

        System.setProperty(ZTSConsts.ZTS_PROP_SSH_RECORD_STORE_FACTORY_CLASS, "invalid");
        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid ssh record store factory class"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_RECORD_STORE_FACTORY_CLASS);
    }

    @Test
    public void testEmptySSHRecordStoreClass() {

        System.setProperty(ZTSConsts.ZTS_PROP_SSH_RECORD_STORE_FACTORY_CLASS, "");
        InstanceCertManager manager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));

        // no exceptions here since with empty factory class
        // we're not going to process any ssh certs

        assertNull(manager.generateSSHCertificates(null, null, null));
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_RECORD_STORE_FACTORY_CLASS);
    }

    @Test
    public void testInitWithIncorrectCABundle() {

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME, "invalid-file");
        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
            assertTrue(ex.getMessage().contains("Unable to load Certificate bundle from: invalid-file"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
    }

    @Test
    public void testInitWithMockSSHSigner() {

        System.setProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS, "com.yahoo.athenz.zts.cert.impl.MockSSHSignerFactory");
        InstanceCertManager instanceCertManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        assertNotNull(instanceCertManager);
        instanceCertManager.shutdown();
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS);
    }

    @Test
    public void testGetSSHCertificateSignerNoStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instance.setCertSigner(null);

        assertNull(instance.getSSHCertificateSigner("host", null));
        instance.shutdown();
    }

    @Test
    public void testGetSSHCertificateSignerMockStore() {
        System.setProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS, "com.yahoo.athenz.zts.cert.impl.MockSSHSignerFactory");
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));

        assertNull(instance.getSSHCertificateSigner("host", null));
        assertNull(instance.getSSHCertificateSigner("user", null));
        instance.shutdown();
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_SIGNER_FACTORY_CLASS);
    }

    @Test
    public void testExpiredX509CertRecordCleaner() throws ServerResourceException {

        CertRecordStore store = Mockito.mock(CertRecordStore.class);
        when(store.getConnection()).thenThrow(new RuntimeException("invalid connection"));

        InstanceCertManager.ExpiredX509CertRecordCleaner cleaner =
                new InstanceCertManager.ExpiredX509CertRecordCleaner(store, 100, 0, new DynamicConfigBoolean(false));

        // make sure no exceptions are thrown

        cleaner.run();
    }

    @Test
    public void testExpiredSSHCertRecordCleaner() {

        FileSSHRecordStoreFactory factory = new FileSSHRecordStoreFactory();
        SSHRecordStore store = factory.create(null);
        assertNotNull(store);

        InstanceCertManager.ExpiredSSHCertRecordCleaner cleaner =
                new InstanceCertManager.ExpiredSSHCertRecordCleaner(store, 100, 0, new DynamicConfigBoolean(false));

        // make sure no exceptions are thrown

        cleaner.run();
    }

    @Test
    public void testExpiredSSHCertRecordCleanerException() throws ServerResourceException {

        SSHRecordStore store = Mockito.mock(SSHRecordStore.class);
        when(store.getConnection()).thenThrow(new RuntimeException("invalid connection"));

        InstanceCertManager.ExpiredSSHCertRecordCleaner cleaner =
                new InstanceCertManager.ExpiredSSHCertRecordCleaner(store, 100, 0, new DynamicConfigBoolean(false));

        // make sure no exceptions are thrown

        cleaner.run();
    }

    @Test
    public void testLogNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertStore(null);

        // passing all null which should typically return a NPE
        // however, with null cert store, we should never call log
        instance.logX509Cert(null, null, null, null, null);
        instance.shutdown();
    }

    @Test
    public void loadCertificateAuthorityBundlesInvalidFile() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME, "invalid-file");

        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Certificate Authority Bundles"));
        }

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME, "src/test/resources/ca-bundle-file-invalid.json");

        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Certificate Authority Bundles"));
        }

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME, "src/test/resources/ca-bundle-file-missing-filename.json");

        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Certificate Authority Bundles"));
        }

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME, "src/test/resources/ca-bundle-file-empty.json");

        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Certificate Authority Bundles"));
        }

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME, "src/test/resources/ca-bundle-file-invalid-x509.json");

        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Certificate Authority Bundles"));
        }

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME, "src/test/resources/ca-bundle-file-invalid-ssh.json");

        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to load Certificate Authority Bundles"));
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME);
    }

    @Test
    public void loadCertificateAuthorityBundles() throws IOException {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME, "src/test/resources/ca-bundle-file.json");

        InstanceCertManager certManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));

        // test our valid bundles. athenz and system should present same data
        // since one just includes comments

        CertificateAuthorityBundle bundleAthenz = certManager.getCertificateAuthorityBundle("athenz");
        assertNotNull(bundleAthenz);

        assertEquals(bundleAthenz.getName(), "athenz");
        final String athenzData = bundleAthenz.getCerts();

        CertificateAuthorityBundle bundleSystem = certManager.getCertificateAuthorityBundle("system");
        assertNotNull(bundleSystem);

        assertEquals(bundleSystem.getName(), "system");
        final String systemData = bundleSystem.getCerts();

        assertEquals(athenzData, systemData);

        // compare the contents with the actual file contents

        File caFile = new File("src/test/resources/x509_certs_no_comments.pem");
        byte[] data = Files.readAllBytes(Paths.get(caFile.toURI()));
        assertEquals(athenzData, new String(data));

        CertificateAuthorityBundle bundleSsh = certManager.getCertificateAuthorityBundle("ssh");
        assertNotNull(bundleSsh);

        assertEquals(bundleSsh.getName(), "ssh");
        final String sshData = bundleSsh.getCerts();
        assertEquals(sshData, "ssh-certificate-authority-keys");

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME);
    }

    @Test
    void testGetUnrefreshedNotifications() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);

        X509CertRecord record = new X509CertRecord();
        record.setHostName("testHost");
        List<X509CertRecord> x509CertRecords = Collections.singletonList(record);
        String lastNotifiedServer = "server";
        String provider = "provider";
        when(certConnection.updateUnrefreshedCertificatesNotificationTimestamp(
                eq(lastNotifiedServer),
                anyLong(), eq(provider)))
                .thenReturn(x509CertRecords);

        instance.setCertStore(certStore);

        List<X509CertRecord> unrefreshedCertificateNotifications = instance.getUnrefreshedCertsNotifications(lastNotifiedServer, provider);
        assertEquals(unrefreshedCertificateNotifications.get(0).getHostName(), "testHost");

        instance.shutdown();
    }

    @Test
    public void testNoCertStoreUnrefreshedCerts() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instance.setCertStore(null);
        List<X509CertRecord> unrefreshedCertificateNotifications = instance.getUnrefreshedCertsNotifications(
                "localhost",
                "provdider");
        assertEquals(unrefreshedCertificateNotifications, new ArrayList<>());
    }

    @Test
    public void testUpdateSSHCertRecordNullStore() {

        // without a store we're going to get false

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setSSHSigner(null);
        instance.setSSHStore(null);

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        assertFalse(instance.updateSSHCertRecord(sshCertRecord, true));
        assertFalse(instance.updateSSHCertRecord(null, true));

        instance.shutdown();
    }

    @Test
    public void testUpdateSSHCertRecord() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setSSHSigner(null);

        SSHRecordStore certStore = Mockito.mock(SSHRecordStore.class);
        SSHRecordStoreConnection certConnection = Mockito.mock(SSHRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);
        instance.setSSHStore(certStore);

        // when record is null, we get success all the time

        assertTrue(instance.updateSSHCertRecord(null, true));

        // now let's set our mock object to return success
        // and pass a real object

        when(certConnection.updateSSHCertRecord(ArgumentMatchers.isA(SSHCertRecord.class))).thenReturn(true);
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        assertTrue(instance.updateSSHCertRecord(sshCertRecord, true));

        instance.shutdown();
    }

    @Test
    public void testInsertSSHCertRecord() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setSSHSigner(null);

        SSHRecordStore certStore = Mockito.mock(SSHRecordStore.class);
        SSHRecordStoreConnection certConnection = Mockito.mock(SSHRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);

        when(certConnection.insertSSHCertRecord(ArgumentMatchers.isA(SSHCertRecord.class))).thenReturn(true);
        instance.setSSHStore(certStore);

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        assertTrue(instance.updateSSHCertRecord(sshCertRecord, false));
        instance.shutdown();
    }

    @Test
    public void testUpdateSSHCertRecordException() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));

        SSHRecordStore certStore = Mockito.mock(SSHRecordStore.class);
        SSHRecordStoreConnection certConnection = Mockito.mock(SSHRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);

        when(certConnection.updateSSHCertRecord(any())).thenThrow(new RuntimeException("Fail to update"));

        instance.setSSHStore(certStore);

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        assertFalse(instance.updateSSHCertRecord(sshCertRecord, true));
        instance.shutdown();
    }

    @Test
    public void testUpdateSSHCertRecordNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setSSHSigner(null);

        instance.setSSHStore(null);
        SSHCertRecord sshCertRecord = new SSHCertRecord();
        assertFalse(instance.updateSSHCertRecord(sshCertRecord, true));
        instance.shutdown();
    }

    @Test
    public void testUpdateSSHHostPrincipals() {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));

        SSHCertRecord record = new SSHCertRecord();
        instance.updateSSHHostPrincipals((SshHostCsr) null, record);
        assertEquals(record.getPrincipals(), "127.0.0.1");

        // reset and test csr with no principals

        record.setPrincipals(null);
        SshHostCsr csr = new SshHostCsr();
        instance.updateSSHHostPrincipals(csr, record);
        assertEquals(record.getPrincipals(), "127.0.0.1");

        // reset and test csr with principals and xprincipals

        record.setPrincipals(null);

        String[] principals = new String[1];
        principals[0] = "principal1";
        csr.setPrincipals(principals);

        String[] xprincipals = new String[2];
        xprincipals[0] = "xprincipal1";
        xprincipals[1] = "xprincipal2";
        csr.setXPrincipals(xprincipals);

        instance.updateSSHHostPrincipals(csr, record);
        Set<String> result = new HashSet<>(Arrays.asList(record.getPrincipals().split(",")));
        assertEquals(result.size(), 3);
        assertTrue(result.contains("principal1"));
        assertTrue(result.contains("xprincipal1"));
        assertTrue(result.contains("xprincipal2"));
    }

    @Test
    public void testUpdateSSHHostPrincipalsDuplicateValues() {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));

        SshHostCsr csr = new SshHostCsr();

        String[] principals = new String[3];
        principals[0] = "principal1";
        principals[1] = "principal2";
        principals[2] = "principal4";
        csr.setPrincipals(principals);

        String[] xprincipals = new String[3];
        xprincipals[0] = "principal1";
        xprincipals[1] = "principal2";
        xprincipals[2] = "principal5";
        csr.setXPrincipals(xprincipals);

        SSHCertRecord record = new SSHCertRecord();
        instance.updateSSHHostPrincipals(csr, record);
        Set<String> result = new HashSet<>(Arrays.asList(record.getPrincipals().split(",")));
        assertEquals(result.size(), 4);
        assertTrue(result.contains("principal1"));
        assertTrue(result.contains("principal2"));
        assertTrue(result.contains("principal4"));
        assertTrue(result.contains("principal5"));
    }

    @Test
    public void testUpdateSSHHostPrincipalsNullValues() {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));

        SshHostCsr csr = new SshHostCsr();

        csr.setPrincipals(new String[0]);
        csr.setPrincipals(new String[0]);
        SSHCertRecord record = new SSHCertRecord();
        instance.updateSSHHostPrincipals(csr, record);
        assertEquals(record.getPrincipals(), "127.0.0.1");

        String[] principals = new String[3];
        principals[0] = "principal1";
        principals[1] = "principal2";
        principals[2] = "principal4";

        csr.setPrincipals(principals);
        csr.setXPrincipals(null);

        record = new SSHCertRecord();
        instance.updateSSHHostPrincipals(csr, record);
        Set<String> result = new HashSet<>(Arrays.asList(record.getPrincipals().split(",")));
        assertEquals(result.size(), 3);
        assertTrue(result.contains("principal1"));
        assertTrue(result.contains("principal2"));
        assertTrue(result.contains("principal4"));

        // now let's try with principals set to null

        csr.setPrincipals(null);
        csr.setXPrincipals(principals);

        record = new SSHCertRecord();
        instance.updateSSHHostPrincipals(csr, record);
        result = new HashSet<>(Arrays.asList(record.getPrincipals().split(",")));
        assertEquals(result.size(), 3);
        assertTrue(result.contains("principal1"));
        assertTrue(result.contains("principal2"));
        assertTrue(result.contains("principal4"));
    }

    @Test
    public void testUpdateSSHHostPrincipalWithCertRequest() {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));

        SSHCertRecord record = new SSHCertRecord();
        SSHCertRequest sshCertRequest = new SSHCertRequest();

        instance.updateSSHHostPrincipals(sshCertRequest, record);
        assertEquals(record.getPrincipals(), "127.0.0.1");

        // reset and test with meta set to null

        record.setPrincipals(null);
        sshCertRequest.setCertRequestData(new SSHCertRequestData());
        sshCertRequest.setCertRequestMeta(null);

        instance.updateSSHHostPrincipals(sshCertRequest, record);
        assertEquals(record.getPrincipals(), "127.0.0.1");

        // reset and test with data set to null

        record.setPrincipals(null);
        sshCertRequest.setCertRequestData(null);
        sshCertRequest.setCertRequestMeta(new SSHCertRequestMeta());

        instance.updateSSHHostPrincipals(sshCertRequest, record);
        assertEquals(record.getPrincipals(), "127.0.0.1");

        // reset and test csr with principals and xprincipals

        record.setPrincipals(null);
        sshCertRequest.setCertRequestData(new SSHCertRequestData()
                .setPrincipals(Arrays.asList("principal1", "principal2")));
        sshCertRequest.setCertRequestMeta(new SSHCertRequestMeta()
                .setKeyIdPrincipals(Arrays.asList("principal2", "principal3")));

        instance.updateSSHHostPrincipals(sshCertRequest, record);
        Set<String> result = new HashSet<>(Arrays.asList(record.getPrincipals().split(",")));
        assertEquals(result.size(), 3);
        assertTrue(result.contains("principal1"));
        assertTrue(result.contains("principal2"));
        assertTrue(result.contains("principal3"));
    }

    @Test
    public void getGenerateSSHCertificate() throws ServerResourceException {

        SSHSigner sshSigner = Mockito.mock(SSHSigner.class);
        Principal principal = Mockito.mock(Principal.class);

        SSHCertRequest certRequest = new SSHCertRequest();
        SSHCertRequestMeta meta = new SSHCertRequestMeta();
        meta.setInstanceId("id");
        meta.setAthenzService("athenz.api");
        meta.setCertType("host");
        certRequest.setCertRequestMeta(meta);

        SSHCertificates sshCertificates = new SSHCertificates();

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));

        // let's insert our ssh record first

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("id");
        certRecord.setService("athenz.api");
        certRecord.setPrincipals("127.0.0.1");
        instanceManager.updateSSHCertRecord(certRecord, false);

        // during the function call we'll add the principals
        // field so for mock we're going to remove that

        when(sshSigner.generateCertificate(any(), any(), any(), any(), any())).thenReturn(sshCertificates);
        instanceManager.setSSHSigner(sshSigner);

        assertEquals(instanceManager.generateSSHCertificates(principal, certRequest, null), sshCertificates);
        instanceManager.shutdown();
    }

    @Test
    public void testGetSSHCertRecordNullStore() {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setSSHStore(null);

        // when store is null, we get null all the time

        assertNull(instance.getSSHCertRecord(null, null));
        assertNull(instance.getSSHCertRecord("id", "athenz.api"));

        instance.shutdown();
    }

    @Test
    public void testeEnableCertStoreNotifications() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        boolean isEnabled = instance.enableCertStoreNotifications(null, null, null);
        assertFalse(isEnabled);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        when(certStore.enableNotifications(any(), any(), any())).thenReturn(true);
        instance.setCertStore(certStore);

        NotificationManager notificationManager = Mockito.mock(NotificationManager.class);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        isEnabled = instance.enableCertStoreNotifications(notificationManager, rolesProvider, "testServer");
        assertTrue(isEnabled);
    }

    @Test
    public void testEnableCertStoreNotificationsNoCertStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertStore(null);
        boolean isEnabled = instance.enableCertStoreNotifications(null, null, null);
        assertFalse(isEnabled);
    }

    @Test
    public void testEnableSSHStoreNotificationsNoSSHStore() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setSSHStore(null);
        boolean isEnabled = instance.enableSSHStoreNotifications(null, null, null);
        assertFalse(isEnabled);
    }
    @Test
    public void testGetWorkloadRecordNullStore() {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setWorkloadStore(null);

        // when store is null, we get null all the time
        assertTrue(instance.getWorkloadsByService(null, null).isEmpty());
        assertTrue(instance.getWorkloadsByService("id", "athenz.api").isEmpty());
        assertTrue(instance.getWorkloadsByIp(null).isEmpty());
        assertTrue(instance.getWorkloadsByIp("10.0.0.1").isEmpty());
        instance.shutdown();
    }

    @Test
    public void testInsertWorkloadRecord() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        WorkloadRecordStore store = Mockito.mock(WorkloadRecordStore.class);
        instance.setWorkloadStore(store);
        WorkloadRecordStoreConnection storeConn = Mockito.mock(WorkloadRecordStoreConnection.class);
        Mockito.when(store.getConnection()).thenReturn(storeConn);
        Mockito.when(storeConn.insertWorkloadRecord(any())).thenReturn(true);

        Date d = new Date();
        assertTrue(instance.insertWorkloadRecord(ZTSTestUtils.createWorkloadRecord(d, d,
                "aws", "i-123", "test-host1.corp.yahoo.com", "10.0.0.1", "athenz.api", d)));
        instance.shutdown();
    }

    @Test
    public void testUpdateWorkloadRecord() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        WorkloadRecordStore store = Mockito.mock(WorkloadRecordStore.class);
        instance.setWorkloadStore(store);
        WorkloadRecordStoreConnection storeConn = Mockito.mock(WorkloadRecordStoreConnection.class);
        Mockito.when(store.getConnection()).thenReturn(storeConn);
        Mockito.when(storeConn.updateWorkloadRecord(any())).thenReturn(true);

        Date d = new Date();
        assertTrue(instance.updateWorkloadRecord(ZTSTestUtils.createWorkloadRecord(d, d,
                "aws", "i-123", "test-host1.corp.yahoo.com", "10.0.0.1", "athenz.api", d)));

        Mockito.when(storeConn.updateWorkloadRecord(any())).thenReturn(false);
        Mockito.when(storeConn.insertWorkloadRecord(any())).thenReturn(true);

        assertTrue(instance.updateWorkloadRecord(ZTSTestUtils.createWorkloadRecord(d, d,
                "aws", "i-123", "test-host1.corp.yahoo.com", "10.0.0.1", "athenz.api", d)));

        instance.shutdown();
    }

    @Test
    public void testGetWorkloadsByService() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        WorkloadRecordStore store = Mockito.mock(WorkloadRecordStore.class);
        instance.setWorkloadStore(store);
        WorkloadRecordStoreConnection storeConn = Mockito.mock(WorkloadRecordStoreConnection.class);
        Mockito.when(store.getConnection()).thenReturn(storeConn);

        long currTime = System.currentTimeMillis();
        Date d = new Date(currTime);

        WorkloadRecord w1 = ZTSTestUtils.createWorkloadRecord(d, d,
                "aws", "i-123", "test-host1.corp.yahoo.com", "10.0.0.1", "athenz.api", d);

        WorkloadRecord w2 = ZTSTestUtils.createWorkloadRecord(d, d,
                "aws", "i-234", "test-host2.corp.yahoo.com", "10.0.0.2", "athenz.api", d);

        WorkloadRecord w3 = ZTSTestUtils.createWorkloadRecord(d, d,
                "aws", "i-234", "test-host2.corp.yahoo.com", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "athenz.api", d);

        List<WorkloadRecord> workloadRecordList = new ArrayList<>();
        workloadRecordList.add(w1);
        workloadRecordList.add(w2);
        workloadRecordList.add(w3);
        Mockito.when(storeConn.getWorkloadRecordsByService(any(), any())).thenReturn(workloadRecordList);

        List<Workload> workloadList = instance.getWorkloadsByService("athenz", "api");
        assertNotNull(workloadList);
        assertEquals(workloadList.size(), 2);

        instance.shutdown();
    }

    @Test
    public void testGetWorkloadsByIp() throws ServerResourceException {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        WorkloadRecordStore store = Mockito.mock(WorkloadRecordStore.class);
        instance.setWorkloadStore(store);
        WorkloadRecordStoreConnection storeConn = Mockito.mock(WorkloadRecordStoreConnection.class);
        Mockito.when(store.getConnection()).thenReturn(storeConn);

        long currTime = System.currentTimeMillis();
        Date d = new Date(currTime);

        WorkloadRecord w1 = ZTSTestUtils.createWorkloadRecord(d, d,
                "aws", "i-123", "test-host1.corp.yahoo.com", "10.0.0.1", "athenz.api", d);

        WorkloadRecord w5 = ZTSTestUtils.createWorkloadRecord(d, d,
                "aws", "i-123", "test-host2.corp.yahoo.com", "10.0.0.1", "athenz.secondapi", d);

        List<WorkloadRecord> workloadRecordList = new ArrayList<>();
        workloadRecordList.add(w1);
        workloadRecordList.add(w5);
        Mockito.when(storeConn.getWorkloadRecordsByIp(any())).thenReturn(workloadRecordList);

        List<Workload> workloadList = instance.getWorkloadsByIp("10.0.0.1");
        assertNotNull(workloadList);
        assertEquals(workloadList.size(), 2);

        List<String> expectedServices = workloadList.stream().map(Workload::getServiceName).collect(Collectors.toList());
        assertTrue(expectedServices.contains("api"));
        assertTrue(expectedServices.contains("secondapi"));
        instance.shutdown();
    }

    @Test
    public void nullWorkloadsStoreTest() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setWorkloadStore(null);
        WorkloadRecord wlr = new WorkloadRecord();
        assertFalse(instance.insertWorkloadRecord(wlr));
        assertFalse(instance.updateWorkloadRecord(wlr));
        instance.shutdown();
    }

    @Test
    public void workloadsStoreInitializationTest() {
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_RECORD_STORE_FACTORY_CLASS, "invalid.class");
        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
            fail();
        } catch(Exception ignored) {
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_RECORD_STORE_FACTORY_CLASS);
    }

    @Test
    public void testValidPrincipalsSSHRequestInvalidIP() {

        final String hostname = "host1.athenz.cloud";
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        when(hostnameResolver.isValidHostname(hostname)).thenReturn(true);

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, hostnameResolver,
                new DynamicConfigBoolean(true));

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        sshCertRecord.setService("athenz.examples.httpd");

        assertFalse(instanceManager.validateSSHHostnames(hostname, Arrays.asList("host1.athenz.cloud", "10.10.10.10"),
                sshCertRecord, Collections.emptySet(), true));

        assertTrue(instanceManager.validateSSHHostnames(hostname, Arrays.asList("host1.athenz.cloud", "10.10.10.10"),
                sshCertRecord, Collections.emptySet(), false));

        assertTrue(instanceManager.validateSSHHostnames(hostname, Arrays.asList("host1.athenz.cloud", "10.10.10.10"),
                sshCertRecord, Collections.singleton("10.10.10.10"), true));

        instanceManager.shutdown();
    }

    @Test
    public void testHasProviderChangeThresholdNotExceeded() {

        ConcurrentHashMap<String, List<IPBlock>> providerCertIPBlocks = new ConcurrentHashMap<>();
        List<IPBlock> ipBlocks = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            ipBlocks.add(new IPBlock("192.1.0." + i + "/32"));
        }
        providerCertIPBlocks.put("provider1", ipBlocks);

        // if the provider doesn't exist, the return is always true

        assertTrue(InstanceCertManager.hasProviderChangeThresholdNotExceeded(providerCertIPBlocks, "provider2", 0));
        assertTrue(InstanceCertManager.hasProviderChangeThresholdNotExceeded(providerCertIPBlocks, "provider2", 1));

        // our provider 1 has 10 ip blocks, so we should get true
        // for any value more than 10 or for 8 and 9. For 7
        // we should get false since that's more than 25% change

        assertTrue(InstanceCertManager.hasProviderChangeThresholdNotExceeded(providerCertIPBlocks, "provider1", 8));
        assertTrue(InstanceCertManager.hasProviderChangeThresholdNotExceeded(providerCertIPBlocks, "provider1", 9));
        assertTrue(InstanceCertManager.hasProviderChangeThresholdNotExceeded(providerCertIPBlocks, "provider1", 10));
        assertTrue(InstanceCertManager.hasProviderChangeThresholdNotExceeded(providerCertIPBlocks, "provider1", 11));
        assertTrue(InstanceCertManager.hasProviderChangeThresholdNotExceeded(providerCertIPBlocks, "provider1", 12));

        assertFalse(InstanceCertManager.hasProviderChangeThresholdNotExceeded(providerCertIPBlocks, "provider1", 7));
        assertFalse(InstanceCertManager.hasProviderChangeThresholdNotExceeded(providerCertIPBlocks, "provider1", 6));
    }

    @Test
    public void testRefreshAllowedIPAddresses() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME, "src/test/resources/cert_refresh_ipblocks.txt");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null,
                new DynamicConfigBoolean(true));

        assertTrue(instanceManager.verifyCertRefreshIPAddress("10.1.3.25"));
        assertTrue(instanceManager.verifyCertRefreshIPAddress("10.0.0.1"));

        // make a copy of our current provider ip blocks

        ConcurrentHashMap<String, List<IPBlock>> instanceProviderCertIPBlocks =
                new ConcurrentHashMap<>(instanceManager.getInstanceCertIPBlocks());

        InstanceCertManager.RefreshAllowedIPAddresses refresher =
                new InstanceCertManager.RefreshAllowedIPAddresses(instanceProviderCertIPBlocks);

        // make sure no exceptions are thrown

        refresher.run();

        // now verify that the contents of the cert refresher haven't been changed

        assertEquals(instanceProviderCertIPBlocks.size(), instanceManager.getInstanceCertIPBlocks().size());
        assertEquals(instanceProviderCertIPBlocks.get("zts-svc-token-provider").size(),
                instanceManager.getInstanceCertIPBlocks().get("zts-svc-token-provider").size());

        List<IPBlock> certIPBlocks = instanceProviderCertIPBlocks.get("zts-svc-token-provider");
        assertTrue(instanceManager.verifyIPAddressAccess("10.1.3.25", certIPBlocks));
        assertTrue(instanceManager.verifyIPAddressAccess("10.0.0.1", certIPBlocks));

        // now let's update the cert refresh ip block setting and point to the updated
        // file which doesn't have the entry for the 10.1.x.x ip block

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME,
                "src/test/resources/cert_refresh_ipblocks_updated.txt");

        // make sure no exceptions are thrown

        refresher.run();

        // our records should have been updated

        int size = instanceManager.getInstanceCertIPBlocks().get("zts-svc-token-provider").size();
        assertEquals(instanceProviderCertIPBlocks.get("zts-svc-token-provider").size(), size - 1);

        certIPBlocks = instanceProviderCertIPBlocks.get("zts-svc-token-provider");
        assertFalse(instanceManager.verifyIPAddressAccess("10.1.3.25", certIPBlocks));
        assertTrue(instanceManager.verifyIPAddressAccess("10.0.0.1", certIPBlocks));

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME);
    }

    @Test
    public void testEnableSSHStoreNotifications() {

        SSHRecordStore store = Mockito.mock(SSHRecordStore.class);
        when(store.enableNotifications(any(), any(), any())).thenReturn(true);

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setSSHStore(store);

        assertTrue(instance.enableSSHStoreNotifications(null, null, null));
        instance.shutdown();
    }

    @Test
    public void testLogX509CertException() {

        CertRecordStore store = Mockito.mock(CertRecordStore.class);
        doThrow(new ResourceException(400)).when(store).log(any(), any(), any(), any(), any());

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));
        instance.setCertStore(store);

        // make sure no exceptions are thrown

        instance.logX509Cert(null, null, null, null, null);
        instance.shutdown();
    }

    @Test
    public void testGetSignerPrimaryKey() {
        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(true));

        assertEquals(instance.getSignerPrimaryKey("provider", "keyid1"), "keyid1");
        assertEquals(instance.getSignerPrimaryKey("", "keyid1"), "keyid1");
        assertEquals(instance.getSignerPrimaryKey(null, "keyid1"), "keyid1");

        assertEquals(instance.getSignerPrimaryKey("provider", ""), "provider");
        assertEquals(instance.getSignerPrimaryKey("provider", null), "provider");
        assertEquals(instance.getSignerPrimaryKey("", null), "default");
        assertEquals(instance.getSignerPrimaryKey("", ""), "default");

        instance.shutdown();
    }

    @Test
    public void testGetX509CertificateSignerPerProviderKey() throws ServerResourceException {

        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_FNAME);
        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_KEYID_FNAME, "key1:src/test/resources/ca-cert-1,key2:src/test/resources/ca-cert-2");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        CertSigner certSigner = Mockito.mock(com.yahoo.athenz.common.server.cert.CertSigner.class);
        when(certSigner.getCACertificate("aws", "key3")).thenReturn("ca-cert-3");
        instanceManager.setCertSigner(certSigner);

        // first two entries are coming from our configuration

        assertEquals(instanceManager.getX509CertificateSigner("aws", "key1"), "ca-cert-1");
        assertEquals(instanceManager.getX509CertificateSigner("aws", "key2"), "ca-cert-2");

        // the last one is coming from the provider

        assertEquals(instanceManager.getX509CertificateSigner("aws", "key3"), "ca-cert-3");

        // others return null

        assertNull(instanceManager.getX509CertificateSigner("aws", "key4"));

        instanceManager.shutdown();
        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_KEYID_FNAME);
    }

    @Test
    public void testGetSSHCertificateSignerPerProviderKey() throws ServerResourceException {

        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_USER_CA_CERT_FNAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_HOST_CA_CERT_FNAME);
        System.setProperty(ZTSConsts.ZTS_PROP_SSH_HOST_CA_CERT_KEYID_FNAME, "key1:src/test/resources/ca-cert-1");
        System.setProperty(ZTSConsts.ZTS_PROP_SSH_USER_CA_CERT_KEYID_FNAME, "key2:src/test/resources/ca-cert-2");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        SSHSigner sshSigner = Mockito.mock(SSHSigner.class);
        when(sshSigner.getSignerCertificate("host", "key3")).thenReturn("ca-cert-3");
        instanceManager.setSSHSigner(sshSigner);

        // first two entries are coming from our configuration

        assertEquals(instanceManager.getSSHCertificateSigner("host", "key1"), "ca-cert-1");
        assertEquals(instanceManager.getSSHCertificateSigner("user", "key2"), "ca-cert-2");

        // the last one is coming from the provider

        assertEquals(instanceManager.getSSHCertificateSigner("host", "key3"), "ca-cert-3");

        // all others return null

        assertNull(instanceManager.getSSHCertificateSigner("user", "key1"));
        assertNull(instanceManager.getSSHCertificateSigner("host", "key2"));
        assertNull(instanceManager.getSSHCertificateSigner("host", "key4"));

        instanceManager.shutdown();
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_HOST_CA_CERT_KEYID_FNAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_USER_CA_CERT_KEYID_FNAME);
    }

    @Test
    public void testGetX509CertificateSignerPerProviderKeyInvalidFile() {

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_KEYID_FNAME, "key1:invalid-file");
        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to load Certificate bundle from: invalid-file"));
        }

        System.setProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_KEYID_FNAME, "key1");
        try {
            new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid provider certificate configuration value: " +
                    ZTSConsts.ZTS_PROP_X509_CA_CERT_KEYID_FNAME + ": key1"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_X509_CA_CERT_KEYID_FNAME);
    }

    @Test
    public void testX509CertOperationFailures() throws ServerResourceException, IOException {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instance.setCertSigner(null);

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        when(certStore.getConnection()).thenReturn(certConnection);

        when(certConnection.getX509CertRecord(anyString(), anyString(), anyString()))
                .thenThrow(new ServerResourceException(400, "Invalid get request"));
        when(certConnection.updateX509CertRecord(any())).thenThrow(new ServerResourceException(400, "Invalid update request"));
        when(certConnection.insertX509CertRecord(any())).thenThrow(new ServerResourceException(400, "Invalid insert request"));
        when(certConnection.deleteX509CertRecord(anyString(), anyString(), anyString()))
                .thenThrow(new ServerResourceException(400, "Invalid delete request"));
        when(certConnection.updateUnrefreshedCertificatesNotificationTimestamp(anyString(), anyLong(), anyString()))
                .thenThrow(new ServerResourceException(400, "Invalid update unrefreshed cert request"));
        when(certConnection.deleteExpiredX509CertRecords(anyInt(), anyInt()))
                .thenThrow(new ServerResourceException(400, "Invalid delete expired certs request"));
        instance.setCertStore(certStore);

        // verify cleaner runs without any exceptions

        InstanceCertManager.ExpiredX509CertRecordCleaner cleaner =
                new InstanceCertManager.ExpiredX509CertRecordCleaner(certStore, 100, 0, new DynamicConfigBoolean(false));
        cleaner.run();

        try {
            instance.getUnrefreshedCertsNotifications("hostname", "provider");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid update unrefreshed cert request"));
        }

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        try {
            instance.getX509CertRecord("ostk", cert);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid get request"));
        }

        try {
            instance.getX509CertRecord("ostk", "1001", "athenz.production");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid get request"));
        }

        X509CertRecord certRecord = new X509CertRecord();
        try {
            instance.updateX509CertRecord(certRecord);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid update request"));
        }

        try {
            instance.insertX509CertRecord(certRecord);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid insert request"));
        }

        try {
            instance.deleteX509CertRecord("ostk", "1001", "athenz.production");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid delete request"));
        }

        instance.shutdown();
    }

    @Test
    public void testSSHCertOperationFailures() throws ServerResourceException {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instance.setCertSigner(null);

        SSHRecordStore sshRecordStore = Mockito.mock(SSHRecordStore.class);
        SSHRecordStoreConnection sshRecordStoreConnection = Mockito.mock(SSHRecordStoreConnection.class);
        when(sshRecordStore.getConnection()).thenReturn(sshRecordStoreConnection);

        when(sshRecordStoreConnection.getSSHCertRecord(anyString(), anyString()))
                .thenThrow(new ServerResourceException(400, "Invalid get request"));
        when(sshRecordStoreConnection.updateSSHCertRecord(any()))
                .thenThrow(new ServerResourceException(400, "Invalid update request"));
        when(sshRecordStoreConnection.deleteExpiredSSHCertRecords(anyInt(), anyInt()))
                .thenThrow(new ServerResourceException(400, "Invalid delete expired certs request"));
        instance.setSSHStore(sshRecordStore);

        // verify cleaner runs without any exceptions

        InstanceCertManager.ExpiredSSHCertRecordCleaner cleaner =
                new InstanceCertManager.ExpiredSSHCertRecordCleaner(sshRecordStore, 100, 0, new DynamicConfigBoolean(false));
        cleaner.run();

        try {
            instance.getSSHCertRecord("instance", "service");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid get request"));
        }

        SSHCertRecord sshCertRecord = new SSHCertRecord();
        assertFalse(instance.updateSSHCertRecord(sshCertRecord, true));

        instance.shutdown();
    }

    @Test
    public void testWorkloadOperationFailures() throws ServerResourceException {

        InstanceCertManager instance = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        instance.setCertSigner(null);

        WorkloadRecordStore recordStore = Mockito.mock(WorkloadRecordStore.class);
        WorkloadRecordStoreConnection storeConnection = Mockito.mock(WorkloadRecordStoreConnection.class);
        when(recordStore.getConnection()).thenReturn(storeConnection);

        when(storeConnection.insertWorkloadRecord(any()))
                .thenThrow(new ServerResourceException(400, "Invalid insert request"));
        when(storeConnection.updateWorkloadRecord(any()))
                .thenThrow(new ServerResourceException(400, "Invalid update request"));
        when(storeConnection.getWorkloadRecordsByIp(any()))
                .thenThrow(new ServerResourceException(400, "Invalid get ip request"));
        when(storeConnection.getWorkloadRecordsByService(any(), any()))
                .thenThrow(new ServerResourceException(400, "Invalid get service request"));
        instance.setWorkloadStore(recordStore);

        assertFalse(instance.insertWorkloadRecord(new WorkloadRecord()));
        assertFalse(instance.updateWorkloadRecord(new WorkloadRecord()));

        try {
            instance.getWorkloadsByIp("127.0.0.1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid get ip request"));
        }

        try {
            instance.getWorkloadsByService("domain", "service");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid get service request"));
        }

        instance.shutdown();
    }

    @Test
    public void testParseTimeUnit() {
        assertEquals(InstanceCertManager.parseTimeUnit("second"), TimeUnit.SECONDS);
        assertEquals(InstanceCertManager.parseTimeUnit("minute"), TimeUnit.MINUTES);
        assertEquals(InstanceCertManager.parseTimeUnit("hour"), TimeUnit.HOURS);
        assertEquals(InstanceCertManager.parseTimeUnit("days"), TimeUnit.DAYS);
        assertEquals(InstanceCertManager.parseTimeUnit("invalidstring"), TimeUnit.DAYS);
    }

    @Test
    public void testEmptyCertSignerFactoryClassName() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS, "");

        InstanceCertManager instanceManager = new InstanceCertManager(null, null, null, new DynamicConfigBoolean(false));
        assertNull(instanceManager.generateX509Certificate("provider", "issuer", "csr", "client", 0, Priority.High, "keyId"));
        assertNull(instanceManager.getCACertificate("provider", "keyId"));

        instanceManager.shutdown();

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS);
    }
}
