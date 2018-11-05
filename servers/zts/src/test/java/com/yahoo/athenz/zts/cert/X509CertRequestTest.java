package com.yahoo.athenz.zts.cert;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.*;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;

public class X509CertRequestTest {

    @Test
    public void testConstructorValidCsr() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
    }
    
    @Test
    public void testConstructorInvalidCsr() {

        X509CertRequest certReq = null;
        try {
            certReq = new X509CertRequest("csr");
            fail();
        } catch (CryptoException ignored) {
        }
        assertNull(certReq);
    }
    
    @Test
    public void testParseCertRequest() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        assertTrue(certReq.parseCertRequest(errorMsg));
    }
    
    @Test
    public void testParseCertRequestIPs() throws IOException {
        Path path = Paths.get("src/test/resources/multiple_ips.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        assertTrue(certReq.parseCertRequest(errorMsg));
        
        List<String> values = certReq.getDnsNames();
        assertEquals(values.size(), 2);
        assertTrue(values.contains("production.athenz.ostk.athenz.cloud"));
        assertTrue(values.contains("1001.instanceid.athenz.ostk.athenz.cloud"));
        
        values = certReq.getIpAddresses();
        assertEquals(values.size(), 2);
        assertTrue(values.contains("10.11.12.13"));
        assertTrue(values.contains("10.11.12.14"));
    }
    
    @Test
    public void testParseCertRequestInvalid() throws IOException {
        Path path = Paths.get("src/test/resources/invalid_dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        assertFalse(certReq.parseCertRequest(errorMsg));
    }
    
    @Test
    public void testValidateCommonName() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);

        assertTrue(certReq.validateCommonName("athenz.production"));
        assertEquals(certReq.getCommonName(), "athenz.production");
        
        assertFalse(certReq.validateCommonName("sys.production"));
        assertFalse(certReq.validateCommonName("athenz.storage"));
    }
    
    @Test
    public void testInstanceId() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);

        assertEquals(certReq.getInstanceId(), "1001");
    }
    
    @Test
    public void testDnsSuffix() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);

        assertEquals(certReq.getDnsSuffix(), "ostk.athenz.cloud");
    }
    
    @Test
    public void testValidateDnsNames() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);
        
        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertTrue(certReq.validateDnsNames(cert));
    }
    
    @Test
    public void testValidateDnsNamesMismatchSize() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.validateDnsNames(cert));
    }
    
    @Test
    public void testValidateDnsNamesMismatchValues() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.mismatch.dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.validateDnsNames(cert));
    }
    
    @Test
    public void testValidatePublicKeysCert() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertTrue(certReq.validatePublicKeys(cert));
    }
    
    @Test
    public void testValidatePublicKeysCertFailure() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        X509Certificate cert = Mockito.mock(X509Certificate.class);
        Mockito.when(cert.getPublicKey()).thenReturn(null);
        
        assertFalse(certReq.validatePublicKeys(cert));
    }
    
    @Test
    public void testValidatePublicKeysCertCSRFailure() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        PKCS10CertificationRequest req = Mockito.mock(PKCS10CertificationRequest.class);
        Mockito.when(req.getSubjectPublicKeyInfo()).thenReturn(null);
        certReq.setCertReq(req);

        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.validatePublicKeys(cert));
    }
    
    @Test
    public void testValidatePublicKeysCertMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.mismatch.dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.validatePublicKeys(cert));
    }
    
    @Test
    public void testValidatePublicKeysNull() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        assertFalse(certReq.validatePublicKeys((String) null));
    }
    
    @Test
    public void testValidatePublicKeysFailure() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        PKCS10CertificationRequest req = Mockito.mock(PKCS10CertificationRequest.class);
        Mockito.when(req.getSubjectPublicKeyInfo()).thenReturn(null);
        certReq.setCertReq(req);
        
        assertFalse(certReq.validatePublicKeys("publickey"));
    }
    
    @Test
    public void testValidateInvalidDnsNames() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "sys", "production",
                null, null, null, errorMsg));
    }
    
    @Test
    public void testValidateInvalidInstanceId() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "athenz", "production",
                null, null, null, errorMsg));
    }
    
    @Test
    public void testValidateInstanceIdMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "athenz", "production",
                "1002", null, null, errorMsg));
    }
    
    @Test
    public void testValidateCnMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.mismatch.cn.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "athenz", "production",
                "1001", null, null, errorMsg));
        assertTrue(errorMsg.toString().contains("Unable to validate CSR common name"));
    }
    
    @Test
    public void testValidateDnsSuffixMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.mismatch.dns.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "athenz", "production",
                "1001", null, null, errorMsg));
        assertTrue(errorMsg.toString().contains("does not end with expected suffix"));
    }
    
    @Test
    public void testValidateDnsSuffixNotAuthorized() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);
        
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
            .thenReturn(false);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(provider, "athenz", "production",
                "1001", null, authorizer, errorMsg));
        assertTrue(errorMsg.toString().contains("not authorized to handle"));
    }

    @Test
    public void testValidateOFieldCheck() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
                .thenReturn(true);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Unknown");

        assertFalse(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, authorizer, errorMsg));
        assertTrue(errorMsg.toString().contains("Unable to validate Subject O Field"));

        validOrgs.add("Athenz");
        assertTrue(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, authorizer, errorMsg));
    }

    @Test
    public void testValidateOFieldCheckNoValue() throws IOException {

        Path path = Paths.get("src/test/resources/valid_cn_only.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");

        assertTrue(certReq.validateSubjectOField(validOrgs));
    }

    @Test
    public void testValidateOFieldCheckMultipleValue() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_org.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");

        assertFalse(certReq.validateSubjectOField(validOrgs));
    }

    @Test
    public void testValidate() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);
        
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
            .thenReturn(true);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertTrue(certReq.validate(provider, "athenz", "production",
                "1001", null, authorizer, errorMsg));

        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertTrue(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, null, errorMsg));
    }
    
    @Test
    public void testValidatePublicKeysString() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        X509CertRequest certReq = new X509CertRequest(csr);
        
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        
        assertTrue(certReq.validatePublicKeys(ztsPublicKey));
    }
    
    @Test
    public void testValidateCertReqPublicKey() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        
        assertTrue(certReq.validatePublicKeys(ztsPublicKey));
    }

    @Test
    public void testValidateCertReqPublicKeyMismatch() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNasdfsdfsadfwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        
        assertFalse(certReq.validatePublicKeys(ztsPublicKey));
    }
    
    @Test
    public void testValidateCertReqPublicKeyWhitespace() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        final String ztsPublicKey1 = "   -----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNA QEBBQADSwAwSAJBAKrvfvBgXWqW Aorw5hYJu3dpOJe0gp3n\n\r\r\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n\r"
                + "-----END PUBLIC KEY-----  \n";
        final String ztsPublicKey2 = "-----BEGIN PUBLIC KEY-----"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ=="
                + "-----END PUBLIC KEY-----";
        
        assertTrue(certReq.validatePublicKeys(ztsPublicKey1));
        assertTrue(certReq.validatePublicKeys(ztsPublicKey2));
    }

    @Test
    public void testValidateCertCNFailure() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_cn.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        // no need to pass any arguments. we should get back false
        // because we can't parse the cn

        assertFalse(certReq.validate(null, null, null, null));
        assertFalse(certReq.validateCommonName(null));
    }

    @Test
    public void testValidateSpiffeURINoValues() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertTrue(certReq.validateSpiffeURI("domain", "sa", "api"));
    }

    @Test
    public void testValidateSpiffeURIMultipleValues() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertFalse(certReq.validateSpiffeURI("domain", "sa", "api"));
    }

    @Test
    public void testValidateSpiffeURI() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertTrue(certReq.validateSpiffeURI("coretech", "ra", "api"));
        assertFalse(certReq.validateSpiffeURI("coretech", "ra", "backend"));
        assertFalse(certReq.validateSpiffeURI("coretech", "sa", "api"));
    }

    @Test
    public void testValidateSpiffeRoleCert() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        Set<String> roles = new HashSet<>();
        roles.add("api");

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertTrue(certReq.validate(roles, "coretech", "sports.api", orgValues));
    }

    @Test
    public void testValidateSpiffeServiceCertValid() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_service.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
                .thenReturn(true);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertTrue(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, null, errorMsg));
    }

    @Test
    public void testValidateSpiffeServiceCertMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_service_mismatch.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
                .thenReturn(true);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertFalse(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, null, errorMsg));
    }

    @Test
    public void testValidateSpiffeServiceCertShortValid() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_short_service.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
                .thenReturn(true);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertTrue(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, null, errorMsg));
    }

    @Test
    public void testValidateSpiffeServiceCertShortMismatchDomain() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_service_short_mismatch_domain.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
                .thenReturn(true);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertFalse(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, null, errorMsg));
    }

    @Test
    public void testValidateSpiffeServiceCertShortMismatchService() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_service_short_mismatch_service.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
                .thenReturn(true);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertFalse(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, null, errorMsg));
    }

    @Test
    public void testValidateSpiffeInvalidScheme() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_invalid_scheme.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
                .thenReturn(true);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertFalse(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, null, errorMsg));
    }

    @Test
    public void testValidateSpiffeMissingScheme() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_invalid_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
                .thenReturn(true);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertFalse(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, null, errorMsg));
    }

    @Test
    public void testValidateSpiffeInvalidURIException() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_invalid_exc.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.auth:dns.ostk.athenz.cloud", provider, null))
                .thenReturn(true);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertFalse(certReq.validate(provider, "athenz", "production",
                "1001", validOrgs, null, errorMsg));
    }

    @Test
    public void testValidateIPAddressMultipleIPs() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_ips.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        assertFalse(certReq.validateIPAddress("10.11.12.14"));
    }

    @Test
    public void testValidateIPAddressNoIPs() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        assertTrue(certReq.validateIPAddress("10.11.12.14"));
    }

    @Test
    public void testValidateIPAddressMismatchIPs() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        assertFalse(certReq.validateIPAddress("10.11.12.14"));
    }

    @Test
    public void testValidateIPAddress() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        assertTrue(certReq.validateIPAddress("10.11.12.13"));
    }

    @Test
    public void testValidateRoleIPAddressNoIPs() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertTrue(certReq.validateIPAddress(null, "10.10.11.12"));
    }

    @Test
    public void testValidateRoleIPAddressNoCert() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertTrue(certReq.validateIPAddress(null, "10.11.12.13"));
        assertFalse(certReq.validateIPAddress(null, "10.10.11.12"));
    }

    @Test
    public void testValidateRoleIPAddressCertNoIPs() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertTrue(certReq.validateIPAddress(cert, "10.11.12.13"));
        assertFalse(certReq.validateIPAddress(cert, "10.10.11.12"));
    }

    @Test
    public void testValidateRoleIPAddressCertIPs() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/svc_single_ip.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert1 = Crypto.loadX509Certificate(pem);

        path = Paths.get("src/test/resources/svc_multiple_ip.pem");
        pem = new String(Files.readAllBytes(path));
        X509Certificate cert2 = Crypto.loadX509Certificate(pem);

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertTrue(certReq.validateIPAddress(cert1, "10.11.12.13"));
        assertTrue(certReq.validateIPAddress(cert2, "10.11.12.13"));
    }

    @Test
    public void testValidateRoleIPAddressCertMultipleIPs() throws IOException {

        Path path = Paths.get("src/test/resources/role_multiple_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/svc_single_ip.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert1 = Crypto.loadX509Certificate(pem);

        path = Paths.get("src/test/resources/svc_multiple_ip.pem");
        pem = new String(Files.readAllBytes(path));
        X509Certificate cert2 = Crypto.loadX509Certificate(pem);

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertFalse(certReq.validateIPAddress(cert1, "10.11.12.13"));
        assertTrue(certReq.validateIPAddress(cert2, "10.11.12.13"));
    }

    @Test
    public void testValidateOUFieldCheck() throws IOException {

        // the ou is "Testing Domain"

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        HashSet<String> validOrgUnits = new HashSet<>();

        assertFalse(certReq.validateSubjectOUField(null, null, null));
        assertFalse(certReq.validateSubjectOUField("Testing Domains", null, null));
        assertFalse(certReq.validateSubjectOUField(null, "Testing Domains", null));
        assertFalse(certReq.validateSubjectOUField("Bad1", "Bad2", null));
        assertFalse(certReq.validateSubjectOUField(null, null, validOrgUnits));
        assertFalse(certReq.validateSubjectOUField("Testing Domains", "None Test", validOrgUnits));

        // add invalid entry into set
        validOrgUnits.add("Testing Domains");
        assertFalse(certReq.validateSubjectOUField("Testing Domains", "None Test", validOrgUnits));

        assertTrue(certReq.validateSubjectOUField("Testing Domain", null, null));
        assertTrue(certReq.validateSubjectOUField("Testing Domain", "Bad2", validOrgUnits));

        assertTrue(certReq.validateSubjectOUField(null, "Testing Domain", null));
        assertTrue(certReq.validateSubjectOUField("Bad1", "Testing Domain", validOrgUnits));

        // add valid entry inti set
        validOrgUnits.add("Testing Domain");
        assertTrue(certReq.validateSubjectOUField(null, null, validOrgUnits));
        assertTrue(certReq.validateSubjectOUField("Bad1", "Bad2", validOrgUnits));
    }

    @Test
    public void testValidateOUFieldCheckMissingOU() throws IOException {

        // no ou field available
        Path path = Paths.get("src/test/resources/athenz.single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        HashSet<String> validOrgUnits = new HashSet<>();
        validOrgUnits.add("Athenz");

        assertTrue(certReq.validateSubjectOUField(null, null, null));
        assertTrue(certReq.validateSubjectOUField("Testing Domains", null, null));
        assertTrue(certReq.validateSubjectOUField(null, "Testing Domains", null));
        assertTrue(certReq.validateSubjectOUField("Bad1", "Bad2", null));
        assertTrue(certReq.validateSubjectOUField(null, null, validOrgUnits));
        assertTrue(certReq.validateSubjectOUField("Testing Domains", "None Test", validOrgUnits));
    }

    @Test
    public void testValidateOUFieldCheckInvalidOU() throws IOException {

        // multiple ou field: Athenz and Yahoo which we don't support
        Path path = Paths.get("src/test/resources/athenz.multiple_ou.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        assertFalse(certReq.validateSubjectOUField("Athenz", null, null));
        assertFalse(certReq.validateSubjectOUField("Yahoo", null, null));
    }
}
