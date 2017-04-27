package com.yahoo.athenz.zts.cert;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import static org.testng.Assert.*;

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
        } catch (CryptoException ex) {
        }
        assertNull(certReq);
    }
    
    @Test
    public void testParseDnsNames() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        assertTrue(certReq.parseDnsNames("athenz", "production", errorMsg));
        assertFalse(certReq.parseDnsNames("athenz", "storage", errorMsg));
        assertFalse(certReq.parseDnsNames("sys", "production", errorMsg));
    }
    
    @Test
    public void testParseDnsNamesInvalid() throws IOException {
        Path path = Paths.get("src/test/resources/invalid_dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        assertFalse(certReq.parseDnsNames("athenz", "production", errorMsg));
        assertTrue(errorMsg.toString().contains("Invalid SAN dnsName entry"));
    }
    
    @Test
    public void testCompareCommonName() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production", errorMsg);

        assertTrue(certReq.compareCommonName("athenz.production"));
        assertEquals(certReq.getCommonName(), "athenz.production");
        
        assertFalse(certReq.compareCommonName("sys.production"));
        assertFalse(certReq.compareCommonName("athenz.storage"));
    }
    
    @Test
    public void testInstanceId() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production", errorMsg);

        assertEquals(certReq.getInstanceId(), "1001");
    }
    
    @Test
    public void testDnsSuffix() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production", errorMsg);

        assertEquals(certReq.getDnsSuffix(), "ostk.athenz.cloud");
    }
    
    @Test
    public void testCompareDnsNames() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production", errorMsg);
        
        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertTrue(certReq.compareDnsNames(cert));
    }
    
    @Test
    public void testCompareDnsNamesMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production", errorMsg);

        path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.compareDnsNames(cert));
    }
    
    @Test
    public void testValidateInvalidDnsNames() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "sys", "production", null, null, errorMsg));
    }
    
    @Test
    public void testValidateInvalidInstanceId() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "athenz", "production", null, null, errorMsg));
    }
    
    @Test
    public void testValidateInstanceIdMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "athenz", "production", "1002", null, errorMsg));
    }
    
    @Test
    public void testValidateCnMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.mismatch.cn.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "athenz", "production", "1001", null, errorMsg));
        assertTrue(errorMsg.toString().contains("Unable to validate CSR common name"));
    }
    
    @Test
    public void testValidateDnsSuffixMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.mismatch.dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(null, "athenz", "production", "1001", null, errorMsg));
        assertTrue(errorMsg.toString().contains("Mismatch DNS suffixes"));
    }
    
    @Test
    public void testValidateDnsSuffixNotAuthorized() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.provider:dns.ostk.athenz.cloud", provider, (String) null))
            .thenReturn(false);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate(provider, "athenz", "production", "1001", authorizer, errorMsg));
        assertTrue(errorMsg.toString().contains("not authorized to handle"));
    }
    
    @Test
    public void testValidate() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal provider = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("launch", "sys.provider:dns.ostk.athenz.cloud", provider, (String) null))
            .thenReturn(true);
        
        StringBuilder errorMsg = new StringBuilder(256);
        assertTrue(certReq.validate(provider, "athenz", "production", "1001", authorizer, errorMsg));
    }
}
