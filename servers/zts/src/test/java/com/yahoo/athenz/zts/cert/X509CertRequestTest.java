package com.yahoo.athenz.zts.cert;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import static org.testng.Assert.*;
import org.testng.annotations.Test;

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
        Path path = Paths.get("src/test/resources/athenz.uuid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        assertTrue(certReq.parseDnsNames("athenz", "production"));
        assertFalse(certReq.parseDnsNames("athenz", "storage"));
        assertFalse(certReq.parseDnsNames("sys", "production"));
    }
    
    @Test
    public void testParseDnsNamesInvalid() throws IOException {
        Path path = Paths.get("src/test/resources/invalid_dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        assertFalse(certReq.parseDnsNames("athenz", "production"));
    }
    
    @Test
    public void testValidateCommonName() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.uuid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production");

        assertTrue(certReq.validateCommonName("athenz.production"));
        assertEquals(certReq.getCommonName(), "athenz.production");
        
        assertFalse(certReq.validateCommonName("sys.production"));
        assertFalse(certReq.validateCommonName("athenz.storage"));
    }
    
    @Test
    public void testInstanceId() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.uuid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production");

        assertEquals(certReq.getInstanceId(), "1001");
    }
    
    @Test
    public void testDnsSuffix() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.uuid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production");

        assertEquals(certReq.getDnsSuffix(), "ostk.athenz.cloud");
    }
    
    @Test
    public void testCompareDnsNames() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.uuid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production");
        
        path = Paths.get("src/test/resources/athenz.uuid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertTrue(certReq.compareDnsNames(cert));
    }
    
    @Test
    public void testCompareDnsNamesMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.uuid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseDnsNames("athenz", "production");

        path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.compareDnsNames(cert));
    }
}
