package com.yahoo.athenz.auth.impl;

import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.*;

public class CertificateAuthorityValidatorTest {

    @Test
    public void testInitialize() {
        Set<String> issuerDNSet = new HashSet<>();
        issuerDNSet.add("CN=athenz.syncer,OU=athenz.syncer,O=My Test Company,L=Sunnyvale,ST=CA,C=US");
        issuerDNSet.add("CN=athenz.syncer,OU=athenz.syncer,O=My Test Company,L=New York,ST=NY,C=US");

        try {
            System.setProperty("athenz.authority.truststore.path", "src/test/resources/x509_ca_certificate_chain.pem");
            CertificateAuthorityValidator certificateAuthorityValidator = new CertificateAuthorityValidator();
            assertEquals(certificateAuthorityValidator.getIssuerDNs(), issuerDNSet);
        } catch (Exception e) {
            fail();
        } finally {
            System.clearProperty("athenz.authority.truststore.path");
        }

        CertificateAuthorityValidator certificateAuthorityValidator = new CertificateAuthorityValidator("src/test/resources/x509_ca_certificate_chain.pem");
        assertEquals(certificateAuthorityValidator.getIssuerDNs(), issuerDNSet);
    }

    @Test
    public void testValidate() throws IOException {
        System.setProperty("athenz.authority.truststore.path", "src/test/resources/x509_ca_certificate_chain.pem");
        try (InputStream inStream = new FileInputStream("src/test/resources/x509_client_certificate_with_ca.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            CertificateAuthorityValidator certificateAuthorityValidator = new CertificateAuthorityValidator();
            assertTrue(certificateAuthorityValidator.validate(cert));

            certificateAuthorityValidator = new CertificateAuthorityValidator("");
            assertTrue(certificateAuthorityValidator.validate(cert));

            certificateAuthorityValidator = new CertificateAuthorityValidator(null);
            assertTrue(certificateAuthorityValidator.validate(cert));

        } catch (IOException | CertificateException e) {
            fail();
        }

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            CertificateAuthorityValidator certificateAuthorityValidator = new CertificateAuthorityValidator();
            assertFalse(certificateAuthorityValidator.validate(cert));
        } catch (Exception e) {
            fail();
        }
        finally {
            System.clearProperty("athenz.authority.truststore.path");
        }
    }
}