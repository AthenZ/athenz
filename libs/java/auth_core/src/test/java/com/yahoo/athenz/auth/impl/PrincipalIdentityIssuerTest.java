/*
 * Copyright The Athenz Authors
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
package com.yahoo.athenz.auth.impl;

import org.bouncycastle.asn1.x500.X500Name;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class PrincipalIdentityIssuerTest {

    @Test
    public void testGetIssuerIdentity() throws Exception {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers.json");

        try (FileInputStream inStream = new FileInputStream("src/test/resources/x509_client_certificate_with_ca.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            assertEquals(issuer.getIssuerIdentity(cert), "primary");
        }
    }

    @Test
    public void testGetIssuerIdentityNotFound() throws Exception {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers.json");

        try (FileInputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            assertEquals(issuer.getIssuerIdentity(cert), "athenz");
        }
    }

    @Test
    public void testGetIssuerIdentityNullCert() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers.json");
        assertEquals(issuer.getIssuerIdentity((X509Certificate) null), "athenz");
    }

    @Test
    public void testNullFilename() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(null);
        assertNull(issuer.getIssuerIdentity((X509Certificate) null));
    }

    @Test
    public void testEmptyFilename() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer("");
        assertNull(issuer.getIssuerIdentity((X509Certificate) null));
    }

    @Test
    public void testInvalidFilename() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer("non_existent_file.json");
        assertNull(issuer.getIssuerIdentity((X509Certificate) null));
    }

    @Test
    public void testInvalidJsonFile() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/x509_ca_certificate.pem");
        assertNull(issuer.getIssuerIdentity((X509Certificate) null));
    }

    @Test
    public void testGetIssuerIdentityBySignerKey() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers.json");
        assertEquals(issuer.getIssuerIdentity("x509-primary"), "primary");
        assertEquals(issuer.getIssuerIdentity("x509-partner1"), "partner1");
    }

    @Test
    public void testGetIssuerIdentityBySignerKeyNotFound() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers.json");
        assertEquals(issuer.getIssuerIdentity("unknown-key"), "athenz");
    }

    @Test
    public void testGetIssuerIdentityBySignerKeyNull() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers.json");
        assertEquals(issuer.getIssuerIdentity((String) null), "athenz");
    }

    @Test
    public void testGetIssuerIdentityDefaultOnly() throws Exception {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers_default_only.json");

        assertEquals(issuer.getIssuerIdentity((X509Certificate) null), "athenz");
        assertEquals(issuer.getIssuerIdentity((String) null), "athenz");
        assertEquals(issuer.getIssuerIdentity("unknown-key"), "athenz");

        try (FileInputStream inStream = new FileInputStream("src/test/resources/x509_client_certificate_with_ca.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            assertEquals(issuer.getIssuerIdentity(cert), "athenz");
        }
    }

    @Test
    public void testGetIssuerIdentityInvalidEntrySkipped() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers_invalid_entry.json");

        assertEquals(issuer.getIssuerIdentity("x509-primary"), "primary");
        assertEquals(issuer.getIssuerIdentity("x509-partner1"), "athenz");
    }

    @Test
    public void testGetIssuerIdentityMultiValueCertDn() throws Exception {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers_multi_value.json");

        try (FileInputStream inStream = new FileInputStream("src/test/resources/x509_client_certificate_with_ca.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            assertEquals(issuer.getIssuerIdentity(cert), "primary");
        }
    }

    @Test
    public void testGetIssuerIdentityMultiValueSignerKey() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers_multi_value.json");

        assertEquals(issuer.getIssuerIdentity("x509-primary"), "primary");
        assertEquals(issuer.getIssuerIdentity("x509-primary-alt"), "primary");
        assertEquals(issuer.getIssuerIdentity("x509-partner1"), "partner1");
        assertEquals(issuer.getIssuerIdentity("unknown-key"), "athenz");
    }

    @Test
    public void testNormalizeDn() {
        String normalizedStringDn = PrincipalIdentityIssuer.normalizeDn("CN = Athenz Primary, O = Athenz");
        String normalizedX500Dn = PrincipalIdentityIssuer.normalizeX500Name(
                X500Name.getInstance(new X500Principal("CN=Athenz Primary,O=Athenz").getEncoded()));
        assertEquals(normalizedStringDn, normalizedX500Dn);

        normalizedX500Dn = PrincipalIdentityIssuer.normalizeX500Name(
                X500Name.getInstance(new X500Principal("o=Athenz, CN=Athenz Primary").getEncoded()));
        assertEquals(normalizedStringDn, normalizedX500Dn);
    }

    @Test
    public void testNormalizeDnInvalid() {
        assertNull(PrincipalIdentityIssuer.normalizeDn("not a valid dn"));
    }

    @Test
    public void getIssuerIdentityInvalidCert() {
        PrincipalIdentityIssuer issuer = new PrincipalIdentityIssuer(
                "src/test/resources/principal_identity_issuers.json");

        X509Certificate mockCert = Mockito.mock(X509Certificate.class);
        when(mockCert.getIssuerX500Principal()).thenThrow(new RuntimeException("mock exception"));
        assertEquals(issuer.getIssuerIdentity(mockCert), "athenz");
    }
}
