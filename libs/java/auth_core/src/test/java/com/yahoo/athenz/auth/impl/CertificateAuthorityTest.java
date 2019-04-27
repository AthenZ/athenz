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
package com.yahoo.athenz.auth.impl;

import static org.testng.Assert.*;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.Authority.CredSource;

public class CertificateAuthorityTest {

    @Test
    public void testGetDomain() {
        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();
        assertNull(authority.getDomain());
    }

    @Test
    public void testGetHeader() {
        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();
        assertNull(authority.getHeader());
    }
    
    @Test
    public void testGetCredSource() {
        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();
        assertEquals(CredSource.CERTIFICATE, authority.getCredSource());
    }
    
    @Test
    public void testHeaderAuthenticate() {
        
        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();
        assertNull(authority.authenticate("v=U1;d=domain;n=service;s=sig", null, "GET", null));
    }
    
    @Test
    public void testAuthenticateCertificate() throws Exception {
        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();
        
        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            
            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;
            Principal principal = authority.authenticate(certs, null);
            assertNotNull(principal);
            assertEquals("athenz", principal.getDomain());
            assertEquals("syncer", principal.getName());
            assertNull(principal.getRoles());
        }
    }

    @Test
    public void testAuthenticateRoleCertificate() throws Exception {
        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;
            Principal principal = authority.authenticate(certs, null);
            assertNotNull(principal);
            assertEquals("athens", principal.getDomain());
            assertEquals("zts", principal.getName());
            assertEquals("sports:role.readers", principal.getRoles().get(0));
        }
    }
    
    @Test
    public void testAuthenciateInvalidArray() {
        
        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();
        StringBuilder errMsg = new StringBuilder(512);
        Principal principal = authority.authenticate((X509Certificate[]) null, errMsg);
        assertNull(principal);
        
        X509Certificate[] certs = new X509Certificate[1];
        certs[0] = null;
        principal = authority.authenticate(certs, errMsg);
        assertNull(principal);
    }

    @Test
    public void testGetAuthenticateChallenge() {
        CertificateAuthority authority = new CertificateAuthority();
        assertEquals(authority.getAuthenticateChallenge(), "AthenzX509Certificate realm=\"athenz\"");
    }

    @Test
    public void testAuthenticateRoleCertificateExcluded() throws Exception {

        System.setProperty("athenz.auth.certificate.exclude_role_certificates", "true");

        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(certs, errMsg);
            assertNull(principal);
            assertTrue(errMsg.toString().contains("Role Certificates not allowed"));
        }

        System.clearProperty("athenz.auth.certificate.exclude_role_certificates");
    }

    @Test
    public void testAuthenticateCertificateExcluded() throws Exception {

        System.setProperty("athenz.auth.certificate.excluded_principals", "athenz.syncer,sports.api");

        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(certs, errMsg);
            assertNull(principal);
            assertTrue(errMsg.toString().contains("Principal is excluded"));

            // retry with no err message

            principal = authority.authenticate(certs, null);
            assertNull(principal);
        }

        System.clearProperty("athenz.auth.certificate.excluded_principals");
    }

    @Test
    public void testAuthenticateCertificateInvalidEmail() throws Exception {

        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/invalid_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(certs, errMsg);
            assertNull(principal);
            assertTrue(errMsg.toString().contains("invalid email SAN entry"));
        }
    }

    @Test
    public void testAuthenticateCertificateNoEmail() throws Exception {

        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/no_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(certs, errMsg);
            assertNull(principal);
            assertTrue(errMsg.toString().contains("no email SAN entry"));
        }
    }

    @Test
    public void testAuthenticateCertificateNoPrincipal() throws Exception {

        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/no_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(certs, errMsg);
            assertNull(principal);
            assertTrue(errMsg.toString().contains("Certificate principal is empty"));
        }
    }

    @Test
    public void testAuthenticateCertificateInvalidPrincipal() throws Exception {

        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/invalid_principal_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(certs, errMsg);
            assertNull(principal);
            assertTrue(errMsg.toString().contains("Principal is not a valid service identity"));
        }
    }

    @Test
    public void testAuthenticateCertificateRoleURIs() throws Exception {

        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/role_cert_multiple_uri.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(certs, errMsg);
            assertNotNull(principal);
            List<String> roles = principal.getRoles();
            assertEquals(2, roles.size());
            assertTrue(roles.contains("coretech:role.readers"));
            assertTrue(roles.contains("coretech:role.writers"));
        }
    }

    @Test
    public void testAuthenticateCertificateRoleURIsExcluded() throws Exception {

        System.setProperty("athenz.auth.certificate.exclude_role_certificates", "true");

        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/role_cert_multiple_uri.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(certs, errMsg);
            assertNull(principal);
            assertTrue(errMsg.toString().contains("Role Certificates not allowed"));
        }

        System.clearProperty("athenz.auth.certificate.exclude_role_certificates");
    }

    @Test
    public void testAuthenticateCertificateInvalidRoleURI() throws Exception {

        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();

        try (InputStream inStream = new FileInputStream("src/test/resources/role_cert_invalid_uri.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;

            StringBuilder errMsg = new StringBuilder();
            Principal principal = authority.authenticate(certs, errMsg);
            assertNull(principal);
            assertTrue(errMsg.toString().contains("invalid uri SAN entry"));
        }
    }
}
