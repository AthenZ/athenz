/**
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
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.Authority.CredSource;
import com.yahoo.athenz.auth.impl.CertificateAuthority;

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
    public void testAuthenticateCertificate() throws Exception, IOException {
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
        }
    }
    
    @Test
    public void testAuthenciateInvalidArray() {
        
        CertificateAuthority authority = new CertificateAuthority();
        authority.initialize();
        StringBuilder errMsg = new StringBuilder(512);
        Principal principal = authority.authenticate(null, errMsg);
        assertNull(principal);
        
        X509Certificate[] certs = new X509Certificate[1];
        certs[0] = null;
        principal = authority.authenticate(certs, errMsg);
        assertNull(principal);
    }
}
