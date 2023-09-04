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

import static org.testng.Assert.*;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.testng.annotations.Test;

public class CertificateIdentityTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private X509Certificate readCert(String resourceName) throws Exception {
        try (FileInputStream certIs = new FileInputStream(this.classLoader.getResource(resourceName).getFile())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(certIs);
        }
    }

    @Test
    public void testCertificateIdentity() throws Exception {
        X509Certificate cert = this.readCert("valid_cn_x509.cert");
        CertificateIdentity certId = new CertificateIdentity("domain", "service", Arrays.asList("role_1", "role_2"), cert);

        assertNotNull(certId);
        assertEquals(certId.getDomain(), "domain");
        assertEquals(certId.getService(), "service");
        assertEquals(certId.getRoles(), Arrays.asList("role_1", "role_2"));
        assertSame(certId.getX509Certificate(), cert);
    }

    @Test
    public void testGetPrincipalName() throws Exception {
        CertificateIdentity certId = new CertificateIdentity("domain", "service", null, null);

        assertNotNull(certId);
        assertEquals(certId.getPrincipalName(), "domain.service");
        assertNull(certId.getRoles());
        assertNull(certId.getX509Certificate());
    }

    @Test
    public void testToString() throws Exception {
        X509Certificate cert = this.readCert("valid_cn_x509.cert");
        CertificateIdentity certId = new CertificateIdentity("domain", "service", Arrays.asList("role_1", "role_2"),
                "domain.service", cert);

        assertNotNull(certId);
        assertEquals(certId.toString(), String.format("{\"domain\":\"domain\", \"service\":\"service\", " +
                "\"roles\":[\"role_1\", \"role_2\"], \"rolePrincipalName\":\"domain.service\", \"x509Cert\":\"%s\"}",
                certId.getX509Certificate().toString()));
    }

}
