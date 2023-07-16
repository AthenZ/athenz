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
package com.yahoo.athenz.auth.util;

import static org.testng.Assert.*;

import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

public class AthenzUtilsTest {

    @Test
    public void testExtractServicePrincipal() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_singleip.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertEquals("athenz.production", AthenzUtils.extractServicePrincipal(cert));
        }

        try (InputStream inStream = new FileInputStream("src/test/resources/ec_public_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertEquals("athenz.syncer", AthenzUtils.extractServicePrincipal(cert));
        }
    }

    @Test
    public void testExtractServicePrincipalRoleCert() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/valid_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertEquals("athens.zts", AthenzUtils.extractServicePrincipal(cert));
        }
    }

    @Test
    public void testExtractRolePrincipalRoleCert() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/valid_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertEquals("athens.zts", AthenzUtils.extractRolePrincipal(cert));
        }
    }

    @Test
    public void testExtractServicePrincipalRoleCertUri() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/role_cert_principal_uri_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertEquals("athenz.production", AthenzUtils.extractServicePrincipal(cert));
        }
    }

    @Test
    public void testExtractRolePrincipalRoleCertUri() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/role_cert_principal_uri_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertEquals("athenz.production", AthenzUtils.extractRolePrincipal(cert));
        }
    }

    @Test
    public void testExtractServicePrincipalNoCn() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/no_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertNull(AthenzUtils.extractServicePrincipal(cert));
        }
    }

    @Test
    public void testExtractServicePrincipalInvalidEmailCount() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/no_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertNull(AthenzUtils.extractServicePrincipal(cert));
        }

        try (InputStream inStream = new FileInputStream("src/test/resources/multiple_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertNull(AthenzUtils.extractServicePrincipal(cert));
        }
    }

    @Test
    public void testExtractServicePrincipalInvalidEmailFormat() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/invalid_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertNull(AthenzUtils.extractServicePrincipal(cert));
        }
    }

    @Test
    public void testIsRoleCertificateServiceCertificate() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_singleip.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertFalse(AthenzUtils.isRoleCertificate(cert));
        }
    }

    @Test
    public void testIsRoleCertificateRoleCertificate() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/valid_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertTrue(AthenzUtils.isRoleCertificate(cert));
        }
    }

    @Test
    public void testIsRoleCertificateNoCn() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/no_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertFalse(AthenzUtils.isRoleCertificate(cert));
        }
    }

    @Test
    public void testExtractRoleName() {
        assertEquals(AthenzUtils.extractRoleName("athenz:role.readers"), "readers");
        assertEquals(AthenzUtils.extractRoleName("athenz.api:role.readers"), "readers");
        assertEquals(AthenzUtils.extractRoleName("athenz.api.test:role.readers"), "readers");

        assertNull(AthenzUtils.extractRoleName("athenz:roles.readers"));
        assertNull(AthenzUtils.extractRoleName("athenz.role.readers"));
        assertNull(AthenzUtils.extractRoleName("athenz:role."));
        assertNull(AthenzUtils.extractRoleName(":role.readers"));
        assertNull(AthenzUtils.extractRoleName("athenz.readers"));
    }

    @Test
    public void testExtractPolicyName() {
        assertEquals(AthenzUtils.extractPolicyName("athenz:policy.readers"), "readers");
        assertEquals(AthenzUtils.extractPolicyName("athenz.api:policy.readers"), "readers");
        assertEquals(AthenzUtils.extractPolicyName("athenz.api.test:policy.readers"), "readers");

        assertNull(AthenzUtils.extractPolicyName("athenz:policys.readers"));
        assertNull(AthenzUtils.extractPolicyName("athenz.policy.readers"));
        assertNull(AthenzUtils.extractPolicyName("athenz:policy."));
        assertNull(AthenzUtils.extractPolicyName(":policy.readers"));
        assertNull(AthenzUtils.extractPolicyName("athenz.readers"));
    }

    @Test
    public void testExtractGroupName() {
        assertEquals(AthenzUtils.extractGroupName("athenz:group.readers"), "readers");
        assertEquals(AthenzUtils.extractGroupName("athenz.api:group.readers"), "readers");
        assertEquals(AthenzUtils.extractGroupName("athenz.api.test:group.readers"), "readers");

        assertNull(AthenzUtils.extractGroupName("athenz:groups.readers"));
        assertNull(AthenzUtils.extractGroupName("athenz.group.readers"));
        assertNull(AthenzUtils.extractGroupName("athenz:group."));
        assertNull(AthenzUtils.extractGroupName(":group.readers"));
        assertNull(AthenzUtils.extractGroupName("athenz.readers"));
    }

    @Test
    public void testExtractRoleDomainName() {
        assertEquals(AthenzUtils.extractRoleDomainName("athenz:role.readers"), "athenz");
        assertEquals(AthenzUtils.extractRoleDomainName("athenz.api:role.readers"), "athenz.api");
        assertEquals(AthenzUtils.extractRoleDomainName("athenz.api.test:role.readers"), "athenz.api.test");

        assertNull(AthenzUtils.extractRoleDomainName("athenz.role.readers"));
        assertNull(AthenzUtils.extractRoleDomainName("athenz:roles.readers"));
        assertNull(AthenzUtils.extractRoleDomainName("athenz:role."));
        assertNull(AthenzUtils.extractRoleDomainName(":role.readers"));
        assertNull(AthenzUtils.extractRoleDomainName("athenz.readers"));
    }

    @Test
    public void testExtractPrincipalDomainName() {
        assertEquals(AthenzUtils.extractPrincipalDomainName("athenz.reader"), "athenz");
        assertEquals(AthenzUtils.extractPrincipalDomainName("athenz.api.reader"), "athenz.api");
        assertEquals(AthenzUtils.extractPrincipalDomainName("athenz.api.test.reader"), "athenz.api.test");

        assertNull(AthenzUtils.extractPrincipalDomainName("athenz"));
        assertNull(AthenzUtils.extractPrincipalDomainName("athenz."));
        assertNull(AthenzUtils.extractPrincipalDomainName(".athenz"));
    }

    @Test
    public void testExtractPrincipalServiceName() {
        assertEquals(AthenzUtils.extractPrincipalServiceName("athenz.reader"), "reader");
        assertEquals(AthenzUtils.extractPrincipalServiceName("athenz.api.reader"), "reader");
        assertEquals(AthenzUtils.extractPrincipalServiceName("athenz.api.test.reader"), "reader");

        assertNull(AthenzUtils.extractPrincipalServiceName("athenz"));
        assertNull(AthenzUtils.extractPrincipalServiceName("athenz."));
        assertNull(AthenzUtils.extractPrincipalServiceName(".athenz"));
    }

    @Test
    public void testSplitPrincipalName() {
        assertEquals(AthenzUtils.splitPrincipalName("athenz.reader"), new String[]{"athenz", "reader"});
        assertEquals(AthenzUtils.splitPrincipalName("Athenz.Reader"), new String[]{"athenz", "reader"});
        assertEquals(AthenzUtils.splitPrincipalName("athenz.api.reader"), new String[]{"athenz.api", "reader"});
        assertEquals(AthenzUtils.splitPrincipalName("athenz.api.test.reader"), new String[]{"athenz.api.test", "reader"});

        assertNull(AthenzUtils.splitPrincipalName("athenz"));
        assertNull(AthenzUtils.splitPrincipalName("athenz."));
        assertNull(AthenzUtils.splitPrincipalName(".athenz"));
    }

    @Test
    public void testGetPrincipalName() {
        assertEquals(AthenzUtils.getPrincipalName("domain", "service"), "domain.service");
        assertEquals(AthenzUtils.getPrincipalName("dDd", "SsS"), "ddd.sss");

        assertNull(AthenzUtils.getPrincipalName("domain", null));
        assertNull(AthenzUtils.getPrincipalName("domain", ""));
        assertNull(AthenzUtils.getPrincipalName(null, "service"));
        assertNull(AthenzUtils.getPrincipalName("", "service"));
    }

    @Test
    public void testPrivateConstructor() throws Exception {
        Constructor<AthenzUtils> constructor = AthenzUtils.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        constructor.newInstance();
    }

    @Test
    public void testSplitCommaSeperatedSystemProperty() {
        String systemProperty = "athenz.zts.notification_cert_fail_ignored_services_list";
        System.setProperty(systemProperty, "aaa, bbb, ccc");

        List<String> values = AthenzUtils.splitCommaSeparatedSystemProperty(systemProperty);
        assertEquals(3, values.size());
        assertEquals("aaa", values.get(0));
        assertEquals("bbb", values.get(1));
        assertEquals("ccc", values.get(2));

        List<String> values2 = AthenzUtils.splitCommaSeparatedSystemProperty("unset.property");
        assertEquals(new ArrayList<>(), values2);

        System.clearProperty(systemProperty);
    }
}
