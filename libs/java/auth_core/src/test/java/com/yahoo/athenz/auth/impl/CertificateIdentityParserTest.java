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
import java.lang.reflect.Field;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.BiFunction;
import jakarta.servlet.http.HttpServletRequest;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

public class CertificateIdentityParserTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private X509Certificate readCert(String resourceName) throws Exception {
        try (FileInputStream certIs = new FileInputStream(this.classLoader.getResource(resourceName).getFile())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(certIs);
        }
    }

    @Test
    public void testCertificateIdentityParser() {
        BiFunction<Field, CertificateIdentityParser, Object> getFieldValue = (f, object) -> {
            try {
                f.setAccessible(true);
                return f.get(object);
            } catch (IllegalArgumentException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        };
        CertificateIdentityParser parser;

        parser = new CertificateIdentityParser(null, false);
        assertNotNull(parser);
        for (Field f : parser.getClass().getDeclaredFields()) {
            switch (f.getName()) {
            case "excludedPrincipalSet":
                assertNull(getFieldValue.apply(f, parser));
                break;
            case "excludeRoleCertificates":
                assertEquals(getFieldValue.apply(f, parser), false);
                break;
            }
        }

        parser = new CertificateIdentityParser(new HashSet<>(Arrays.asList("principal_1", "principal_2")), true);
        assertNotNull(parser);
        for (Field f : parser.getClass().getDeclaredFields()) {
            switch (f.getName()) {
            case "excludedPrincipalSet":
                assertEquals(getFieldValue.apply(f, parser), new HashSet<>(Arrays.asList("principal_1", "principal_2")));
                break;
            case "excludeRoleCertificates":
                assertEquals(getFieldValue.apply(f, parser), true);
                break;
            }
        }
    }

    @Test
    public void testParseFromHttpServletRequest() throws Exception {
        // mock request
        X509Certificate[] certs = new X509Certificate[]{ this.readCert("valid_cn_x509.cert") };
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getAttribute(CertificateIdentityParser.JAVAX_CERT_ATTR)).thenReturn(certs);

        // mock instance
        CertificateIdentityParser mock = Mockito.spy(new CertificateIdentityParser(null, false));
        ArgumentCaptor<X509Certificate[]> argument = ArgumentCaptor.forClass(X509Certificate[].class);
        mock.parse(request);

        // verify
        Mockito.verify(mock, Mockito.times(1)).parse(argument.capture());
        assertSame(argument.getValue(), certs);
    }

    @Test
    public void testParseCertificate() throws Exception {
        CertificateIdentityParser parser = new CertificateIdentityParser(null, false);

        X509Certificate[] certs = new X509Certificate[]{ this.readCert("valid_cn_x509.cert") };
        CertificateIdentity certId = parser.parse(certs);
        assertNotNull(certId);
        assertEquals(certId.getDomain(), "athenz");
        assertEquals(certId.getService(), "syncer");
        assertNull(certId.getRoles());
    }

    @Test
    public void testParseRoleCertificate() throws Exception {
        CertificateIdentityParser parser = new CertificateIdentityParser(null, false);

        X509Certificate[] certs = new X509Certificate[]{ this.readCert("valid_email_x509.cert") };
        CertificateIdentity certId = parser.parse(certs);
        assertNotNull(certId);
        assertEquals(certId.getDomain(), "athens");
        assertEquals(certId.getService(), "zts");
        assertEquals(certId.getRoles().get(0), "sports:role.readers");
    }

    @Test
    public void testParseInvalidArray() {
        CertificateIdentityParser parser = new CertificateIdentityParser(null, false);
        CertificateIdentity certId = null;

        try {
            certId = parser.parse((X509Certificate[]) null);
        } catch (CertificateIdentityException e) {
            assertEquals(e.getMessage(), "No certificate available in request");
        } finally {
            assertNull(certId);
        }

        try {
            certId = parser.parse(new X509Certificate[]{ null });
        } catch (CertificateIdentityException e) {
            assertEquals(e.getMessage(), "No certificate available in request");
        } finally {
            assertNull(certId);
        }
    }

    @Test
    public void testParseRoleCertificateExcluded() throws Exception {
        CertificateIdentityParser parser = new CertificateIdentityParser(null, true);

        X509Certificate[] certs = new X509Certificate[]{ this.readCert("valid_email_x509.cert") };
        CertificateIdentity certId = null;
        try {
            certId = parser.parse(certs);
        } catch (CertificateIdentityException e) {
            assertEquals(e.getMessage(), "Role Certificates not allowed");
        } finally {
            assertNull(certId);
        }
    }

    @Test
    public void testParseCertificateExcluded() throws Exception {
        Set<String> excludedPrincipalSet = new HashSet<>(Arrays.asList("athenz.syncer", "sports.api"));
        CertificateIdentityParser parser = new CertificateIdentityParser(excludedPrincipalSet, false);

        X509Certificate[] certs = new X509Certificate[]{ this.readCert("valid_cn_x509.cert") };
        CertificateIdentity certId = null;
        try {
            certId = parser.parse(certs);
        } catch (CertificateIdentityException e) {
            assertEquals(e.getMessage(), "Principal is excluded");
        } finally {
            assertNull(certId);
        }
    }

    @Test
    public void testParseCertificateInvalidEmail() throws Exception {
        CertificateIdentityParser parser = new CertificateIdentityParser(null, false);

        X509Certificate[] certs = new X509Certificate[]{ this.readCert("invalid_email_x509.cert") };
        CertificateIdentity certId = null;
        try {
            certId = parser.parse(certs);
        } catch (CertificateIdentityException e) {
            assertEquals(e.getMessage(), "Invalid role cert, no role principal");
        } finally {
            assertNull(certId);
        }
    }

    @Test
    public void testParseCertificateNoEmail() throws Exception {
        CertificateIdentityParser parser = new CertificateIdentityParser(null, false);

        X509Certificate[] certs = new X509Certificate[]{ this.readCert("no_email_x509.cert") };
        CertificateIdentity certId = null;
        try {
            certId = parser.parse(certs);
        } catch (CertificateIdentityException e) {
            assertEquals(e.getMessage(), "Invalid role cert, no role principal");
        } finally {
            assertNull(certId);
        }
    }

    @Test
    public void testParseCertificateNoPrincipal() throws Exception {
        CertificateIdentityParser parser = new CertificateIdentityParser(null, false);

        X509Certificate[] certs = new X509Certificate[]{ this.readCert("no_cn_x509.cert") };
        CertificateIdentity certId = null;
        try {
            certId = parser.parse(certs);
        } catch (CertificateIdentityException e) {
            assertEquals(e.getMessage(), "Certificate principal is empty");
        } finally {
            assertNull(certId);
        }
    }

    @Test
    public void testParseCertificateInvalidPrincipal() throws Exception {
        CertificateIdentityParser parser = new CertificateIdentityParser(null, false);

        X509Certificate[] certs = new X509Certificate[]{ this.readCert("invalid_principal_x509.cert") };
        CertificateIdentity certId = null;
        try {
            certId = parser.parse(certs);
        } catch (CertificateIdentityException e) {
            assertEquals(e.getMessage(), "Principal is not a valid service identity");
        } finally {
            assertNull(certId);
        }
    }
}
