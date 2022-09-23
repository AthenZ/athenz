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
package com.yahoo.athenz.common.server.cert;

import org.testng.annotations.*;
import org.mockito.Mockito;

import static org.testng.Assert.*;

public class CertSignerTest {

    @Test
    public void testCertSignerFactory() {

        CertSigner signer = Mockito.mock(CertSigner.class);

        CertSignerFactory factory = () -> signer;

        CertSigner testSigner = factory.create();
        assertNotNull(testSigner);
    }

    @Test
    public void testCertSignerDefaultMethods() {

        CertSigner signer = new CertSigner() {
        };

        assertNull(signer.generateX509Certificate("csr", "client", 60));
        assertNull(signer.generateX509Certificate("aws", "us-west-2", "csr", "client", 60));
        assertNull(signer.generateX509Certificate("aws", "us-west-2", "csr", "client", 60, Priority.Unspecified_priority));
        assertNull(signer.getCACertificate());
        assertNull(signer.getCACertificate("aws"));
        assertEquals(signer.getMaxCertExpiryTimeMins(), 0);
        signer.close();
    }

    @Test
    public void testCertSigner() {

        CertSigner signer = Mockito.mock(CertSigner.class);
        Mockito.when(signer.generateX509Certificate("csr", "client", 100)).thenReturn("cert");
        Mockito.when(signer.generateX509Certificate("aws", "us-west-2", "csr", "client", 100)).thenReturn("cert1");
        Mockito.when(signer.generateX509Certificate("aws", "us-west-2", "csr", "client", 100, Priority.High)).thenReturn("cert2");
        Mockito.when(signer.getCACertificate()).thenReturn("ca-cert");
        Mockito.when(signer.getCACertificate("aws")).thenReturn("ca-cert1");
        Mockito.when(signer.getMaxCertExpiryTimeMins()).thenReturn(60);

        CertSignerFactory factory = () -> signer;

        CertSigner testSigner = factory.create();
        assertNotNull(testSigner);
        assertEquals("cert", testSigner.generateX509Certificate("csr", "client", 100));
        assertEquals("cert1", testSigner.generateX509Certificate("aws", "us-west-2", "csr", "client", 100));
        assertEquals("cert2", testSigner.generateX509Certificate("aws", "us-west-2", "csr", "client", 100, Priority.High));
        assertEquals("ca-cert", testSigner.getCACertificate());
        assertEquals("ca-cert1", testSigner.getCACertificate("aws"));
        assertEquals(60, testSigner.getMaxCertExpiryTimeMins());

        testSigner.close();
    }
}
