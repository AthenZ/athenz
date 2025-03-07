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

import com.yahoo.athenz.common.server.ServerResourceException;
import org.testng.annotations.*;
import org.mockito.Mockito;

import static org.testng.Assert.*;

public class CertSignerTest {

    @Test
    public void testCertSignerFactory() throws ServerResourceException {

        CertSigner signer = Mockito.mock(CertSigner.class);

        CertSignerFactory factory = () -> signer;

        CertSigner testSigner = factory.create();
        assertNotNull(testSigner);
    }

    @Test
    public void testCertSignerDefaultMethods() throws ServerResourceException {

        CertSigner signer = new CertSigner() {
        };

        assertNull(signer.generateX509Certificate("aws", "us-west-2", "csr", "client", 60,
                Priority.Unspecified_priority, "keyid"));
        assertNull(signer.getCACertificate("aws", "keyid"));
        assertEquals(signer.getMaxCertExpiryTimeMins(), 0);
        signer.close();
    }

    @Test
    public void testCertSigner() throws ServerResourceException {

        CertSigner signer = Mockito.mock(CertSigner.class);
        Mockito.when(signer.generateX509Certificate("aws", "us-west-2", "csr", "client", 100, Priority.High, "keyid"))
                .thenReturn("cert2-keyid");
        Mockito.when(signer.getCACertificate("aws", "keyid")).thenReturn("ca-cert1-keyid");
        Mockito.when(signer.getMaxCertExpiryTimeMins()).thenReturn(60);

        CertSignerFactory factory = () -> signer;

        CertSigner testSigner = factory.create();
        assertNotNull(testSigner);
        assertEquals(testSigner.generateX509Certificate("aws", "us-west-2", "csr", "client", 100,
                Priority.High, "keyid"), "cert2-keyid");
        assertEquals(testSigner.getCACertificate("aws", "keyid"), "ca-cert1-keyid");
        assertEquals(testSigner.getMaxCertExpiryTimeMins(), 60);

        testSigner.close();
    }

    @Test
    public void testPriority() {
        assertEquals(Priority.Unspecified_priority.getPriorityValue(), 0);
        assertEquals(Priority.High.getPriorityValue(), 5);
        assertEquals(Priority.Medium.getPriorityValue(), 10);
        assertEquals(Priority.Low.getPriorityValue(), 15);
    }
}
