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
package com.yahoo.athenz.common.server.ssh;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.zts.*;
import org.mockito.*;
import org.testng.annotations.*;

import static org.testng.Assert.*;

public class SSHSignerTest {

    @Test
    public void testSSHSignerFactory() {

        SSHSigner signer = Mockito.mock(SSHSigner.class);

        SSHSignerFactory factory = () -> signer;

        SSHSigner testSigner = factory.create();
        assertNotNull(testSigner);
    }

    @Test
    public void testSSHSignerDefaultMethods() {

        SSHSigner signer = new SSHSigner() {
        };

        assertNull(signer.generateCertificate(null, null, null, "client"));
        assertNull(signer.getSignerCertificate("host"));
        signer.setAuthorizer(null);
        signer.close();
    }

    @Test
    public void testSSHSigner() {

        SSHSigner signer = Mockito.mock(SSHSigner.class);
        SSHCertRequest certRequest = new SSHCertRequest();
        Principal principal = Mockito.mock(Principal.class);
        SSHCertificates certs = new SSHCertificates();
        Mockito.when(signer.generateCertificate(principal, certRequest, null, "user")).thenReturn(certs);
        Mockito.when(signer.getSignerCertificate("user")).thenReturn("ssh-cert");

        SSHSignerFactory factory = () -> signer;

        SSHSigner testSigner = factory.create();
        assertNotNull(testSigner);

        assertEquals(certs, testSigner.generateCertificate(principal, certRequest, null, "user"));
        assertEquals("ssh-cert", testSigner.getSignerCertificate("user"));
        testSigner.close();
    }
}
