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
package com.yahoo.athenz.zts.cert;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.server.cert.CertificateDataValidator;
import com.yahoo.athenz.common.server.spiffe.SpiffeUriManager;
import org.bouncycastle.asn1.x509.GeneralName;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.*;

public class X509ExternalMemberCertRequestTest {

    final SpiffeUriManager spiffeUriManager = new SpiffeUriManager();
    final CertificateDataValidator certificateDataValidator = null;

    private String generateCsr(String x500Principal, GeneralName[] sanArray) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        return Crypto.generateX509CSR(keyPair.getPrivate(), keyPair.getPublic(),
                x500Principal, sanArray);
    }

    @Test
    public void testConstructor() throws Exception {
        String csr = generateCsr("cn=email:ext.joe@athenz.io,o=Athenz", null);
        X509ExternalMemberCertRequest certReq =
                new X509ExternalMemberCertRequest(csr, spiffeUriManager, certificateDataValidator);
        assertNotNull(certReq);
    }

    @Test
    public void testConstructorInvalidCsr() {
        try {
            new X509ExternalMemberCertRequest("invalid-csr", spiffeUriManager, certificateDataValidator);
            fail();
        } catch (CryptoException ignored) {
        }
    }

    @Test
    public void testValidateValidNoUri() throws Exception {
        String csr = generateCsr("cn=email:ext.joe@athenz.io,o=Athenz", null);
        X509ExternalMemberCertRequest certReq =
                new X509ExternalMemberCertRequest(csr, spiffeUriManager, certificateDataValidator);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertTrue(certReq.validate(orgValues));
    }

    @Test
    public void testValidateValidNullOrgValues() throws Exception {
        String csr = generateCsr("cn=email:ext.joe@athenz.io,o=Athenz", null);
        X509ExternalMemberCertRequest certReq =
                new X509ExternalMemberCertRequest(csr, spiffeUriManager, certificateDataValidator);

        assertTrue(certReq.validate(null));
    }

    @Test
    public void testValidateWithDnsNames() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "host.example.com")
        };
        String csr = generateCsr("cn=email:ext.joe@athenz.io,o=Athenz", sanArray);
        X509ExternalMemberCertRequest certReq =
                new X509ExternalMemberCertRequest(csr, spiffeUriManager, certificateDataValidator);

        assertFalse(certReq.validate(null));
    }

    @Test
    public void testValidateWithIpAddresses() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.iPAddress, "10.11.12.13")
        };
        String csr = generateCsr("cn=email:ext.joe@athenz.io,o=Athenz", sanArray);
        X509ExternalMemberCertRequest certReq =
                new X509ExternalMemberCertRequest(csr, spiffeUriManager, certificateDataValidator);

        assertFalse(certReq.validate(null));
    }

    @Test
    public void testValidateRejectsSpiffeUri() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "spiffe://user/sa/email:ext.joe@athenz.io")
        };
        String csr = generateCsr("cn=email:ext.joe@athenz.io,o=Athenz", sanArray);
        X509ExternalMemberCertRequest certReq =
                new X509ExternalMemberCertRequest(csr, spiffeUriManager, certificateDataValidator);

        assertFalse(certReq.validate(null));
    }

    @Test
    public void testValidateRejectsInstanceIdUri() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "athenz://instanceid/provider/1001")
        };
        String csr = generateCsr("cn=email:ext.joe@athenz.io,o=Athenz", sanArray);
        X509ExternalMemberCertRequest certReq =
                new X509ExternalMemberCertRequest(csr, spiffeUriManager, certificateDataValidator);

        assertFalse(certReq.validate(null));
    }

    @Test
    public void testValidateWithInvalidOrg() throws Exception {
        String csr = generateCsr("cn=email:ext.joe@athenz.io,o=InvalidOrg", null);
        X509ExternalMemberCertRequest certReq =
                new X509ExternalMemberCertRequest(csr, spiffeUriManager, certificateDataValidator);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate(orgValues));
    }
}
