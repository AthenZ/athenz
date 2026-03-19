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
import com.yahoo.athenz.common.server.spiffe.SpiffeUriManager;
import org.bouncycastle.asn1.x509.GeneralName;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.*;

import static org.testng.Assert.*;

public class X509UserCertRequestTest {

    final SpiffeUriManager spiffeUriManager = new SpiffeUriManager();

    private String generateCsr(String x500Principal, GeneralName[] sanArray) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        return Crypto.generateX509CSR(keyPair.getPrivate(), keyPair.getPublic(),
                x500Principal, sanArray);
    }

    @Test
    public void testConstructor() throws Exception {
        String csr = generateCsr("cn=user.joe,o=Athenz", null);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);
        assertNotNull(certReq);
    }

    @Test
    public void testConstructorInvalidCsr() {
        try {
            new X509UserCertRequest("invalid-csr", spiffeUriManager);
            fail();
        } catch (CryptoException ignored) {
        }
    }

    @Test
    public void testConstructorMultipleSpiffeUris() {
        try {
            GeneralName[] sanArray = new GeneralName[]{
                    new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://user/sa/joe"),
                    new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://user/sa/jane")
            };
            String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
            new X509UserCertRequest(csr, spiffeUriManager);
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testValidateValidNoUri() throws Exception {
        String csr = generateCsr("cn=user.joe,o=Athenz", null);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertTrue(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateValidNullOrgValues() throws Exception {
        String csr = generateCsr("cn=user.joe,o=Athenz", null);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        assertTrue(certReq.validate("user", "joe", null));
    }

    @Test
    public void testValidateValidEmptyOrgValues() throws Exception {
        String csr = generateCsr("cn=user.joe", null);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        assertTrue(certReq.validate("user", "joe", new HashSet<>()));
    }

    @Test
    public void testValidateWithDnsNames() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "host.example.com")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithIpAddresses() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.iPAddress, "10.11.12.13")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithInstanceId() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "athenz://instanceid/provider/1001")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithUriHostname() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "athenz://hostname/host.example.com")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithMultipleUris() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "spiffe://user/sa/joe"),
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "athenz://principal/user.joe")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithSingleNonSpiffeUri() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "athenz://principal/user.joe")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithInvalidOrg() throws Exception {
        String csr = generateCsr("cn=user.joe,o=InvalidOrg", null);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithValidBasicSpiffeUri() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "spiffe://user/sa/joe")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertTrue(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithValidTrustDomainSpiffeUri() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "spiffe://athenz.io/ns/default/sa/user.joe")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertTrue(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithInvalidSpiffeUri() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "spiffe://wrongdomain/sa/joe")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithSpiffeUriMismatchServiceName() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "spiffe://user/sa/jane")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateSpiffeURINull() throws Exception {
        String csr = generateCsr("cn=user.joe,o=Athenz", null);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        assertTrue(certReq.validateSpiffeURI("user", "joe"));
    }

    @Test
    public void testValidateSpiffeURIValid() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "spiffe://user/sa/joe")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        assertTrue(certReq.validateSpiffeURI("user", "joe"));
    }

    @Test
    public void testValidateSpiffeURIInvalidDomain() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "spiffe://user/sa/joe")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        assertFalse(certReq.validateSpiffeURI("wrongdomain", "joe"));
    }

    @Test
    public void testValidateSpiffeURIInvalidUserName() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "spiffe://user/sa/joe")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        assertFalse(certReq.validateSpiffeURI("user", "jane"));
    }

    @Test
    public void testValidateWithDnsNamesAndIpAddresses() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "host.example.com"),
                new GeneralName(GeneralName.iPAddress, "10.11.12.13")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithInstanceIdAndUriHostname() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "athenz://instanceid/provider/1001"),
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "athenz://hostname/host.example.com")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateWithInstanceIdFromDnsName() throws Exception {
        GeneralName[] sanArray = new GeneralName[]{
                new GeneralName(GeneralName.dNSName,
                        "1001.instanceid.athenz.ostk.athenz.cloud")
        };
        String csr = generateCsr("cn=user.joe,o=Athenz", sanArray);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("user", "joe", orgValues));
    }

    @Test
    public void testValidateFieldAccess() throws Exception {
        String csr = generateCsr("cn=user.joe,o=Athenz", null);
        X509UserCertRequest certReq = new X509UserCertRequest(csr, spiffeUriManager);

        assertNull(certReq.reqUserName);
        assertNull(certReq.userPrincipal);

        certReq.reqUserName = "joe";
        certReq.userPrincipal = "user.joe";

        assertEquals(certReq.reqUserName, "joe");
        assertEquals(certReq.userPrincipal, "user.joe");
    }
}
