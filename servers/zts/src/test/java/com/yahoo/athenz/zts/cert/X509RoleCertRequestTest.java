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
import com.yahoo.athenz.common.server.spiffe.SpiffeUriManager;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.testng.Assert.*;

public class X509RoleCertRequestTest {

    final SpiffeUriManager spiffeUriManager = new SpiffeUriManager();

    @Test
    public void testX509RoleCertRequest() throws IOException {
        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertNotNull(certReq);

        assertEquals(certReq.getReqRoleDomain(), "coretech");
        assertEquals(certReq.getReqRoleName(), "api");

        // override the values

        certReq.setReqRoleDomain("athenz");
        certReq.setReqRoleName("backend");

        assertEquals(certReq.getReqRoleDomain(), "athenz");
        assertEquals(certReq.getReqRoleName(), "backend");
    }

    @Test
    public void testValidateSpiffeRoleCert() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertTrue(certReq.validate("sports.api", null, orgValues));
    }

    @Test
    public void testValidateRoleIPAddressNoIPs() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertTrue(certReq.validateIPAddress(null, "10.10.11.12"));
    }

    @Test
    public void testValidateRoleIPAddressNoCert() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertTrue(certReq.validateIPAddress(null, "10.11.12.13"));
        assertFalse(certReq.validateIPAddress(null, "10.10.11.12"));
    }

    @Test
    public void testValidateRoleIPAddressCertNoIPs() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertTrue(certReq.validateIPAddress(cert, "10.11.12.13"));
        assertFalse(certReq.validateIPAddress(cert, "10.10.11.12"));
    }

    @Test
    public void testValidateRoleIPAddressCertIPs() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/svc_single_ip.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert1 = Crypto.loadX509Certificate(pem);

        path = Paths.get("src/test/resources/svc_multiple_ip.pem");
        pem = new String(Files.readAllBytes(path));
        X509Certificate cert2 = Crypto.loadX509Certificate(pem);

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertTrue(certReq.validateIPAddress(cert1, "10.11.12.13"));
        assertTrue(certReq.validateIPAddress(cert2, "10.11.12.13"));
    }

    @Test
    public void testValidateRoleIPAddressCertMultipleIPs() throws IOException {

        Path path = Paths.get("src/test/resources/role_multiple_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/svc_single_ip.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert1 = Crypto.loadX509Certificate(pem);

        path = Paths.get("src/test/resources/svc_multiple_ip.pem");
        pem = new String(Files.readAllBytes(path));
        X509Certificate cert2 = Crypto.loadX509Certificate(pem);

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertFalse(certReq.validateIPAddress(cert1, "10.11.12.13"));
        assertTrue(certReq.validateIPAddress(cert2, "10.11.12.13"));
    }

    @Test
    public void testValidateMissingProxyUserUri() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("sports.api", "proxy.user", orgValues));
    }

    @Test
    public void testValidateNoProxyUserUri() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("athenz.production", "proxy.user", orgValues));
    }

    @Test
    public void testValidateMultipleProxyUserUri() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_proxy_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("sports.api", "proxy.user", orgValues));
    }

    @Test
    public void testValidateProxyUserUri() throws IOException {

        Path path = Paths.get("src/test/resources/proxy_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        // valid proxy user
        assertTrue(certReq.validate("sports.api", "proxy.user", orgValues));

        // mismatch proxy user
        assertFalse(certReq.validate("sports.api", "proxy2.user", orgValues));
    }

    @Test
    public void testRoleCertValidatePrincipalURINoEmail() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_role_principal_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertTrue(certReq.validate("athenz.production", null, null));
        assertFalse(certReq.validate("athenz.api", null, null));
    }

    @Test
    public void testRoleCertValidatePrincipalURIWithEmail() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_role_principal_uri_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertTrue(certReq.validate("athenz.production", null, null));
        assertFalse(certReq.validate("athenz.api", null, null));
    }

    @Test
    public void testRoleCertValidatePrincipalURIWithEmailMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_role_principal_uri_email_mismatch.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertFalse(certReq.validate("athenz.production", null, null));
        assertFalse(certReq.validate("athenz.api", null, null));
    }

    @Test
    public void testValidateSpiffeURIWithoutTrustDomain() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertTrue(certReq.validateSpiffeURI("coretech", "api"));
        assertFalse(certReq.validateSpiffeURI("coretech", "backend"));
    }

    @Test
    public void testValidateSpiffeURIWithTrustDomain() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role_trust_domain.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertTrue(certReq.validateSpiffeURI("coretech", "api"));
        assertFalse(certReq.validateSpiffeURI("coretech", "backend"));
    }

    @Test
    public void testValidateDnsNamesEmptyDnsNames() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertTrue(certReq.validateDnsNames("sports.api"));
    }

    @Test
    public void testValidateDnsNamesInvalidPrincipalNoDot() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        assertFalse(certReq.validateDnsNames("nodotprincipal"));
    }

    @Test
    public void testValidateDnsNamesValidationOffValidDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("api.sports.athenz.cloud");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        try {
            assertTrue(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesValidationOffInvalidDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("invalid.dns.name");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        try {
            assertTrue(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesValidationOffMultipleInvalidDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Arrays.asList("invalid1.dns.name", "invalid2.dns.name");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        try {
            assertTrue(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesValidationOffMixedDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Arrays.asList("api.sports.athenz.cloud", "invalid.dns.name");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        try {
            assertTrue(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesValidationOnSingleValidDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("api.sports.athenz.cloud");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertTrue(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesValidationOnSingleInvalidDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("invalid.dns.name");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertFalse(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesValidationOnMultipleDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Arrays.asList("api.sports.athenz.cloud", "extra.dns.athenz.cloud");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertFalse(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesValidationOnMultipleValidDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Arrays.asList("api.sports.athenz.cloud", "api.sports.athenz.cloud");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertFalse(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesSubdomainPrincipal() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("api.athenz-sub.athenz.cloud");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertTrue(certReq.validateDnsNames("athenz.sub.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesSubdomainPrincipalMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("api.athenz-wrong.athenz.cloud");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertFalse(certReq.validateDnsNames("athenz.sub.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesWithExistingCsrDnsNames() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);

        // role_single_ip.csr has DNS names that don't match the default suffix pattern
        // with validation off, should still return true
        X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        try {
            assertTrue(certReq.validateDnsNames("athenz.production"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesWithExistingCsrDnsNamesValidationOn() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);

        // role_single_ip.csr has 2 DNS names, with validation on and size != 1, should fail
        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertFalse(certReq.validateDnsNames("athenz.production"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesWrongSuffix() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("api.sports.wrong.suffix");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertFalse(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesWrongServiceInDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("wrongservice.sports.athenz.cloud");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertFalse(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateDnsNamesWrongDomainInDns() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("api.wrongdomain.athenz.cloud");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertFalse(certReq.validateDnsNames("sports.api"));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }

    @Test
    public void testValidateFailsDnsNames() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr, spiffeUriManager);
        certReq.dnsNames = Collections.singletonList("invalid.dns.name");

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        X509RoleCertRequest.VALIDATE_DNS_NAMES = true;
        try {
            assertFalse(certReq.validate("sports.api", null, orgValues));
        } finally {
            X509RoleCertRequest.VALIDATE_DNS_NAMES = false;
        }
    }
}

