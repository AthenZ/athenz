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
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.testng.Assert.*;

public class X509RoleCertRequestTest {

    @Test
    public void testX509RoleCertRequest() throws IOException {
        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertNotNull(certReq);

        assertEquals("coretech", certReq.getReqRoleDomain());
        assertEquals("api", certReq.getReqRoleName());

        // override the values

        certReq.setReqRoleDomain("athenz");
        certReq.setReqRoleName("backend");

        assertEquals("athenz", certReq.getReqRoleDomain());
        assertEquals("backend", certReq.getReqRoleName());
    }

    @Test
    public void testValidateSpiffeRoleCert() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertTrue(certReq.validate("sports.api", null, orgValues));
    }

    @Test
    public void testValidateRoleIPAddressNoIPs() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertTrue(certReq.validateIPAddress(null, "10.10.11.12"));
    }

    @Test
    public void testValidateRoleIPAddressNoCert() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
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

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
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

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
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

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertFalse(certReq.validateIPAddress(cert1, "10.11.12.13"));
        assertTrue(certReq.validateIPAddress(cert2, "10.11.12.13"));
    }

    @Test
    public void testValidateMissingProxyUserUri() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("sports.api", "proxy.user", orgValues));
    }

    @Test
    public void testValidateNoProxyUserUri() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("athenz.production", "proxy.user", orgValues));
    }

    @Test
    public void testValidateMultipleProxyUserUri() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_proxy_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertFalse(certReq.validate("sports.api", "proxy.user", orgValues));
    }

    @Test
    public void testValidateProxyUserUri() throws IOException {

        Path path = Paths.get("src/test/resources/proxy_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

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

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertTrue(certReq.validate("athenz.production", null, null));
        assertFalse(certReq.validate("athenz.api", null, null));
    }

    @Test
    public void testRoleCertValidatePrincipalURIWithEmail() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_role_principal_uri_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertTrue(certReq.validate("athenz.production", null, null));
        assertFalse(certReq.validate("athenz.api", null, null));
    }

    @Test
    public void testRoleCertValidatePrincipalURIWithEmailMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_role_principal_uri_email_mismatch.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertFalse(certReq.validate("athenz.production", null, null));
        assertFalse(certReq.validate("athenz.api", null, null));
    }

    @Test
    public void testValidateSpiffeURI() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertTrue(certReq.validateSpiffeURI("coretech", "api"));
        assertFalse(certReq.validateSpiffeURI("coretech", "backend"));
    }
}

