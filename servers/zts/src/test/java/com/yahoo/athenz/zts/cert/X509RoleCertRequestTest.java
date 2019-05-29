/*
 * Copyright 2019 Oath Holdings Inc.
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
    public void testValidateSpiffeRoleCert() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        Set<String> roles = new HashSet<>();
        roles.add("api");

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        assertTrue(certReq.validate(roles, "coretech", "sports.api", orgValues));
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
    public void testGetRequestedRoleListNoURI() throws IOException {

        Path path = Paths.get("src/test/resources/role_multiple_ip.csr");
        String csr = new String(Files.readAllBytes(path));
        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertNull(certReq.getRequestedRoleList());
    }

    @Test
    public void testGetRequestedRoleListNoRolesURI() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));
        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertNull(certReq.getRequestedRoleList());
    }

    @Test
    public void testGetRequestedRoleListInvalidRole() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_role_uri_invalid.csr");
        String csr = new String(Files.readAllBytes(path));
        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertNull(certReq.getRequestedRoleList());
    }

    @Test
    public void testGetRequestedRoleList() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));
        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        Map<String, String[]> roles = certReq.getRequestedRoleList();
        assertEquals(roles.size(), 2);
        String[] list1 = roles.get("sports");
        assertEquals(list1.length, 1);
        assertEquals(list1[0], "readers");
        String[] list2 = roles.get("weather");
        assertEquals(list2.length, 2);
        assertEquals(list2[0], "readers");
        assertEquals(list2[1], "writers");
    }

    @Test
    public void testRoleCertValidate() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> orgValues = new HashSet<>();
        orgValues.add("Athenz");

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertTrue(certReq.validate("athenz.production", "proxy.service", orgValues));
        assertTrue(certReq.validate("athenz.production", "proxy.service", null));
        assertFalse(certReq.validate("athenz.api", "proxy.service", orgValues));
        assertFalse(certReq.validate("athenz.production", "proxy.api", orgValues));

        Set<String> orgValues2 = new HashSet<>();
        orgValues2.add("sports");
        assertFalse(certReq.validate("athenz.production", "proxy.service", orgValues2));
    }
}

