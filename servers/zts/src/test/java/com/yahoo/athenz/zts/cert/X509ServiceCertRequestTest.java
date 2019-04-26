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
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.testng.Assert.*;

public class X509ServiceCertRequestTest {

    @Test
    public void testValidateInvalidDnsNames() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        assertFalse(certReq.validate("sys", "production",
                null, null, null, null, null, errorMsg));
    }

    @Test
    public void testValidateInvalidInstanceId() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        List<String> providerDnsSuffixList = Collections.singletonList("ostk.athenz.cloud");
        assertFalse(certReq.validate("athenz", "production",
                null, providerDnsSuffixList, null, null, null, errorMsg));
    }

    @Test
    public void testValidateInstanceIdMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        assertTrue(certReq.parseCertRequest(errorMsg));

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        assertFalse(certReq.validateInstanceId("1002", cert));
        assertTrue(certReq.validateInstanceId("1001", cert));
    }

    @Test
    public void testValidateCnMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.mismatch.cn.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        List<String> providerDnsSuffixList = Collections.singletonList("ostk.athenz.cloud");
        assertFalse(certReq.validate("athenz", "production",
                null, providerDnsSuffixList, null, null, null, errorMsg));
        assertTrue(errorMsg.toString().contains("Unable to validate CSR common name"));
    }

    @Test
    public void testValidateDnsSuffixMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.mismatch.dns.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        List<String> providerDnsSuffixList = Collections.singletonList("zts.athenz.cloud");
        assertFalse(certReq.validate("athenz", "production",
                null, providerDnsSuffixList, null, null, null, errorMsg));
        assertTrue(errorMsg.toString().contains("invalid dns suffix"));
    }

    @Test
    public void testValidateOFieldCheck() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Unknown");

        List<String> providerDnsSuffixList = Collections.singletonList("ostk.athenz.cloud");

        assertFalse(certReq.validate("athenz", "production",
                validOrgs, providerDnsSuffixList, null, null, null, errorMsg));
        assertTrue(errorMsg.toString().contains("Unable to validate Subject O Field"));

        validOrgs.add("Athenz");
        assertTrue(certReq.validate("athenz", "production",
                validOrgs, providerDnsSuffixList, null, null, null, errorMsg));
    }

    @Test
    public void testValidateOFieldCheckNoValue() throws IOException {

        Path path = Paths.get("src/test/resources/valid_cn_only.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");

        assertTrue(certReq.validateSubjectOField(validOrgs));
    }

    @Test
    public void testValidateOFieldCheckMultipleValue() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_org.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");

        assertFalse(certReq.validateSubjectOField(validOrgs));
    }

    @Test
    public void testValidate() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        List<String> providerDnsSuffixList = Collections.singletonList("ostk.athenz.cloud");

        assertTrue(certReq.validate("athenz", "production",
                null, providerDnsSuffixList, null, null, null, errorMsg));

        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertTrue(certReq.validate("athenz", "production",
                validOrgs, providerDnsSuffixList, null, null, null, errorMsg));
    }


    @DataProvider(name = "spiffeUriData")
    public static Object[][] spiffeUriData() {
        return new Object[][] {
                { "src/test/resources/spiffe_service.csr", true },
                { "src/test/resources/spiffe_service_mismatch.csr", false},
                { "src/test/resources/spiffe_short_service.csr", true },
                { "src/test/resources/spiffe_service_short_mismatch_domain.csr", false },
                { "src/test/resources/spiffe_service_short_mismatch_service.csr", false },
                { "src/test/resources/spiffe_invalid_uri.csr", false },
                { "src/test/resources/spiffe_invalid_exc.csr", false },
                { "src/test/resources/spiffe_invalid_scheme.csr", true}
        };
    }

    @Test(dataProvider = "spiffeUriData")
    public void testValidateSpiffeUri(final String csrPath, boolean expectedResult) throws IOException {

        Path path = Paths.get(csrPath);
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        List<String> providerDnsSuffixList = Collections.singletonList("ostk.athenz.cloud");
        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        boolean ourResult = certReq.validate("athenz", "production",
                validOrgs, providerDnsSuffixList, null, null, null, errorMsg);
        assertEquals(ourResult, expectedResult);
    }

    @Test
    public void testValidateIPAddressMultipleIPs() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_ips.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        assertFalse(certReq.validateIPAddress("10.11.12.14"));
    }

    @Test
    public void testValidateIPAddressNoIPs() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        assertTrue(certReq.validateIPAddress("10.11.12.14"));
    }

    @Test
    public void testValidateIPAddressMismatchIPs() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        assertFalse(certReq.validateIPAddress("10.11.12.14"));
    }

    @Test
    public void testValidateIPAddress() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        assertTrue(certReq.validateIPAddress("10.11.12.13"));
    }
}

