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
import com.yahoo.athenz.zts.cache.DataCache;
import org.mockito.Mockito;
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
        assertFalse(certReq.validate("sys", "production", "provider",
                null, null, null, null, null, null, null, errorMsg));
    }

    @Test
    public void testValidateInvalidInstanceId() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        List<String> providerDnsSuffixList = Collections.singletonList("ostk.athenz.cloud");

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider")).thenReturn(providerDnsSuffixList);

        assertFalse(certReq.validate("athenz", "production", "provider",
                null, athenzSysDomainCache, null, null, null, null, null, errorMsg));
    }

    @Test
    public void testValidateInstanceIdMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

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

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider")).thenReturn(providerDnsSuffixList);

        assertFalse(certReq.validate("athenz", "production", "provider",
                null, athenzSysDomainCache, null, null, null, null, null, errorMsg));
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

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider")).thenReturn(providerDnsSuffixList);

        assertFalse(certReq.validate("athenz", "production", "provider",
                null, athenzSysDomainCache, null, null, null, null, null, errorMsg));
        assertEquals(errorMsg.toString(), "production.athenz.ostk.athenz.cloud does not end with provider/service configured suffix or hostname");
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

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider")).thenReturn(providerDnsSuffixList);

        assertFalse(certReq.validate("athenz", "production", "provider",
                validOrgs, athenzSysDomainCache, null, null, null, null, null, errorMsg));
        assertTrue(errorMsg.toString().contains("Unable to validate Subject O Field"));

        validOrgs.add("Athenz");
        assertTrue(certReq.validate("athenz", "production", "provider",
                validOrgs, athenzSysDomainCache, null, null, null, null, null, errorMsg));
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

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider")).thenReturn(providerDnsSuffixList);

        assertTrue(certReq.validate("athenz", "production", "provider",
                null, athenzSysDomainCache, null, null, null, null, null, errorMsg));

        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertTrue(certReq.validate("athenz", "production", "provider",
                validOrgs, athenzSysDomainCache, null, null, null, null, null, errorMsg));
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

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider")).thenReturn(providerDnsSuffixList);

        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        boolean ourResult = certReq.validate("athenz", "production", "provider",
                validOrgs, athenzSysDomainCache, null, null, null, null, null, errorMsg);
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

    @Test
    public void testValidateUriHostname() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.examples.uri-instanceid-hostname.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        assertTrue(certReq.validateUriHostname("abc.athenz.com"));
        assertTrue(certReq.validateUriHostname("abc.athenz.com"));

        assertFalse(certReq.validateUriHostname(null));
        assertFalse(certReq.validateUriHostname(""));
        assertFalse(certReq.validateUriHostname("def.athenz.com"));
    }


    @Test
    public void testValidateWithUriHostname() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.examples.uri-instanceid-hostname.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        List<String> providerDnsSuffixList = Collections.singletonList("ostk.athenz.cloud");
        List<String> providerHostnameAllowSuffixList = Collections.singletonList("athenz.com");

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("ostk.provider")).thenReturn(providerDnsSuffixList);
        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("ostk.provider")).thenReturn(providerHostnameAllowSuffixList);

        assertFalse(certReq.validate("athenz.examples", "httpd", "ostk.provider",
                null, athenzSysDomainCache, null, "def.athenz.com", null, null, null, errorMsg));
        assertFalse(certReq.validate("athenz.examples", "httpd", "ostk.provider",
                null, athenzSysDomainCache, null, null, null, null, null, errorMsg));

        assertTrue(certReq.validate("athenz.examples", "httpd", "ostk.provider",
                null, athenzSysDomainCache, null, "abc.athenz.com", null, null, null, errorMsg));

        HashSet<String> validOrgs = new HashSet<>();
        validOrgs.add("Athenz");
        assertTrue(certReq.validate("athenz.examples", "httpd", "ostk.provider",
                validOrgs, athenzSysDomainCache, null, "abc.athenz.com", null, null, null, errorMsg));
    }

    @Test
    public void testValidateSpiffeURIWithoutURI() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertTrue(certReq.validateSpiffeURI("domain", "api", null));
        assertTrue(certReq.validateSpiffeURI("domain", "api", "default"));
    }

    @Test
    public void testValidateSpiffeURIWithNamespace() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe-namespace.csr");
        String csr = new String(Files.readAllBytes(path));

        X509ServiceCertRequest certReq = new X509ServiceCertRequest(csr);
        assertTrue(certReq.validateSpiffeURI("athenz", "production", "default"));
        assertFalse(certReq.validateSpiffeURI("athenz", "production", "test"));

        // with null or empty we default to value of default

        assertTrue(certReq.validateSpiffeURI("athenz", "production", null));
        assertTrue(certReq.validateSpiffeURI("athenz", "production", ""));
    }

    @Test
    public void testValidateSpiffeURIMultipleValues() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        try {
            new X509ServiceCertRequest(csr);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid SPIFFE URI present"));
        }
    }
}

