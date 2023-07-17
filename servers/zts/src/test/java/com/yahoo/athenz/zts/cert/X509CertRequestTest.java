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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.testng.Assert.*;

import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.zts.CertType;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cert.impl.TestHostnameResolver;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;

public class X509CertRequestTest {

    @Test
    public void testConstructorValidCsr() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
    }
    
    @Test
    public void testConstructorInvalidCsr() {

        X509CertRequest certReq = null;
        try {
            certReq = new X509CertRequest("csr");
            fail();
        } catch (CryptoException ignored) {
        }
        assertNull(certReq);
    }

    @Test
    public void testConstructorValidUriHostname() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.examples.uri-instanceid-hostname.csr");

        X509CertRequest certReq = new X509CertRequest(new String(Files.readAllBytes(path)));
        assertNotNull(certReq);

        assertEquals(certReq.getUriHostname(), "abc.athenz.com");

        path = Paths.get("src/test/resources/athenz.examples.uri-hostname-only.csr");

        certReq = new X509CertRequest(new String(Files.readAllBytes(path)));
        assertNotNull(certReq);
        assertEquals(certReq.getUriHostname(), "abc.athenz.com");
    }

    @Test
    public void testParseCertRequestIPs() throws IOException {
        Path path = Paths.get("src/test/resources/multiple_ips.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        List<String> values = certReq.getDnsNames();
        assertEquals(values.size(), 2);
        assertTrue(values.contains("production.athenz.ostk.athenz.cloud"));
        assertTrue(values.contains("1001.instanceid.athenz.ostk.athenz.cloud"));
        
        values = certReq.getIpAddresses();
        assertEquals(values.size(), 2);
        assertTrue(values.contains("10.11.12.13"));
        assertTrue(values.contains("10.11.12.14"));
    }
    
    @Test
    public void testParseCertRequestInvalid() throws IOException {
        Path path = Paths.get("src/test/resources/invalid_dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
    }
    
    @Test
    public void testValidateCommonName() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        assertTrue(certReq.validateCommonName("athenz.production"));
        assertEquals(certReq.getCommonName(), "athenz.production");
        
        assertFalse(certReq.validateCommonName("sys.production"));
        assertFalse(certReq.validateCommonName("athenz.storage"));
    }

    @Test
    public void testValidateUriHostname() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.examples.uri-instanceid-hostname.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        assertTrue(certReq.validateUriHostname("abc.athenz.com"));

        assertFalse(certReq.validateUriHostname(null));
        assertFalse(certReq.validateUriHostname(""));
        assertFalse(certReq.validateUriHostname("def.athenz.com"));


        path = Paths.get("src/test/resources/athenz.examples.uri-hostname-empty.csr");
        csr = new String(Files.readAllBytes(path));

        certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        assertTrue(certReq.validateUriHostname("abc.athenz.com"));
    }

    @Test
    public void testInstanceId() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        assertEquals(certReq.getInstanceId(), "1001");
    }

    @Test
    public void testValidateDnsNamesWithCert() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertTrue(certReq.validateDnsNames(cert));
    }

    @Test
    public void testValidateDnsNamesWithValues() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        List<String> providerDnsSuffixList = new ArrayList<>();

        // for the first test we're going to return null
        // and the list for all subsequent tests

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(null)
                .thenReturn(providerDnsSuffixList);

        List<String> providerHostnameAllowedSuffixList = Collections.singletonList("athenz.cloud");
        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("provider"))
                .thenReturn(providerHostnameAllowedSuffixList);
        Mockito.when(athenzSysDomainCache.getProviderHostnameDeniedSuffixList("provider"))
                .thenReturn(null);

        StringBuilder errorMsg = new StringBuilder();
        assertTrue(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "ostk.athenz.cloud", null, null, null, errorMsg));

        // empty provider suffix list

        assertTrue(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "ostk.athenz.cloud", null, null, null, errorMsg));

        // provider suffix list with no match

        providerDnsSuffixList.add("ostk.myathenz.cloud");
        assertTrue(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "ostk.athenz.cloud", null, null, null, errorMsg));

        // no match if service list does not match

        assertFalse(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "ostk.athenz2.cloud", null, null, null, errorMsg));

        // add the same domain to the provider suffix list

        providerDnsSuffixList.add("ostk.athenz.cloud");
        assertTrue(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "ostk.athenz2.cloud", null, null, null, errorMsg));
        assertTrue(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "ostk.athenz.cloud", null, null, null, errorMsg));
        assertTrue(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "", null, null, null, errorMsg));
        assertTrue(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                null, null, null, null, errorMsg));
    }

    @Test
    public void testValidateDnsNamesWithCnameValues() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.cname.csr");
        String csr = new String(Files.readAllBytes(path));
        String service = "athenz.production";

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(Collections.singletonList("ostk.athenz.cloud"));

        List<String> allowedSuffixList = new ArrayList<>();
        allowedSuffixList.add("athenz.info");
        allowedSuffixList.add("athenz.cloud");
        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("provider"))
                .thenReturn(allowedSuffixList);
        Mockito.when(athenzSysDomainCache.getProviderHostnameDeniedSuffixList("provider"))
                .thenReturn(null);

        List<String> cnameList = new ArrayList<>();
        cnameList.add("cname1.athenz.info");
        cnameList.add("cname2.athenz.info");
        HostnameResolver resolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(resolver.isValidHostCnameList(service, "host1.athenz.cloud", cnameList, CertType.X509))
                .thenReturn(false)
                .thenReturn(true);
        Mockito.when(resolver.isValidHostname("host1.athenz.cloud")).thenReturn(true);

        // first call we're going to get failure

        StringBuilder errorMsg = new StringBuilder();
        assertFalse(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "ostk.athenz.cloud", "host1.athenz.cloud", cnameList, resolver, errorMsg));

        // second call is success

        assertTrue(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "ostk.athenz.cloud", "host1.athenz.cloud", cnameList, resolver, errorMsg));
    }

    @Test
    public void testValidateDnsNamesWithCnameValuesWithSameSuffix() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.cname.suffix.csr");
        String csr = new String(Files.readAllBytes(path));
        String service = "athenz.production";

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(Collections.singletonList("ostk.athenz.cloud"));

        List<String> allowedSuffixList = new ArrayList<>();
        allowedSuffixList.add("athenz.info");
        allowedSuffixList.add("athenz.cloud");
        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("provider"))
                .thenReturn(allowedSuffixList);
        Mockito.when(athenzSysDomainCache.getProviderHostnameDeniedSuffixList("provider"))
                .thenReturn(null);

        List<String> cnameList = new ArrayList<>();
        cnameList.add("cname1.ostk.athenz.cloud");
        cnameList.add("cname2.athenz.info");
        HostnameResolver resolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(resolver.isValidHostCnameList(service, "host1.athenz.cloud", cnameList, CertType.X509))
                .thenReturn(true);
        Mockito.when(resolver.isValidHostname("host1.athenz.cloud")).thenReturn(true);

        StringBuilder errorMsg = new StringBuilder();
        assertTrue(certReq.validateDnsNames("athenz", "production", "provider", athenzSysDomainCache,
                "ostk.athenz.cloud", "host1.athenz.cloud", cnameList, resolver, errorMsg));
    }

    @Test
    public void testValidateDnsNamesWithMultipleDomainValues() throws IOException {

        Path path = Paths.get("src/test/resources/multi_dns_domain.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        List<String> providerDnsSuffixList = new ArrayList<>();

        // for the first test we're going to return null
        // and the list for all subsequent tests

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(null)
                .thenReturn(providerDnsSuffixList);

        // only one domain will not match

        StringBuilder errorMsg = new StringBuilder();
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "ostk.athenz.info", null, null, null, errorMsg));

        // only provider suffix list will not match

        providerDnsSuffixList.add("ostk.athenz.cloud");
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                null, null, null, null, errorMsg));

        // specifying both values match

        assertTrue(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "ostk.athenz.info", null, null, null, errorMsg));

        // tests with hostname field

        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", null, null, null, errorMsg));
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "host1.athenz.info", null, null, errorMsg));
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "athenz.ostk.athenz.info", null, null, errorMsg));

        List<String> providerHostnameAllowedSuffixList = new ArrayList<>();
        providerHostnameAllowedSuffixList.add(".ostk.athenz.info");
        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("provider"))
                .thenReturn(providerHostnameAllowedSuffixList);

        assertTrue(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, null, errorMsg));

        // now specify a resolver for the hostname check

        TestHostnameResolver resolver = new TestHostnameResolver();
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, resolver, errorMsg));

        // include resolver with invalid hostname

        resolver.addValidHostname("api1.athenz.ostk.athenz.info");
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, resolver, errorMsg));

        // now add the hostname to the list

        resolver.addValidHostname("api.athenz.ostk.athenz.info");
        assertTrue(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, resolver, errorMsg));
    }


    @Test
    public void testValidateUri() throws IOException {

        Path path = Paths.get("src/test/resources/multi_dns_domain.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        List<String> providerDnsSuffixList = new ArrayList<>();
        providerDnsSuffixList.add("ostk.athenz.cloud");

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(providerDnsSuffixList);

        // both of our lists are null

        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("provider"))
                .thenReturn(null);
        Mockito.when(athenzSysDomainCache.getProviderHostnameDeniedSuffixList("provider"))
                .thenReturn(null);

        // we should get false since we're not allowed

        StringBuilder errorMsg = new StringBuilder();
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, null, errorMsg));
    }


    @Test
    public void testValidateDnsNamesHostnameNullLists() throws IOException {

        Path path = Paths.get("src/test/resources/multi_dns_domain.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        List<String> providerDnsSuffixList = new ArrayList<>();
        providerDnsSuffixList.add("ostk.athenz.cloud");

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(providerDnsSuffixList);

        // both of our lists are null

        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("provider"))
                .thenReturn(null);
        Mockito.when(athenzSysDomainCache.getProviderHostnameDeniedSuffixList("provider"))
                .thenReturn(null);

        // we should get false since we're not allowed

        StringBuilder errorMsg = new StringBuilder();
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, null, errorMsg));
    }

    @Test
    public void testValidateDnsNamesHostnameNotAllowed() throws IOException {

        Path path = Paths.get("src/test/resources/multi_dns_domain.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        List<String> providerDnsSuffixList = new ArrayList<>();
        providerDnsSuffixList.add("ostk.athenz.cloud");

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(providerDnsSuffixList);

        // first we're going to allow a suffix that does not match
        // to our list

        List<String> providerHostnameAllowedSuffixList = new ArrayList<>();
        providerHostnameAllowedSuffixList.add(".ostk.athenz.data");
        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("provider"))
                .thenReturn(providerHostnameAllowedSuffixList);

        StringBuilder errorMsg = new StringBuilder();
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, null, errorMsg));

        // next we're going to add the suffix that matches so we'll get
        // successful response

        providerHostnameAllowedSuffixList.add(".ostk.athenz.info");
        assertTrue(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, null, errorMsg));

        // now we're going to return a denied list but first a value that
        // does not match our hostname

        List<String> providerHostnameDeniedSuffixList = new ArrayList<>();
        providerHostnameDeniedSuffixList.add(".ostk.athenz.data");
        Mockito.when(athenzSysDomainCache.getProviderHostnameDeniedSuffixList("provider"))
                .thenReturn(providerHostnameDeniedSuffixList);

        // since there is no match in our denied list we're going to get
        // a still successful response

        assertTrue(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, null, errorMsg));

        // now we're going to add the suffix to the list and make sure the
        // request is denied

        providerHostnameDeniedSuffixList.add(".ostk.athenz.info");
        assertFalse(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache,
                "zts.athenz.info", "api.athenz.ostk.athenz.info", null, null, errorMsg));
    }

    @Test
    public void testValidateProviderDnsNamesList() throws IOException {

        Path path = Paths.get("src/test/resources/multi_dns_domain.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        // now add the hostname to the list

        List<String> providerDnsSuffixList = new ArrayList<>();
        providerDnsSuffixList.add("ostk.athenz.cloud");

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(providerDnsSuffixList);

        List<String> providerHostnameAllowedSuffixList = new ArrayList<>();
        providerHostnameAllowedSuffixList.add(".ostk.athenz.info");
        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("provider"))
                .thenReturn(providerHostnameAllowedSuffixList);

        StringBuilder errorMsg = new StringBuilder();
        assertTrue(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache, "zts.athenz.info",
                "api.athenz.ostk.athenz.info", null, null, errorMsg));

        List<String> dnsNames = certReq.getProviderDnsNames();
        assertEquals(dnsNames.size(), 2);
        assertTrue(dnsNames.contains("api.athenz.ostk.athenz.info"));
        assertTrue(dnsNames.contains("production.athenz.ostk.athenz.cloud"));
    }

    @Test
    public void testValidateProviderDnsNamesListWithWildcard() throws IOException {

        Path path = Paths.get("src/test/resources/multi_dns_domain_wildcard.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        // now add the hostname to the list

        List<String> providerDnsSuffixList = new ArrayList<>();
        providerDnsSuffixList.add("ostk.athenz.cloud");

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(providerDnsSuffixList);

        StringBuilder errorMsg = new StringBuilder();
        assertTrue(certReq.validateDnsNames("athenz", "api", "provider", athenzSysDomainCache, null,
                null, null, null, errorMsg));

        // we should automatically skip the *.api.athenz
        // dns name from provider dns name review list

        List<String> dnsNames = certReq.getProviderDnsNames();
        assertEquals(dnsNames.size(), 2);
        assertTrue(dnsNames.contains("api.athenz.ostk.athenz.cloud"));
        assertTrue(dnsNames.contains("uuid.instanceid.athenz.ostk.athenz.cloud"));
    }

    @Test
    public void testValidateProviderDnsNamesListWithWildcardMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/multi_dns_domain_wildcard_mismatch.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        // now add the hostname to the list

        List<String> providerDnsSuffixList = new ArrayList<>();
        providerDnsSuffixList.add("ostk.athenz.cloud");

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(providerDnsSuffixList);

        StringBuilder errorMsg = new StringBuilder();
        assertTrue(certReq.validateDnsNames("athenz.prod", "api", "provider", athenzSysDomainCache,
                null, null, null, null, errorMsg));

        // we should automatically skip the *.api.athenz
        // however it doesn't match the prefix so we're going
        // to keep it here and require the provider to verify it

        List<String> dnsNames = certReq.getProviderDnsNames();
        assertEquals(dnsNames.size(), 3);
        assertTrue(dnsNames.contains("api.athenz-prod.ostk.athenz.cloud"));
        assertTrue(dnsNames.contains("*.api.athenz.ostk.athenz.cloud"));
        assertTrue(dnsNames.contains("uuid.instanceid.athenz.ostk.athenz.cloud"));
    }

    @Test
    public void testValidateDnsNamesNoValues() throws IOException {

        Path path = Paths.get("src/test/resources/valid_cn_only.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        Mockito.when(athenzSysDomainCache.getProviderDnsSuffixList("provider"))
                .thenReturn(null);

        StringBuilder errorMsg = new StringBuilder();
        assertTrue(certReq.validateDnsNames("domain", "service1", "provider", athenzSysDomainCache,
                null, null, null, null, errorMsg));
    }

    @Test
    public void testValidateDnsNamesMismatchSize() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.validateDnsNames(cert));
    }
    
    @Test
    public void testValidateDnsNamesMismatchValues() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.mismatch.dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.validateDnsNames(cert));
    }
    
    @Test
    public void testValidatePublicKeysCert() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertTrue(certReq.validatePublicKeys(cert));
    }
    
    @Test
    public void testValidatePublicKeysCertFailure() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        X509Certificate cert = Mockito.mock(X509Certificate.class);
        Mockito.when(cert.getPublicKey()).thenReturn(null);
        
        assertFalse(certReq.validatePublicKeys(cert));
    }
    
    @Test
    public void testValidatePublicKeysCertCSRFailure() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        PKCS10CertificationRequest req = Mockito.mock(PKCS10CertificationRequest.class);
        Mockito.when(req.getSubjectPublicKeyInfo()).thenReturn(null);
        certReq.setCertReq(req);

        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.validatePublicKeys(cert));
    }
    
    @Test
    public void testValidatePublicKeysCertMismatch() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.mismatch.dns.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertFalse(certReq.validatePublicKeys(cert));
    }
    
    @Test
    public void testValidatePublicKeysNull() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        assertFalse(certReq.validatePublicKeys((String) null));
    }
    
    @Test
    public void testValidatePublicKeysFailure() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        PKCS10CertificationRequest req = Mockito.mock(PKCS10CertificationRequest.class);
        Mockito.when(req.getSubjectPublicKeyInfo()).thenReturn(null);
        certReq.setCertReq(req);
        
        assertFalse(certReq.validatePublicKeys("publickey"));
    }
    
    @Test
    public void testValidatePublicKeysString() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        X509CertRequest certReq = new X509CertRequest(csr);
        
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        
        assertTrue(certReq.validatePublicKeys(ztsPublicKey));
    }
    
    @Test
    public void testValidateCertReqPublicKey() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        
        assertTrue(certReq.validatePublicKeys(ztsPublicKey));
    }

    @Test
    public void testValidateCertReqPublicKeyMismatch() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNasdfsdfsadfwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        
        assertFalse(certReq.validatePublicKeys(ztsPublicKey));
    }
    
    @Test
    public void testValidateCertReqPublicKeyWhitespace() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        
        final String ztsPublicKey1 = "   -----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNA QEBBQADSwAwSAJBAKrvfvBgXWqW Aorw5hYJu3dpOJe0gp3n\n\r\r\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n\r"
                + "-----END PUBLIC KEY-----  \n";
        final String ztsPublicKey2 = "-----BEGIN PUBLIC KEY-----"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ=="
                + "-----END PUBLIC KEY-----";
        
        assertTrue(certReq.validatePublicKeys(ztsPublicKey1));
        assertTrue(certReq.validatePublicKeys(ztsPublicKey2));
    }

    @Test
    public void testValidateCertCNFailure() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_cn.csr");
        String csr = new String(Files.readAllBytes(path));

        try {
            new X509CertRequest(csr);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Subject contains multiple values"));
        }
    }

    @Test
    public void testValidateOUFieldCheck() throws IOException {

        // the ou is "Testing Domain"

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        testValidateOUFieldCheck(certReq);

        // the ou is "Testing Domain:restricted" which should
        // behave the same as before

        path = Paths.get("src/test/resources/athenz.instanceid.restricted.csr");
        csr = new String(Files.readAllBytes(path));

        certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        testValidateOUFieldCheck(certReq);
    }

    public void testValidateOUFieldCheck(X509CertRequest certReq) {

        HashSet<String> validOrgUnits = new HashSet<>();

        assertFalse(certReq.validateSubjectOUField(null, null, null));
        assertFalse(certReq.validateSubjectOUField("Testing Domains", null, null));
        assertFalse(certReq.validateSubjectOUField(null, "Testing Domains", null));
        assertFalse(certReq.validateSubjectOUField("Bad1", "Bad2", null));
        assertFalse(certReq.validateSubjectOUField(null, null, validOrgUnits));
        assertFalse(certReq.validateSubjectOUField("Testing Domains", "None Test", validOrgUnits));

        // add invalid entry into set
        validOrgUnits.add("Testing Domains");
        assertFalse(certReq.validateSubjectOUField("Testing Domains", "None Test", validOrgUnits));

        assertTrue(certReq.validateSubjectOUField("Testing Domain", null, null));
        assertTrue(certReq.validateSubjectOUField("Testing Domain", "Bad2", validOrgUnits));

        assertTrue(certReq.validateSubjectOUField(null, "Testing Domain", null));
        assertTrue(certReq.validateSubjectOUField("Bad1", "Testing Domain", validOrgUnits));

        // add valid entry inti set
        validOrgUnits.add("Testing Domain");
        assertTrue(certReq.validateSubjectOUField(null, null, validOrgUnits));
        assertTrue(certReq.validateSubjectOUField("Bad1", "Bad2", validOrgUnits));
    }

    @Test
    public void testValidateOUFieldCheckMissingOU() throws IOException {

        // no ou field available
        Path path = Paths.get("src/test/resources/athenz.single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        HashSet<String> validOrgUnits = new HashSet<>();
        validOrgUnits.add("Athenz");

        assertTrue(certReq.validateSubjectOUField(null, null, null));
        assertTrue(certReq.validateSubjectOUField("Testing Domains", null, null));
        assertTrue(certReq.validateSubjectOUField(null, "Testing Domains", null));
        assertTrue(certReq.validateSubjectOUField("Bad1", "Bad2", null));
        assertTrue(certReq.validateSubjectOUField(null, null, validOrgUnits));
        assertTrue(certReq.validateSubjectOUField("Testing Domains", "None Test", validOrgUnits));
    }

    @Test
    public void testValidateOUFieldCheckInvalidOU() throws IOException {

        // multiple ou field: Athenz and Yahoo which we don't support
        Path path = Paths.get("src/test/resources/athenz.multiple_ou.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        assertFalse(certReq.validateSubjectOUField("Athenz", null, null));
        assertFalse(certReq.validateSubjectOUField("Yahoo", null, null));
    }

    @Test
    public void testExtractInstanceIdURI() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.uri.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        assertEquals(certReq.getInstanceId(), "id-001");
    }

    @Test
    public void testValidateInstanceCnames() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.uri.csr");
        String csr = new String(Files.readAllBytes(path));
        String service = "athenz.api";

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        // cnames null and empty is always true

        StringBuilder errorMsg = new StringBuilder();
        assertTrue(certReq.validateInstanceCnames(null, null, service, null, null, null, errorMsg));
        assertTrue(certReq.validateInstanceCnames(null, null, service, null, Collections.emptyList(), null, errorMsg));

        // if the name is empty or null, then it's failure

        assertFalse(certReq.validateInstanceCnames(null, null, service, null,
                Collections.singletonList("host1.athenz.cloud"), null, errorMsg));
        assertFalse(certReq.validateInstanceCnames(null, null, service, "",
                Collections.singletonList("host1.athenz.cloud"), null, errorMsg));

        DataCache athenzSysDomainCache = Mockito.mock(DataCache.class);
        List<String> providerHostnameAllowedSuffixList = Collections.singletonList("athenz.cloud");
        Mockito.when(athenzSysDomainCache.getProviderHostnameAllowedSuffixList("provider"))
                .thenReturn(providerHostnameAllowedSuffixList);
        List<String> providerHostnameDeniedSuffixList = Collections.singletonList("athenz.info");
        Mockito.when(athenzSysDomainCache.getProviderHostnameDeniedSuffixList("provider"))
                .thenReturn(providerHostnameDeniedSuffixList);

        // cname does not match allowed suffix list thus denied

        assertFalse(certReq.validateInstanceCnames("provider", athenzSysDomainCache, service, "hostname.athenz.cloud",
                Collections.singletonList("host1.athenz.data"), null, errorMsg));

        List<String> cnameList = new ArrayList<>();
        cnameList.add("host1.athenz.cloud");
        cnameList.add("host1.athenz.data");

        assertFalse(certReq.validateInstanceCnames("provider", athenzSysDomainCache, service, "hostname.athenz.cloud",
                cnameList, null, errorMsg));

        // cname is explicitly denied

        assertFalse(certReq.validateInstanceCnames("provider", athenzSysDomainCache, service, "hostname.athenz.cloud",
                Collections.singletonList("host1.athenz.info"), null, errorMsg));

        cnameList.add("host1.athenz.info");
        assertFalse(certReq.validateInstanceCnames("provider", athenzSysDomainCache, service, "hostname.athenz.cloud",
                cnameList, null, errorMsg));

        // no hostname resolver thus denied

        assertFalse(certReq.validateInstanceCnames("provider", athenzSysDomainCache, service, "hostname.athenz.cloud",
                Collections.singletonList("host1.athenz.cloud"), null, errorMsg));

        HostnameResolver resolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(resolver.isValidHostCnameList(service, "hostname.athenz.cloud", Collections.singletonList("host1.athenz.cloud"), CertType.X509))
                .thenReturn(false);

        assertFalse(certReq.validateInstanceCnames("provider", athenzSysDomainCache, service, "hostname.athenz.cloud",
                Collections.singletonList("host1.athenz.cloud"), resolver, errorMsg));

        // set resolver to return true for host2

        Mockito.when(resolver.isValidHostCnameList(service, "hostname.athenz.cloud", Collections.singletonList("host2.athenz.cloud"), CertType.X509))
                .thenReturn(true);

        assertTrue(certReq.validateInstanceCnames("provider", athenzSysDomainCache, service, "hostname.athenz.cloud",
                Collections.singletonList("host2.athenz.cloud"), resolver, errorMsg));
    }
}

