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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.testng.Assert.*;

import com.yahoo.athenz.common.server.dns.HostnameResolver;
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
    public void testParseCertRequest() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        assertTrue(certReq.parseCertRequest(errorMsg));
    }
    
    @Test
    public void testParseCertRequestIPs() throws IOException {
        Path path = Paths.get("src/test/resources/multiple_ips.csr");
        String csr = new String(Files.readAllBytes(path));
        
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        StringBuilder errorMsg = new StringBuilder(256);
        assertTrue(certReq.parseCertRequest(errorMsg));
        
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
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        assertFalse(certReq.parseCertRequest(errorMsg));
    }
    
    @Test
    public void testValidateCommonName() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);

        assertTrue(certReq.validateCommonName("athenz.production"));
        assertEquals(certReq.getCommonName(), "athenz.production");
        
        assertFalse(certReq.validateCommonName("sys.production"));
        assertFalse(certReq.validateCommonName("athenz.storage"));
    }
    
    @Test
    public void testInstanceId() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);

        assertEquals(certReq.getInstanceId(), "1001");
    }

    @Test
    public void testValidateDnsNamesWithCert() throws IOException {
        
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));
        
        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);
        
        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        assertTrue(certReq.validateDnsNames(cert));
    }

    @Test
    public void testValidateDnsNamesWithValues() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);

        assertTrue(certReq.validateDnsNames(null, "ostk.athenz.cloud", null, null));

        // empty provider suffix list

        List<String> providerDnsSuffixList = new ArrayList<>();
        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, "ostk.athenz.cloud", null, null));

        // provider suffix list with no match

        providerDnsSuffixList.add("ostk.myathenz.cloud");
        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, "ostk.athenz.cloud", null, null));
        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, "ostk.athenz.cloud", "host1.athenz.cloud", null));

        // no match if service list does not match

        assertFalse(certReq.validateDnsNames(providerDnsSuffixList, "ostk.athenz2.cloud", null, null));

        // add the same domain to the provider suffix list

        providerDnsSuffixList.add("ostk.athenz.cloud");
        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, "ostk.athenz2.cloud", null, null));
        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, "ostk.athenz.cloud", null, null));
        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, "", null, null));
        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, null, null, null));
    }

    @Test
    public void testValidateDnsNamesWithMultipleDomainValues() throws IOException {

        Path path = Paths.get("src/test/resources/multi_dns_domain.csr");
        String csr = new String(Files.readAllBytes(path));

        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);

        // only one domain will not match

        assertFalse(certReq.validateDnsNames(null, "ostk.athenz.info", null, null));

        // only provider suffix list will not match

        List<String> providerDnsSuffixList = new ArrayList<>();
        providerDnsSuffixList.add("ostk.athenz.cloud");
        assertFalse(certReq.validateDnsNames(providerDnsSuffixList, null, null, null));

        // specifying both values match

        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, "ostk.athenz.info", null, null));

        // tests with hostname field

        assertFalse(certReq.validateDnsNames(providerDnsSuffixList, "zts.athenz.info", null, null));
        assertFalse(certReq.validateDnsNames(providerDnsSuffixList, "zts.athenz.info",
                "host1.athenz.info", null));
        assertFalse(certReq.validateDnsNames(providerDnsSuffixList, "zts.athenz.info",
                "athenz.ostk.athenz.info", null));
        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, "zts.athenz.info",
                "api.athenz.ostk.athenz.info", null));

        // now specify a resolver for the hostname check

        HostnameResolver resolver = new TestHostnameResolver();
        assertFalse(certReq.validateDnsNames(providerDnsSuffixList, "zts.athenz.info",
                "api.athenz.ostk.athenz.info", resolver));

        // include resolver with invalid hostname

        ((TestHostnameResolver) resolver).addValidHostname("api1.athenz.ostk.athenz.info");
        assertFalse(certReq.validateDnsNames(providerDnsSuffixList, "zts.athenz.info",
                "api.athenz.ostk.athenz.info", resolver));

        // now add the hostname to the list

        ((TestHostnameResolver) resolver).addValidHostname("api.athenz.ostk.athenz.info");
        assertTrue(certReq.validateDnsNames(providerDnsSuffixList, "zts.athenz.info",
                "api.athenz.ostk.athenz.info", resolver));
    }

    @Test
    public void testValidateDnsNamesNoValues() throws IOException {

        Path path = Paths.get("src/test/resources/valid_cn_only.csr");
        String csr = new String(Files.readAllBytes(path));

        StringBuilder errorMsg = new StringBuilder(256);
        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.parseCertRequest(errorMsg);

        assertTrue(certReq.validateDnsNames(null, null, null, null));
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
    public void testValidateSpiffeURINoValues() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertTrue(certReq.validateSpiffeURI("domain", "sa", "api"));
    }

    @Test
    public void testValidateSpiffeURIMultipleValues() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        try {
            new X509CertRequest(csr);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid SPIFFE URI present"));
        }
    }

    @Test
    public void testValidateSpiffeURI() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_role.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertTrue(certReq.validateSpiffeURI("coretech", "ra", "api"));
        assertFalse(certReq.validateSpiffeURI("coretech", "ra", "backend"));
        assertFalse(certReq.validateSpiffeURI("coretech", "sa", "api"));
    }

    @Test
    public void testValidateOUFieldCheck() throws IOException {

        // the ou is "Testing Domain"

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

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

        StringBuilder errMsg = new StringBuilder();
        assertTrue(certReq.parseCertRequest(errMsg));
        assertEquals(certReq.getInstanceId(), "id-001");
    }
}

