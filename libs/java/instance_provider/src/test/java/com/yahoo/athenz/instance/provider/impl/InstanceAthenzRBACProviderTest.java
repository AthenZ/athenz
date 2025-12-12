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
 * distributed under the License is distributed on "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.instance.provider.impl;

import java.util.*;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.*;
import static org.testng.Assert.*;

public class InstanceAthenzRBACProviderTest {

    private static final String TEST_ISSUER_DN = "CN=Test Issuer,OU=Test,O=Athenz";
    private static final String TEST_SUBJECT_DN = "CN=athenz.service,OU=Test,O=Athenz";

    private InstanceAthenzRBACProvider provider;

    @BeforeMethod
    public void setUp() {
        provider = new InstanceAthenzRBACProvider();
        System.clearProperty(InstanceAthenzRBACProvider.ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST);
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(InstanceAthenzRBACProvider.ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST);
    }

    @Test
    public void testGetProviderScheme() {
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
    }

    @Test
    public void testInitializeWithoutIssuerList() {
        provider.initialize("test-provider", "class://test", null, null);
        assertNull(provider.issuerDNs);
        assertEquals(provider.provider, "test-provider");
        assertEquals(provider.getSVIDType(), InstanceProvider.SVIDType.JWT);
    }

    @Test
    public void testInitializeWithIssuerList() {
        System.setProperty(InstanceAthenzRBACProvider.ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST,
                TEST_ISSUER_DN + ";CN=Another Issuer,OU=Test");
        provider.initialize("test-provider", "class://test", null, null);
        assertNotNull(provider.issuerDNs);
        assertEquals(provider.issuerDNs.size(), 2);
        assertTrue(provider.issuerDNs.contains(TEST_ISSUER_DN));
        assertEquals(provider.provider, "test-provider");
    }

    @Test
    public void testInitializeWithEmptyIssuerList() {
        System.setProperty(InstanceAthenzRBACProvider.ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST, "");
        provider.initialize("test-provider", "class://test", null, null);
        assertNull(provider.issuerDNs);
    }

    @Test
    public void testSetAuthorizer() {
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);
        assertEquals(provider.authorizer, authorizer);
    }

    @Test
    public void testConfirmInstanceWithoutAuthorizer() {
        provider.initialize("test-provider", "class://test", null, null);
        InstanceConfirmation confirmation = createBasicConfirmation("athenz", "service",
                TEST_ISSUER_DN, TEST_SUBJECT_DN);

        try {
            provider.confirmInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Authorizer not available"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutIssuerDN() {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = createBasicConfirmation("athenz", "service",
                null, TEST_SUBJECT_DN);

        try {
            provider.confirmInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Invalid issuer DN"));
        }
    }

    @Test
    public void testConfirmInstanceWithIssuerDNNotInList() {
        System.setProperty(InstanceAthenzRBACProvider.ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST,
                "CN=Other Issuer,OU=Test");
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = createBasicConfirmation("athenz", "service",
                TEST_ISSUER_DN, TEST_SUBJECT_DN);

        try {
            provider.confirmInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Invalid issuer DN"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutSubjectDN() {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = createBasicConfirmation("athenz", "service",
                TEST_ISSUER_DN, null);

        try {
            provider.confirmInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("No certificate subject DN provided"));
        }
    }

    @Test
    public void testConfirmInstanceWithEmptySubjectDN() {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = createBasicConfirmation("athenz", "service",
                TEST_ISSUER_DN, "");

        try {
            provider.confirmInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("No certificate subject DN provided"));
        }
    }

    @Test
    public void testConfirmInstanceWithInvalidCNFormat() {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String invalidSubjectDN = "CN=invalid-cn-without-dot,OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("athenz", "service",
                TEST_ISSUER_DN, invalidSubjectDN);

        try {
            provider.confirmInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Invalid certificate subject CN"));
        }
    }

    @Test
    public void testConfirmInstanceWithSubjectDNMissingCN() {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String subjectDNWithoutCN = "OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("athenz", "service",
                TEST_ISSUER_DN, subjectDNWithoutCN);

        try {
            provider.confirmInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Unable to extract certificate subject CN"));
        }
    }

    @Test
    public void testConfirmInstanceWithAuthorizationFailure() {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String subjectDN = "CN=athenz.service,OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("sports", "api",
                TEST_ISSUER_DN, subjectDN);

        Principal principal = SimplePrincipal.create("athenz", "service", (String) null);
        String resource = "sports:service.api";
        Mockito.when(authorizer.access(eq(InstanceAthenzRBACProvider.ATHENZ_RBAC_ACTION),
                eq(resource), eq(principal), isNull())).thenReturn(false);

        try {
            provider.confirmInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("not authorized to assume identity"));
            assertTrue(ex.getMessage().contains("athenz.service"));
            assertTrue(ex.getMessage().contains("sports.api"));
        }
    }

    @Test
    public void testConfirmInstanceSuccess() throws ProviderResourceException {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String subjectDN = "CN=athenz.service,OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("sports", "api",
                TEST_ISSUER_DN, subjectDN);

        Principal principal = SimplePrincipal.create("athenz", "service", (String) null);
        String resource = "sports:service.api";
        Mockito.when(authorizer.access(eq(InstanceAthenzRBACProvider.ATHENZ_RBAC_ACTION),
                eq(resource), eq(principal), isNull())).thenReturn(true);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertNotNull(result);
        assertEquals(result.getDomain(), "sports");
        assertEquals(result.getService(), "api");
    }

    @Test
    public void testConfirmInstanceSuccessWithIssuerDNInList() throws ProviderResourceException {
        System.setProperty(InstanceAthenzRBACProvider.ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST,
                TEST_ISSUER_DN + ";CN=Another Issuer,OU=Test");
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String subjectDN = "CN=athenz.service,OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("sports", "api",
                TEST_ISSUER_DN, subjectDN);

        Principal principal = SimplePrincipal.create("athenz", "service", (String) null);
        String resource = "sports:service.api";
        Mockito.when(authorizer.access(eq(InstanceAthenzRBACProvider.ATHENZ_RBAC_ACTION),
                eq(resource), eq(principal), isNull())).thenReturn(true);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertNotNull(result);
    }

    @Test
    public void testConfirmInstanceSuccessWithoutIssuerDNList() throws ProviderResourceException {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String subjectDN = "CN=athenz.service,OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("sports", "api",
                TEST_ISSUER_DN, subjectDN);

        Principal principal = SimplePrincipal.create("athenz", "service", (String) null);
        String resource = "sports:service.api";
        Mockito.when(authorizer.access(eq(InstanceAthenzRBACProvider.ATHENZ_RBAC_ACTION),
                eq(resource), eq(principal), isNull())).thenReturn(true);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertNotNull(result);
    }

    @Test
    public void testConfirmInstanceWithComplexDomainAndService() throws ProviderResourceException {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String subjectDN = "CN=coretech.weather,OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("sports", "api",
                TEST_ISSUER_DN, subjectDN);

        Principal principal = SimplePrincipal.create("coretech", "weather", (String) null);
        String resource = "sports:service.api";
        Mockito.when(authorizer.access(eq(InstanceAthenzRBACProvider.ATHENZ_RBAC_ACTION),
                eq(resource), eq(principal), isNull())).thenReturn(true);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertNotNull(result);
    }

    @Test
    public void testRefreshInstance() {
        provider.initialize("test-provider", "class://test", null, null);
        InstanceConfirmation confirmation = new InstanceConfirmation();

        try {
            provider.refreshInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("JWT SVIDs cannot be refreshed"));
        }
    }

    @Test
    public void testValidateIssuerWithoutIssuerDN() {
        provider.initialize("test-provider", "class://test", null, null);
        Map<String, String> attributes = new HashMap<>();

        boolean result = provider.validateIssuer(attributes);
        assertFalse(result);
    }

    @Test
    public void testValidateIssuerWithEmptyIssuerDN() {
        provider.initialize("test-provider", "class://test", null, null);
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, "");

        boolean result = provider.validateIssuer(attributes);
        assertFalse(result);
    }

    @Test
    public void testValidateIssuerWithoutIssuerDNList() {
        provider.initialize("test-provider", "class://test", null, null);
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, TEST_ISSUER_DN);

        boolean result = provider.validateIssuer(attributes);
        assertTrue(result);
    }

    @Test
    public void testValidateIssuerWithIssuerDNInList() {
        System.setProperty(InstanceAthenzRBACProvider.ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST,
                TEST_ISSUER_DN + ";CN=Another Issuer,OU=Test");
        provider.initialize("test-provider", "class://test", null, null);
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, TEST_ISSUER_DN);

        boolean result = provider.validateIssuer(attributes);
        assertTrue(result);
    }

    @Test
    public void testValidateIssuerWithIssuerDNNotInList() {
        System.setProperty(InstanceAthenzRBACProvider.ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST,
                "CN=Other Issuer,OU=Test");
        provider.initialize("test-provider", "class://test", null, null);
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, TEST_ISSUER_DN);

        boolean result = provider.validateIssuer(attributes);
        assertFalse(result);
    }

    @Test
    public void testValidateIssuerWithMultipleIssuersInList() {
        String issuer1 = "CN=Issuer1,OU=Test";
        String issuer2 = "CN=Issuer2,OU=Test";
        System.setProperty(InstanceAthenzRBACProvider.ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST,
                issuer1 + ";" + issuer2);
        provider.initialize("test-provider", "class://test", null, null);

        Map<String, String> attributes1 = new HashMap<>();
        attributes1.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, issuer1);
        assertTrue(provider.validateIssuer(attributes1));

        Map<String, String> attributes2 = new HashMap<>();
        attributes2.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, issuer2);
        assertTrue(provider.validateIssuer(attributes2));
    }

    @Test
    public void testParseDnList() {
        provider.initialize("test-provider", "class://test", null, null);
        List<String> dnList = Arrays.asList(
                "CN=Test Issuer,OU=Test,O=Athenz",
                "CN=Another Issuer,OU=Test,O=Athenz"
        );

        Set<String> result = provider.parseDnList(dnList);
        assertNotNull(result);
        assertEquals(result.size(), 2);
        assertTrue(result.contains("CN=Test Issuer,OU=Test,O=Athenz"));
        assertTrue(result.contains("CN=Another Issuer,OU=Test,O=Athenz"));
    }

    @Test
    public void testParseDnListWithEmptyList() {
        provider.initialize("test-provider", "class://test", null, null);
        List<String> dnList = List.of();

        Set<String> result = provider.parseDnList(dnList);
        assertNotNull(result);
        assertEquals(result.size(), 0);
    }

    @Test
    public void testParseDnListWithSingleDN() {
        provider.initialize("test-provider", "class://test", null, null);
        List<String> dnList = List.of("CN=Single Issuer,OU=Test");

        Set<String> result = provider.parseDnList(dnList);
        assertNotNull(result);
        assertEquals(result.size(), 1);
        assertTrue(result.contains("CN=Single Issuer,OU=Test"));
    }

    @Test
    public void testForbiddenError() {
        provider.initialize("test-provider", "class://test", null, null);
        String errorMessage = "Test error message";

        ProviderResourceException ex = provider.forbiddenError(errorMessage);
        assertNotNull(ex);
        assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
        assertTrue(ex.getMessage().contains(errorMessage));
    }

    @Test
    public void testConfirmInstanceWithCNAtStart() throws ProviderResourceException {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String subjectDN = "CN=test.service,OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("domain", "svc",
                TEST_ISSUER_DN, subjectDN);

        Principal principal = SimplePrincipal.create("test", "service", (String) null);
        String resource = "domain:service.svc";
        Mockito.when(authorizer.access(eq(InstanceAthenzRBACProvider.ATHENZ_RBAC_ACTION),
                eq(resource), eq(principal), isNull())).thenReturn(true);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertNotNull(result);
    }

    @Test
    public void testConfirmInstanceWithCNContainingMultipleDots() throws ProviderResourceException {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String subjectDN = "CN=sub.domain.service,OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("target", "api",
                TEST_ISSUER_DN, subjectDN);

        Principal principal = SimplePrincipal.create("sub.domain", "service", (String) null);
        String resource = "target:service.api";
        Mockito.when(authorizer.access(eq(InstanceAthenzRBACProvider.ATHENZ_RBAC_ACTION),
                eq(resource), eq(principal), isNull())).thenReturn(true);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertNotNull(result);
    }

    @Test
    public void testConfirmInstanceWithCNLastDotAtEnd() {
        provider.initialize("test-provider", "class://test", null, null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        String subjectDN = "CN=domain.,OU=Test,O=Athenz";
        InstanceConfirmation confirmation = createBasicConfirmation("target", "api",
                TEST_ISSUER_DN, subjectDN);

        try {
            provider.confirmInstance(confirmation);
            fail("Should have thrown ProviderResourceException");
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Invalid certificate subject CN"));
        }
    }

    private InstanceConfirmation createBasicConfirmation(String domain, String service,
                                                         String issuerDN, String subjectDN) {
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain(domain);
        confirmation.setService(service);

        Map<String, String> attributes = new HashMap<>();
        if (issuerDN != null) {
            attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN, issuerDN);
        }
        if (subjectDN != null) {
            attributes.put(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN, subjectDN);
        }
        confirmation.setAttributes(attributes);

        return confirmation;
    }
}

