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
package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class InstanceGithubActionsPropTest {

    private InstanceGithubActionsProp instanceGithubActionsProp;

    @BeforeMethod
    public void setUp() {
        instanceGithubActionsProp = new InstanceGithubActionsProp();
    }

    @Test
    public void testAddPropertiesAndGetters() {
        String issuer = "testIssuer";
        String providerDnsSuffix = "testDnsSuffix";
        String audience = "testAudience";
        String enterprise = "testEnterprise";
        String jwksUri = "https://example.com/jwks";

        instanceGithubActionsProp.addProperties(issuer, providerDnsSuffix, audience, enterprise, jwksUri);

        assertEquals(instanceGithubActionsProp.getProviderDnsSuffix(issuer), providerDnsSuffix);
        assertEquals(instanceGithubActionsProp.getAudience(issuer), audience);
        assertEquals(instanceGithubActionsProp.getEnterprise(issuer), enterprise);
        assertEquals(instanceGithubActionsProp.getJwksUri(issuer), jwksUri);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = instanceGithubActionsProp.getJwtProcessor(issuer);
        assertNotNull(jwtProcessor);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testAddPropertiesWithNullIssuer() {
        instanceGithubActionsProp.addProperties(null, "dnsSuffix", "audience", "enterprise", "https://example.com/jwks");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testAddPropertiesWithNullProviderDnsSuffix() {
        instanceGithubActionsProp.addProperties("issuer", null, "audience", "enterprise", "https://example.com/jwks");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testAddPropertiesWithNullAudience() {
        instanceGithubActionsProp.addProperties("issuer", "dnsSuffix", null, "enterprise", "https://example.com/jwks");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testAddPropertiesWithNullJwksUri() {
        instanceGithubActionsProp.addProperties("issuer", "dnsSuffix", "audience", "enterprise", null);
    }

    @Test
    public void testHasIssuer() {
        String issuer = "testIssuer";
        instanceGithubActionsProp.addProperties(issuer, "dnsSuffix", "audience", "enterprise", "https://example.com/jwks");

        assertTrue(instanceGithubActionsProp.hasIssuer(issuer));
        assertFalse(instanceGithubActionsProp.hasIssuer("nonExistentIssuer"));
    }

    @Test
    public void testGettersReturnNullForNonExistentIssuer() {
        String nonExistentIssuer = "nonExistentIssuer";

        assertFalse(instanceGithubActionsProp.hasIssuer(nonExistentIssuer));
        assertFalse(instanceGithubActionsProp.hasIssuer(""));
        assertFalse(instanceGithubActionsProp.hasIssuer(null));
        assertNull(instanceGithubActionsProp.getProviderDnsSuffix(nonExistentIssuer));
        assertNull(instanceGithubActionsProp.getAudience(nonExistentIssuer));
        assertNull(instanceGithubActionsProp.getEnterprise(nonExistentIssuer));
        assertNull(instanceGithubActionsProp.getJwksUri(nonExistentIssuer));
        assertNull(instanceGithubActionsProp.getJwtProcessor(nonExistentIssuer));
    }

    @Test
    public void testHasEnterprise() {
        String issuer = "testIssuer";
        instanceGithubActionsProp.addProperties(issuer, "dnsSuffix", "audience", "enterprise", "https://example.com/jwks");

        assertTrue(instanceGithubActionsProp.hasEnterprise(issuer));
        assertFalse(instanceGithubActionsProp.hasEnterprise("nonExistentIssuer"));
    }

    @Test
    public void testHasInitializedJwtProcessor() {
        String issuer = "testIssuer";
        instanceGithubActionsProp.addProperties(issuer, "dnsSuffix", "audience", "enterprise", "https://example.com/jwks");

        assertTrue(instanceGithubActionsProp.hasInitializedJwtProcessor());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testAddPropertiesWithNullValues() {
        instanceGithubActionsProp.addProperties(null, "dnsSuffix", "audience", "enterprise", "https://example.com/jwks");
    }
}
