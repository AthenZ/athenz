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
package com.yahoo.athenz.zts.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;

import static org.testng.Assert.*;

public class AccessTokenRequestTest {

    @Test
    public void testAccessTokenRequest() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                + "&authorization_details=details&expires_in=100&proxy_principal_spiffe_uris=", null, null);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "client_credentials");
        assertEquals(request.getScope(), "coretech:role.writers");
        assertEquals(request.getAuthzDetails(), "details");
        assertEquals(request.getExpiryTime(), 100);
        assertNull(request.getProxyPrincipalsSpiffeUris());
    }

    @Test
    public void testAccessTokenRequestInvalidGrant() {

        try {
            new AccessTokenRequest("grant_type=unknown&scope=coretech:role.writers"
                    + "&authorization_details=details", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid grant request: unknown");
        }
    }

    @Test
    public void testAccessTokenRequestEmptyScope() {

        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=&expiry_time=100", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no scope provided");
        }
    }

    @Test
    public void testAccessTokenRequestValidSpiffeUri() {

        // first valid uri test

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service", null, null);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "client_credentials");
        assertEquals(request.getScope(), "test");
        assertEquals(request.getProxyPrincipalsSpiffeUris().size(), 1);
        assertEquals(request.getProxyPrincipalsSpiffeUris().get(0), "spiffe://data/sa/service");

        // uri with leading space

        request = new AccessTokenRequest("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris= spiffe://data/sa/service", null, null);
        assertNotNull(request);
        assertEquals(request.getProxyPrincipalsSpiffeUris().get(0), "spiffe://data/sa/service");

        // uri with multiple values

        request = new AccessTokenRequest("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service,spiffe://sports/sa/api", null, null);
        assertNotNull(request);
        assertEquals(request.getProxyPrincipalsSpiffeUris().size(), 2);
        assertTrue(request.getProxyPrincipalsSpiffeUris().contains("spiffe://data/sa/service"));
        assertTrue(request.getProxyPrincipalsSpiffeUris().contains("spiffe://sports/sa/api"));

        // uri with spaces around the separator

        request = new AccessTokenRequest("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service , spiffe://sports/sa/api", null, null);
        assertNotNull(request);
        assertEquals(request.getProxyPrincipalsSpiffeUris().size(), 2);
        assertTrue(request.getProxyPrincipalsSpiffeUris().contains("spiffe://data/sa/service"));
        assertTrue(request.getProxyPrincipalsSpiffeUris().contains("spiffe://sports/sa/api"));
    }

    @Test
    public void testAccessTokenRequestInvalidSpiffeUri() {
        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=https://athenz.io", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: https://athenz.io");
        }

        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=spiffe://athenz/sa/service,https://athenz.io", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: https://athenz.io");
        }

        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=spiffe://a .io", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: spiffe://a .io");
        }
    }

    @Test
    public void testAccessTokenRequestWithClientAssertionFailures() {

        // missing client assertion type

        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                    + "&authorization_details=details&expires_in=100&client_assertion=jwt", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no client assertion type provided");
        }

        // unknown client assertion type

        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                    + "&authorization_details=details&expires_in=100&client_assertion=jwt"
                    + "&client_assertion_type=unknown", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid client assertion type: unknown");
        }

        // invalid token

        KeyStore publicKeyProvider = Mockito.mock(KeyStore.class);
        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                    + "&authorization_details=details&expires_in=100&client_assertion=invalid-token"
                    + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    publicKeyProvider, "https://athenz.io");
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().startsWith("Invalid client assertion: Unable to parse token: "));
        }
    }

    @Test
    public void testAccessTokenRequestWithClientAssertion() throws JOSEException {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        final File ecPublicKey = new File("./src/test/resources/zts_public_ec.pem");

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("athenz.api")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .issuer("athenz.api")
                .audience("https://athenz.io/zts/v1")
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        KeyStore publicKeyProvider = Mockito.mock(KeyStore.class);
        Mockito.when(publicKeyProvider.getServicePublicKey("athenz", "api", "eckey1"))
                .thenReturn(Crypto.loadPublicKey(ecPublicKey));

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                        + "&authorization_details=details&expires_in=100&client_assertion=" + token
                        + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                publicKeyProvider, "https://athenz.io/zts/v1");
        assertNotNull(request);
        assertEquals(request.getGrantType(), "client_credentials");
        assertEquals(request.getScope(), "coretech:role.writers");
        assertEquals(request.getAuthzDetails(), "details");
        assertEquals(request.getExpiryTime(), 100);
        assertNull(request.getProxyPrincipalsSpiffeUris());

        Principal principal = request.getPrincipal();
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "athenz");
        assertEquals(principal.getName(), "api");
    }

    @Test
    public void testAccessTokenRequestQueryData() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=data\ntest\ragain", null, null);
        assertNotNull(request);
        assertEquals(request.getQueryLogData(), "scope=data%0Atest%0Dagain");

        // generate a string with 1024 length

        final String scope = "012345678901234".repeat(67);
        request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=" + scope + "&expires_in=1024", null, null);
        assertEquals(request.getQueryLogData(), "scope=" + scope + "&expires_in=1");
    }
}
