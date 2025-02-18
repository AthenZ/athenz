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
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PublicKeyProvider;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.util.Crypto;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;

import static org.testng.Assert.*;

public class AccessTokenBodyTest {

    @Test
    public void testAccessTokenBody() {

        AccessTokenBody body = new AccessTokenBody("grant_type=client_credentials&scope=coretech:role.writers"
                + "&authorization_details=details&expires_in=100&proxy_principal_spiffe_uris=", null, null);
        assertNotNull(body);
        assertEquals(body.getGrantType(), "client_credentials");
        assertEquals(body.getScope(), "coretech:role.writers");
        assertEquals(body.getAuthzDetails(), "details");
        assertEquals(body.getExpiryTime(), 100);
        assertNull(body.getProxyPrincipalsSpiffeUris());
    }

    @Test
    public void testAccessTokenBodyInvalidGrant() {

        try {
            new AccessTokenBody("grant_type=unknown&scope=coretech:role.writers"
                    + "&authorization_details=details", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid grant request: unknown");
        }
    }

    @Test
    public void testAccessTokenBodyEmptyScope() {

        try {
            new AccessTokenBody("grant_type=client_credentials&scope=&expiry_time=100", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no scope provided");
        }
    }

    @Test
    public void testAccessTokenBodyValidSpiffeUri() {

        // first valid uri test

        AccessTokenBody body = new AccessTokenBody("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service", null, null);
        assertNotNull(body);
        assertEquals(body.getGrantType(), "client_credentials");
        assertEquals(body.getScope(), "test");
        assertEquals(body.getProxyPrincipalsSpiffeUris().size(), 1);
        assertEquals(body.getProxyPrincipalsSpiffeUris().get(0), "spiffe://data/sa/service");

        // uri with leading space

        body = new AccessTokenBody("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris= spiffe://data/sa/service", null, null);
        assertNotNull(body);
        assertEquals(body.getProxyPrincipalsSpiffeUris().get(0), "spiffe://data/sa/service");

        // uri with multiple values

        body = new AccessTokenBody("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service,spiffe://sports/sa/api", null, null);
        assertNotNull(body);
        assertEquals(body.getProxyPrincipalsSpiffeUris().size(), 2);
        assertTrue(body.getProxyPrincipalsSpiffeUris().contains("spiffe://data/sa/service"));
        assertTrue(body.getProxyPrincipalsSpiffeUris().contains("spiffe://sports/sa/api"));

        // uri with spaces around the separator

        body = new AccessTokenBody("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service , spiffe://sports/sa/api", null, null);
        assertNotNull(body);
        assertEquals(body.getProxyPrincipalsSpiffeUris().size(), 2);
        assertTrue(body.getProxyPrincipalsSpiffeUris().contains("spiffe://data/sa/service"));
        assertTrue(body.getProxyPrincipalsSpiffeUris().contains("spiffe://sports/sa/api"));
    }

    @Test
    public void testAccessTokenBodyInvalidSpiffeUri() {
        try {
            new AccessTokenBody("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=https://athenz.io", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: https://athenz.io");
        }

        try {
            new AccessTokenBody("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=spiffe://athenz/sa/service,https://athenz.io", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: https://athenz.io");
        }

        try {
            new AccessTokenBody("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=spiffe://a .io", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: spiffe://a .io");
        }
    }

    @Test
    public void testAccessTokenBodyWithClientAssertionFailures() {

        // missing client assertion type

        try {
            new AccessTokenBody("grant_type=client_credentials&scope=coretech:role.writers"
                    + "&authorization_details=details&expires_in=100&client_assertion=jwt", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no client assertion type provided");
        }

        // unknown client assertion type

        try {
            new AccessTokenBody("grant_type=client_credentials&scope=coretech:role.writers"
                    + "&authorization_details=details&expires_in=100&client_assertion=jwt"
                    + "&client_assertion_type=unknown", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid client assertion type: unknown");
        }

        // invalid token

        PublicKeyProvider publicKeyProvider = Mockito.mock(PublicKeyProvider.class);
        try {
            new AccessTokenBody("grant_type=client_credentials&scope=coretech:role.writers"
                    + "&authorization_details=details&expires_in=100&client_assertion=invalid-token"
                    + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    publicKeyProvider, "https://athenz.io");
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().startsWith("Invalid client assertion: Unable to parse token: "));
        }
    }

    @Test
    public void testAccessTokenBodyWithClientAssertion() throws JOSEException {

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

        PublicKeyProvider publicKeyProvider = Mockito.mock(PublicKeyProvider.class);
        Mockito.when(publicKeyProvider.getServicePublicKey("athenz", "api", "eckey1"))
                .thenReturn(Crypto.loadPublicKey(ecPublicKey));

        AccessTokenBody body = new AccessTokenBody("grant_type=client_credentials&scope=coretech:role.writers"
                        + "&authorization_details=details&expires_in=100&client_assertion=" + token
                        + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                publicKeyProvider, "https://athenz.io/zts/v1");
        assertNotNull(body);
        assertEquals(body.getGrantType(), "client_credentials");
        assertEquals(body.getScope(), "coretech:role.writers");
        assertEquals(body.getAuthzDetails(), "details");
        assertEquals(body.getExpiryTime(), 100);
        assertNull(body.getProxyPrincipalsSpiffeUris());

        Principal principal = body.getPrincipal();
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "athenz");
        assertEquals(principal.getName(), "api");
    }

    @Test
    public void testAccessTokenBodyQueryData() {

        AccessTokenBody body = new AccessTokenBody("grant_type=client_credentials"
                + "&scope=data\ntest\ragain", null, null);
        assertNotNull(body);
        assertEquals(body.getQueryLogData(), "scope=data_test_again");

        // generate a string with 1024 length

        final String scope = "012345678901234".repeat(67);
        body = new AccessTokenBody("grant_type=client_credentials"
                + "&scope=" + scope + "&expires_in=1024", null, null);
        assertEquals(body.getQueryLogData(), "scope=" + scope + "&expires_in=1");
    }
}
