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

    @Test
    public void testAccessTokenRequestQueryDataWithAllFields() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=test&expires_in=100&proxy_for_principal=user.joe"
                + "&authorization_details=details&proxy_principal_spiffe_uris=spiffe://data/sa/service,spiffe://sports/sa/api", null, null);
        String queryData = request.getQueryLogData();
        assertNotNull(queryData);
        assertTrue(queryData.contains("scope=test"));
        assertTrue(queryData.contains("expires_in=100"));
        assertTrue(queryData.contains("proxy_for_principal=user.joe"));
        assertTrue(queryData.contains("authorization_details=details"));
        assertTrue(queryData.contains("proxy_principal_spiffe_uris="));
        assertTrue(queryData.contains("spiffe%3A%2F%2Fdata%2Fsa%2Fservice"));
        assertTrue(queryData.contains("spiffe%3A%2F%2Fsports%2Fsa%2Fapi"));
    }

    @Test
    public void testAccessTokenRequestWithProxyForPrincipal() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=test&proxy_for_principal=user.joe", null, null);
        assertNotNull(request);
        assertEquals(request.getProxyForPrincipal(), "user.joe");
        assertEquals(request.getScope(), "test");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.ACCESS_TOKEN);
    }

    @Test
    public void testAccessTokenRequestWithOpenIDIssuer() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=test&openid_issuer=true", null, null);
        assertNotNull(request);
        assertTrue(request.isUseOpenIDIssuer());

        request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=test&openid_issuer=false", null, null);
        assertNotNull(request);
        assertFalse(request.isUseOpenIDIssuer());

        request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=test&openid_issuer=invalid", null, null);
        assertNotNull(request);
        assertFalse(request.isUseOpenIDIssuer());
    }

    @Test
    public void testAccessTokenRequestInvalidComponentParsing() {

        // component without separator
        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test&invalid", null, null);
        assertNotNull(request);
        assertEquals(request.getScope(), "test");

        // component with invalid URL encoding in key
        request = new AccessTokenRequest("grant_type=client_credentials&scope=test&%ZZ=value", null, null);
        assertNotNull(request);
        assertEquals(request.getScope(), "test");

        // component with invalid URL encoding in value
        request = new AccessTokenRequest("grant_type=client_credentials&scope=test&extra=%ZZ", null, null);
        assertNotNull(request);
        assertEquals(request.getScope(), "test");
    }

    @Test
    public void testAccessTokenRequestTokenExchange() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                + "&audience=sports&subject_token=token123"
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", null, null);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "urn:ietf:params:oauth:grant-type:token-exchange");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.JAG_TOKEN_EXCHANGE);
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithResource() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                + "&audience=sports&resource=data&subject_token=token123"
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", null, null);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "urn:ietf:params:oauth:grant-type:token-exchange");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.JAG_TOKEN_EXCHANGE);
    }

    @Test
    public void testAccessTokenRequestTokenExchangeInvalidRequestedTokenType() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=invalid"
                    + "&audience=sports&subject_token=token123"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid requested token type: invalid");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeMissingRequestedTokenType() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&audience=sports&subject_token=token123"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().startsWith("Invalid requested token type:"));
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeMissingAudience() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                    + "&subject_token=token123"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no audience provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeEmptyAudience() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                    + "&audience=&subject_token=token123"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no audience provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeMissingSubjectToken() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                    + "&audience=sports"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no subject token provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeEmptySubjectToken() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                    + "&audience=sports&subject_token="
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no subject token provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeInvalidSubjectTokenType() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                    + "&audience=sports&subject_token=token123"
                    + "&subject_token_type=invalid", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid subject token type: invalid");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeMissingSubjectTokenType() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                    + "&audience=sports&subject_token=token123", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().startsWith("Invalid subject token type:"));
        }
    }

    @Test
    public void testAccessTokenRequestMissingScope() {

        try {
            new AccessTokenRequest("grant_type=client_credentials", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no scope provided");
        }
    }

    @Test
    public void testAccessTokenRequestNullPrincipal() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test", null, null);
        assertNotNull(request);
        assertNull(request.getPrincipal());
    }

    @Test
    public void testAccessTokenRequestGettersWithDefaults() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test", null, null);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "client_credentials");
        assertEquals(request.getScope(), "test");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.ACCESS_TOKEN);
        assertNull(request.getProxyForPrincipal());
        assertNull(request.getAuthzDetails());
        assertNull(request.getProxyPrincipalsSpiffeUris());
        assertEquals(request.getExpiryTime(), 0);
        assertFalse(request.isUseOpenIDIssuer());
        assertNull(request.getPrincipal());
    }

    @Test
    public void testAccessTokenRequestQueryDataWithEmptyProxyPrincipalsSpiffeUris() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=", null, null);
        String queryData = request.getQueryLogData();
        assertNotNull(queryData);
        assertTrue(queryData.contains("scope=test"));
        assertFalse(queryData.contains("proxy_principal_spiffe_uris="));
    }

    @Test
    public void testAccessTokenRequestQueryDataNoExpiryTime() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test", null, null);
        String queryData = request.getQueryLogData();
        assertNotNull(queryData);
        assertTrue(queryData.contains("scope=test"));
        assertFalse(queryData.contains("expires_in="));
    }

    @Test
    public void testAccessTokenRequestJWTBearer() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
                + "&assertion=jwt-token-value"
                + "&scope=test&resource=data", null, null);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "urn:ietf:params:oauth:grant-type:jwt-bearer");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.JWT_BEARER);
        assertEquals(request.getAssertion(), "jwt-token-value");
        assertEquals(request.getScope(), "test");
        assertEquals(request.getResource(), "data");
    }

    @Test
    public void testAccessTokenRequestJWTBearerMissingAssertion() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
                    + "&scope=test", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no assertion provided");
        }
    }

    @Test
    public void testAccessTokenRequestJWTBearerEmptyAssertion() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
                    + "&assertion=&scope=test", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no assertion provided");
        }
    }

    @Test
    public void testAccessTokenRequestNoGrantType() {

        try {
            new AccessTokenRequest("scope=test", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no grant type provided");
        }
    }

    @Test
    public void testAccessTokenRequestEmptyGrantType() {

        try {
            new AccessTokenRequest("grant_type=&scope=test", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no grant type provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeGetters() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                + "&audience=sports&subject_token=token123"
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                + "&actor_token=actor123&actor_token_type=urn:ietf:params:oauth:token-type:id_token", null, null);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "urn:ietf:params:oauth:grant-type:token-exchange");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.JAG_TOKEN_EXCHANGE);
        assertEquals(request.getRequestedTokenType(), "urn:ietf:params:oauth:token-type:id-jag ");
        assertEquals(request.getAudience(), "sports");
        assertEquals(request.getSubjectToken(), "token123");
        assertEquals(request.getSubjectTokenType(), "urn:ietf:params:oauth:token-type:id_token");
        assertEquals(request.getActorToken(), "actor123");
        assertEquals(request.getActorTokenType(), "urn:ietf:params:oauth:token-type:id_token");
    }

    @Test
    public void testAccessTokenRequestWithClientAssertionGetters() throws JOSEException {

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
                        + "&client_assertion=" + token
                        + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                publicKeyProvider, "https://athenz.io/zts/v1");
        assertNotNull(request);
        assertEquals(request.getClientAssertion(), token);
        assertEquals(request.getClientAssertionType(), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    }

    @Test
    public void testAccessTokenRequestInvalidExpiryTime() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test&expires_in=invalid", null, null);
        assertNotNull(request);
        assertEquals(request.getExpiryTime(), 0);
    }

    @Test
    public void testAccessTokenRequestUpperCaseValues() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=CLIENT_CREDENTIALS&scope=TEST:ROLE.WRITERS"
                + "&proxy_for_principal=USER.JOE", null, null);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "client_credentials");
        assertEquals(request.getScope(), "test:role.writers");
        assertEquals(request.getProxyForPrincipal(), "user.joe");
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithActorToken() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag "
                + "&audience=sports&subject_token=token123"
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                + "&actor_token=actor123&actor_token_type=actor_type", null, null);
        assertNotNull(request);
        assertEquals(request.getActorToken(), "actor123");
        assertEquals(request.getActorTokenType(), "actor_type");
    }
}
