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

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import org.eclipse.jetty.util.StringUtil;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Objects;
import java.util.Set;

import static org.testng.Assert.*;

public class AccessTokenRequestTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    private TokenConfigOptions defaultConfigOptions = null;
    
    @BeforeMethod
    public void setup() {
        defaultConfigOptions = new TokenConfigOptions();
        defaultConfigOptions.setPublicKeyProvider(null);
        defaultConfigOptions.setOauth2Issuers(null);
        defaultConfigOptions.setJwtJAGProcessor(createJAGProcessor());
        defaultConfigOptions.setJwtIDTProcessor(createIDTokenProcessor());
    }
    
    @Test
    public void testAccessTokenRequest() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                + "&authorization_details=details&expires_in=100&proxy_principal_spiffe_uris=&actor=athenz.api",
                defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "client_credentials");
        assertEquals(request.getScope(), "coretech:role.writers");
        assertEquals(request.getAuthzDetails(), "details");
        assertEquals(request.getExpiryTime(), 100);
        assertNull(request.getProxyPrincipalsSpiffeUris());
        assertEquals(request.getActor(), "athenz.api");
    }

    @Test
    public void testAccessTokenRequestInvalidGrant() {

        try {
            new AccessTokenRequest("grant_type=unknown&scope=coretech:role.writers"
                    + "&authorization_details=details", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid grant request: unknown");
        }
    }

    @Test
    public void testAccessTokenRequestEmptyScope() {

        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=&expiry_time=100", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no scope provided");
        }
    }

    @Test
    public void testAccessTokenRequestValidSpiffeUri() {

        // first valid uri test

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "client_credentials");
        assertEquals(request.getScope(), "test");
        assertEquals(request.getProxyPrincipalsSpiffeUris().size(), 1);
        assertEquals(request.getProxyPrincipalsSpiffeUris().get(0), "spiffe://data/sa/service");

        // uri with leading space

        request = new AccessTokenRequest("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris= spiffe://data/sa/service", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getProxyPrincipalsSpiffeUris().get(0), "spiffe://data/sa/service");

        // uri with multiple values

        request = new AccessTokenRequest("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service,spiffe://sports/sa/api", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getProxyPrincipalsSpiffeUris().size(), 2);
        assertTrue(request.getProxyPrincipalsSpiffeUris().contains("spiffe://data/sa/service"));
        assertTrue(request.getProxyPrincipalsSpiffeUris().contains("spiffe://sports/sa/api"));

        // uri with spaces around the separator

        request = new AccessTokenRequest("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service , spiffe://sports/sa/api", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getProxyPrincipalsSpiffeUris().size(), 2);
        assertTrue(request.getProxyPrincipalsSpiffeUris().contains("spiffe://data/sa/service"));
        assertTrue(request.getProxyPrincipalsSpiffeUris().contains("spiffe://sports/sa/api"));
    }

    @Test
    public void testAccessTokenRequestInvalidSpiffeUri() {
        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=https://athenz.io", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: https://athenz.io");
        }

        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=spiffe://athenz/sa/service,https://athenz.io", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: https://athenz.io");
        }

        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=spiffe://a .io", defaultConfigOptions);
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
                    + "&authorization_details=details&expires_in=100&client_assertion=jwt", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no client assertion type provided");
        }

        // unknown client assertion type

        try {
            new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                    + "&authorization_details=details&expires_in=100&client_assertion=jwt"
                    + "&client_assertion_type=unknown", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid client assertion type: unknown");
        }

        // invalid token

        KeyStore publicKeyProvider = Mockito.mock(KeyStore.class);
        try {
            TokenConfigOptions tokenConfigOptions = new TokenConfigOptions();
            tokenConfigOptions.setPublicKeyProvider(publicKeyProvider);
            tokenConfigOptions.setOauth2Issuers(Set.of("https://athenz.io"));
            new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                    + "&authorization_details=details&expires_in=100&client_assertion=invalid-token"
                    + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    tokenConfigOptions);
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

        TokenConfigOptions tokenConfigOptions = new TokenConfigOptions();
        tokenConfigOptions.setPublicKeyProvider(publicKeyProvider);
        tokenConfigOptions.setOauth2Issuers(Set.of("https://athenz.io/zts/v1"));
        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                        + "&authorization_details=details&expires_in=100&client_assertion=" + token
                        + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                tokenConfigOptions);
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
                + "&scope=data\ntest\ragain", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getQueryLogData(), "scope=data%0Atest%0Dagain");

        // generate a string with 1024 length

        final String scope = "012345678901234".repeat(67);
        request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=" + scope + "&expires_in=1024", defaultConfigOptions);
        assertEquals(request.getQueryLogData(), "scope=" + scope + "&expires_in=1");
    }

    @Test
    public void testAccessTokenRequestQueryDataWithAllFields() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=test&expires_in=100&proxy_for_principal=user.joe"
                + "&authorization_details=details&proxy_principal_spiffe_uris=spiffe://data/sa/service,spiffe://sports/sa/api", defaultConfigOptions);
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
                + "&scope=test&proxy_for_principal=user.joe", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getProxyForPrincipal(), "user.joe");
        assertEquals(request.getScope(), "test");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.ACCESS_TOKEN);
    }

    @Test
    public void testAccessTokenRequestWithOpenIDIssuer() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=test&openid_issuer=true", defaultConfigOptions);
        assertNotNull(request);
        assertTrue(request.isUseOpenIDIssuer());

        request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=test&openid_issuer=false", defaultConfigOptions);
        assertNotNull(request);
        assertFalse(request.isUseOpenIDIssuer());

        request = new AccessTokenRequest("grant_type=client_credentials"
                + "&scope=test&openid_issuer=invalid", defaultConfigOptions);
        assertNotNull(request);
        assertFalse(request.isUseOpenIDIssuer());
    }

    @Test
    public void testAccessTokenRequestInvalidComponentParsing() {

        // component without separator
        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test&invalid", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getScope(), "test");

        // component with invalid URL encoding in key
        request = new AccessTokenRequest("grant_type=client_credentials&scope=test&%ZZ=value", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getScope(), "test");

        // component with invalid URL encoding in value
        request = new AccessTokenRequest("grant_type=client_credentials&scope=test&extra=%ZZ", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getScope(), "test");
    }

    @Test
    public void testAccessTokenRequestTokenExchange() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                + "&audience=sports&subject_token=" + subjectToken
                + "&scope=readers"
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "urn:ietf:params:oauth:grant-type:token-exchange");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.JAG_TOKEN_EXCHANGE);
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithResource() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);
        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                + "&audience=sports&resource=data&subject_token=" + subjectToken
                + "&scope=readers"
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
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
                    + "&scope=readers"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid requested token type: invalid");
        }
    }

    @Test
    public void testAccessTokenRequestJAGTokenExchangeMissingAudience() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                    + "&subject_token=token123"
                    + "&scope=readers"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no audience provided");
        }
    }

    @Test
    public void testAccessTokenRequestJAGTokenExchangeEmptyAudience() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                    + "&audience=&subject_token=token123"
                    + "&scope=readers"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no audience provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenJAGExchangeMissingSubjectToken() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                    + "&audience=sports"
                    + "&scope=readers"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no subject token provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenJAGExchangeEmptySubjectToken() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                    + "&audience=sports&subject_token="
                    + "&scope=readers"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no subject token provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeInvalidSubjectTokenType() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                    + "&audience=sports&subject_token=token123"
                    + "&scope=readers"
                    + "&subject_token_type=invalid", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid subject token type: invalid");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeMissingSubjectTokenType() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                    + "&scope=readers"
                    + "&audience=sports&subject_token=token123", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().startsWith("Invalid subject token type:"));
        }
    }

    @Test
    public void testAccessTokenRequestMissingScope() {

        try {
            new AccessTokenRequest("grant_type=client_credentials", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no scope provided");
        }
    }

    @Test
    public void testAccessTokenRequestNullPrincipal() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test", defaultConfigOptions);
        assertNotNull(request);
        assertNull(request.getPrincipal());
    }

    @Test
    public void testAccessTokenRequestGettersWithDefaults() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test", defaultConfigOptions);
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
                + "&proxy_principal_spiffe_uris=", defaultConfigOptions);
        String queryData = request.getQueryLogData();
        assertNotNull(queryData);
        assertTrue(queryData.contains("scope=test"));
        assertFalse(queryData.contains("proxy_principal_spiffe_uris="));
    }

    @Test
    public void testAccessTokenRequestQueryDataNoExpiryTime() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test", defaultConfigOptions);
        String queryData = request.getQueryLogData();
        assertNotNull(queryData);
        assertTrue(queryData.contains("scope=test"));
        assertFalse(queryData.contains("expires_in="));
    }

    @Test
    public void testAccessTokenRequestJWTBearer() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String assertionToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, AccessToken.HDR_TOKEN_JAG);

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
                + "&assertion=" + assertionToken
                + "&scope=test&resource=data", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "urn:ietf:params:oauth:grant-type:jwt-bearer");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.JAG_JWT_BEARER);
        assertEquals(request.getAssertion(), assertionToken);
        assertEquals(request.getScope(), "test");
        assertEquals(request.getResource(), "data");
    }

    @Test
    public void testAccessTokenRequestJWTBearerMissingAssertion() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
                    + "&scope=test", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no assertion provided");
        }
    }

    @Test
    public void testAccessTokenRequestJWTBearerEmptyAssertion() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
                    + "&assertion=&scope=test", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no assertion provided");
        }
    }

    @Test
    public void testAccessTokenRequestNoGrantType() {

        try {
            new AccessTokenRequest("scope=test", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no grant type provided");
        }
    }

    @Test
    public void testAccessTokenRequestEmptyGrantType() {

        try {
            new AccessTokenRequest("grant_type=&scope=test", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no grant type provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeGetters() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                + "&audience=sports&subject_token=" + subjectToken + "&scope=writers"
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                + "&actor_token=" + subjectToken + "&actor_token_type=urn:ietf:params:oauth:token-type:id_token",
                defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "urn:ietf:params:oauth:grant-type:token-exchange");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.JAG_TOKEN_EXCHANGE);
        assertEquals(request.getRequestedTokenType(), "urn:ietf:params:oauth:token-type:id-jag");
        assertEquals(request.getAudience(), "sports");
        assertEquals(request.getSubjectToken(), subjectToken);
        assertEquals(request.getSubjectTokenType(), "urn:ietf:params:oauth:token-type:id_token");
        assertEquals(request.getActorToken(), subjectToken);
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

        TokenConfigOptions tokenConfigOptions = new TokenConfigOptions();
        tokenConfigOptions.setPublicKeyProvider(publicKeyProvider);
        tokenConfigOptions.setOauth2Issuers(Set.of("https://athenz.io/zts/v1"));
        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=coretech:role.writers"
                        + "&client_assertion=" + token
                        + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                tokenConfigOptions);
        assertNotNull(request);
        assertEquals(request.getClientAssertion(), token);
        assertEquals(request.getClientAssertionType(), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    }

    @Test
    public void testAccessTokenRequestInvalidExpiryTime() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test&expires_in=invalid", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getExpiryTime(), 0);
    }

    @Test
    public void testAccessTokenRequestUpperCaseValues() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=CLIENT_CREDENTIALS&scope=TEST:ROLE.WRITERS"
                + "&proxy_for_principal=USER.JOE", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "client_credentials");
        assertEquals(request.getScope(), "test:role.writers");
        assertEquals(request.getProxyForPrincipal(), "user.joe");
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithActorToken() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                + "&audience=sports&scope=writers&subject_token=" + subjectToken
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                + "&actor_token=actor123&actor_token_type=actor_type", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getActorToken(), "actor123");
        assertEquals(request.getActorTokenType(), "actor_type");
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithAccessTokenType() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:access_token"
                + "&audience=sports&subject_token=" + subjectToken
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "urn:ietf:params:oauth:grant-type:token-exchange");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.TOKEN_EXCHANGE);
        assertEquals(request.getRequestedTokenType(), "urn:ietf:params:oauth:token-type:access_token");
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithEmptyRequestedTokenType() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&audience=sports&subject_token=" + subjectToken
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getGrantType(), "urn:ietf:params:oauth:grant-type:token-exchange");
        assertEquals(request.getRequestType(), AccessTokenRequest.RequestType.TOKEN_EXCHANGE);
        assertTrue(StringUtil.isEmpty(request.getRequestedTokenType()));
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithAccessTokenSubjectTokenType() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&audience=sports&subject_token=" + subjectToken
                + "&subject_token_type=urn:ietf:params:oauth:token-type:access_token", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getSubjectTokenType(), "urn:ietf:params:oauth:token-type:access_token");
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithJWTSubjectTokenType() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&audience=sports&subject_token=" + subjectToken
                + "&subject_token_type=urn:ietf:params:oauth:token-type:jwt", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getSubjectTokenType(), "urn:ietf:params:oauth:token-type:jwt");
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithInvalidSubjectTokenType() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&audience=sports&subject_token=token123"
                    + "&subject_token_type=invalid", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid subject token type: invalid");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithActorTokenMissingType() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&audience=sports&subject_token=" + subjectToken
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                    + "&actor_token=actor123", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid actor token type: null");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithActorTokenInvalidType() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        final File ecPublicKey = new File("./src/test/resources/zts_public_ec.pem");

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "athenz.api",
                "athenz.api", expiryTime, null);

        KeyStore publicKeyProvider = Mockito.mock(KeyStore.class);
        Mockito.when(publicKeyProvider.getServicePublicKey("sys.auth", "zts", "0"))
                .thenReturn(Crypto.loadPublicKey(ecPublicKey));

        try {
            defaultConfigOptions.setOauth2Issuers(Set.of("https://athenz.io:4443/zts/v1"));
            defaultConfigOptions.setPublicKeyProvider(publicKeyProvider);
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&audience=sports&subject_token=" + subjectToken
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                    + "&actor_token=" + subjectToken + "&actor_token_type=invalid", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid actor token type: invalid");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithActorTokenInvalidToken() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        KeyStore publicKeyProvider = Mockito.mock(KeyStore.class);
        try {
            TokenConfigOptions tokenConfigOptions = new TokenConfigOptions();
            tokenConfigOptions.setPublicKeyProvider(publicKeyProvider);
            tokenConfigOptions.setOauth2Issuers(Set.of("https://athenz.io"));
            tokenConfigOptions.setJwtJAGProcessor(createJAGProcessor());
            tokenConfigOptions.setJwtIDTProcessor(createIDTokenProcessor());
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&audience=sports&subject_token=" + subjectToken
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                    + "&actor_token=invalid-token&actor_token_type=urn:ietf:params:oauth:token-type:id_token",
                    tokenConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().startsWith("Invalid actor token: Unable to parse token: "));
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithValidActorToken() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        final File ecPublicKey = new File("./src/test/resources/zts_public_ec.pem");

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        KeyStore publicKeyProvider = Mockito.mock(KeyStore.class);
        Mockito.when(publicKeyProvider.getServicePublicKey("athenz", "api", "eckey1"))
                .thenReturn(Crypto.loadPublicKey(ecPublicKey));
        Mockito.when(publicKeyProvider.getServicePublicKey("sys.auth", "zts", "0"))
                .thenReturn(Crypto.loadPublicKey(ecPublicKey));

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = now + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, "athenz.api", null);
        String actorToken = createToken(privateKey, "0", "athenz.api",
                "athenz.api", expiryTime, null);

        TokenConfigOptions tokenConfigOptions = new TokenConfigOptions();
        tokenConfigOptions.setPublicKeyProvider(publicKeyProvider);
        tokenConfigOptions.setOauth2Issuers(Set.of("https://athenz.io:4443/zts/v1"));
        tokenConfigOptions.setJwtJAGProcessor(createJAGProcessor());
        tokenConfigOptions.setJwtIDTProcessor(createIDTokenProcessor());
        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&audience=sports&subject_token=" + subjectToken
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                + "&actor_token=" + actorToken
                + "&actor_token_type=urn:ietf:params:oauth:token-type:id_token",
                tokenConfigOptions);
        assertNotNull(request);
        assertEquals(request.getActorToken(), actorToken);
        assertNotNull(request.getActorTokenObj());
    }


    @Test
    public void testAccessTokenRequestTokenExchangeWithActorTokenWithoutMayActClaim() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        final File ecPublicKey = new File("./src/test/resources/zts_public_ec.pem");

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        KeyStore publicKeyProvider = Mockito.mock(KeyStore.class);
        Mockito.when(publicKeyProvider.getServicePublicKey("athenz", "api", "eckey1"))
                .thenReturn(Crypto.loadPublicKey(ecPublicKey));
        Mockito.when(publicKeyProvider.getServicePublicKey("sys.auth", "zts", "0"))
                .thenReturn(Crypto.loadPublicKey(ecPublicKey));

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = now + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);
        String actorToken = createToken(privateKey, "0", "athenz.api",
                "athenz.api", expiryTime, null);

        TokenConfigOptions tokenConfigOptions = new TokenConfigOptions();
        tokenConfigOptions.setPublicKeyProvider(publicKeyProvider);
        tokenConfigOptions.setOauth2Issuers(Set.of("https://athenz.io:4443/zts/v1"));
        tokenConfigOptions.setJwtJAGProcessor(createJAGProcessor());
        tokenConfigOptions.setJwtIDTProcessor(createIDTokenProcessor());

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&audience=sports&subject_token=" + subjectToken
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                    + "&actor_token=" + actorToken
                    + "&actor_token_type=urn:ietf:params:oauth:token-type:id_token",
                    tokenConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid subject token: missing may_act claim");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeWithActorTokenWithActMismatch() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        final File ecPublicKey = new File("./src/test/resources/zts_public_ec.pem");

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        KeyStore publicKeyProvider = Mockito.mock(KeyStore.class);
        Mockito.when(publicKeyProvider.getServicePublicKey("athenz", "api", "eckey1"))
                .thenReturn(Crypto.loadPublicKey(ecPublicKey));
        Mockito.when(publicKeyProvider.getServicePublicKey("sys.auth", "zts", "0"))
                .thenReturn(Crypto.loadPublicKey(ecPublicKey));

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = now + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, "athenz.api2", null);
        String actorToken = createToken(privateKey, "0", "athenz.api",
                "athenz.api", expiryTime, null);

        TokenConfigOptions tokenConfigOptions = new TokenConfigOptions();
        tokenConfigOptions.setPublicKeyProvider(publicKeyProvider);
        tokenConfigOptions.setOauth2Issuers(Set.of("https://athenz.io:4443/zts/v1"));
        tokenConfigOptions.setJwtJAGProcessor(createJAGProcessor());
        tokenConfigOptions.setJwtIDTProcessor(createIDTokenProcessor());

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&audience=sports&subject_token=" + subjectToken
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                    + "&actor_token=" + actorToken
                    + "&actor_token_type=urn:ietf:params:oauth:token-type:id_token",
                    tokenConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid subject token: may_act sub does not match actor token subject");
        }
    }

    @Test
    public void testAccessTokenRequestComponentWithNullValue() {

        // Component with null value after decoding should be skipped
        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test&extra=%ZZ", defaultConfigOptions);
        assertNotNull(request);
        assertEquals(request.getScope(), "test");
    }

    @Test
    public void testAccessTokenRequestEmptyBody() {

        try {
            new AccessTokenRequest("", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no grant type provided");
        }
    }

    @Test
    public void testAccessTokenRequestQueryDataEmpty() {

        AccessTokenRequest request = new AccessTokenRequest("grant_type=client_credentials&scope=test", defaultConfigOptions);
        String queryData = request.getQueryLogData();
        assertNotNull(queryData);
        assertTrue(queryData.contains("scope=test"));
    }

    @Test
    public void testAccessTokenRequestGetActorTokenObj() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&audience=sports&subject_token=" + subjectToken
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
        assertNotNull(request);
        assertNull(request.getActorTokenObj());
    }

    @Test
    public void testAccessTokenRequestJAGTokenExchangeWithClientAssertion() throws JOSEException {

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

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = now + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        TokenConfigOptions tokenConfigOptions = new TokenConfigOptions();
        tokenConfigOptions.setPublicKeyProvider(publicKeyProvider);
        tokenConfigOptions.setOauth2Issuers(Set.of("https://athenz.io/zts/v1"));
        tokenConfigOptions.setJwtIDTProcessor(createIDTokenProcessor());
        AccessTokenRequest request = new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                + "&audience=sports&scope=readers&subject_token=" + subjectToken
                + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
                + "&client_assertion=" + token
                + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                tokenConfigOptions);
        assertNotNull(request);
        assertNotNull(request.getPrincipal());
    }

    @Test
    public void testAccessTokenRequestTokenExchangeMissingSubjectToken() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:access_token"
                    + "&audience=sports"
                    + "&scope=readers"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no subject token provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeEmptySubjectToken() {

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:access_token"
                    + "&audience=sports&subject_token="
                    + "&scope=readers"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no subject token provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeMissingAudience() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:access_token"
                    + "&subject_token=" + subjectToken
                    + "&scope=readers"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no audience provided");
        }
    }

    @Test
    public void testAccessTokenRequestTokenExchangeEmptyAudience() {

        final File ecPrivateKey = new File("./src/test/resources/unit_test_zts_private_ec.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        // Create a subject token for user_domain.user with audience as proxy-user1
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createToken(privateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null);

        try {
            new AccessTokenRequest("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:access_token"
                    + "&audience=&subject_token=" + subjectToken
                    + "&scope=readers"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token", defaultConfigOptions);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no audience provided");
        }
    }

    private String createToken(PrivateKey privateKey, String keyId, String subject, String audience,
            long expiryTime, String mayActSubject, String tokenType) {

        try {
            JWSSigner signer = JwtsHelper.getJWSSigner(privateKey);
            long now = System.currentTimeMillis() / 1000;
            HashMap<String, String> mayActMap = null;
            if (mayActSubject != null) {
                mayActMap = new HashMap<>();
                mayActMap.put("sub", mayActSubject);
            }
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issueTime(Date.from(Instant.ofEpochSecond(now)))
                    .expirationTime(Date.from(Instant.ofEpochSecond(expiryTime)))
                    .issuer("https://athenz.io:4443/zts/v1")
                    .audience(audience)
                    .claim("ver", 1)
                    .claim("auth_time", now)
                    .claim("may_act", mayActMap)
                    .build();

            JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId);
            if (tokenType != null) {
                builder.type(new JOSEObjectType(tokenType));
            }
            SignedJWT signedJWT = new SignedJWT(builder.build(), claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException ex) {
            fail("Failed to create ID token: " + ex.getMessage());
            return null;
        }
    }

    private String createToken(PrivateKey privateKey, String keyId, String subject, String audience,
            long expiryTime, String tokenType) {
        return createToken(privateKey, keyId, subject, audience, expiryTime, null, tokenType);
    }

    private ConfigurableJWTProcessor<SecurityContext> createJAGProcessor() {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null, null, true);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSTypeVerifier(JwtsHelper.JWT_JAG_TYPE_VERIFIER);

        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JwtsHelper.JWS_SUPPORTED_ALGORITHMS,
                resolver.getKeySource()));
        return jwtProcessor;
    }

    private ConfigurableJWTProcessor<SecurityContext> createIDTokenProcessor() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null, null, true);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JwtsHelper.JWS_SUPPORTED_ALGORITHMS,
                resolver.getKeySource()));
        return jwtProcessor;
    }
}
