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
package com.yahoo.athenz.auth.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;

import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class IdTokenTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");

    IdToken createIdToken(long now) {

        IdToken token = new IdToken();
        token.setAuthTime(now);
        token.setSubject("subject");
        token.setExpiryTime(now + 3600);
        token.setIssueTime(now);
        token.setAudience("coretech");
        token.setVersion(1);
        token.setIssuer("athenz");
        token.setNonce("nonce");
        token.setGroups(Collections.singletonList("dev-team"));
        return token;
    }

    void validateIdToken(IdToken token, long now) {
        assertEquals(now, token.getAuthTime());
        assertEquals(token.getSubject(), "subject");
        assertEquals(token.getExpiryTime(), now + 3600);
        assertEquals(token.getIssueTime(), now);
        assertEquals(token.getAudience(), "coretech");
        assertEquals(token.getVersion(), 1);
        assertEquals(token.getIssuer(), "athenz");
        assertEquals(token.getNonce(), "nonce");
        assertEquals(token.getGroups(), Collections.singletonList("dev-team"));
    }

    @Test
    public void testIdToken() throws JOSEException, ParseException {

        long now = System.currentTimeMillis() / 1000;

        IdToken token = createIdToken(now);

        // verify the getters

        validateIdToken(token, now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String idJws = token.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(idJws);

        // now verify our signed token

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);
        SignedJWT signedJWT = SignedJWT.parse(idJws);
        assertTrue(signedJWT.verify(verifier));
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertNotNull(claimsSet);

        assertEquals(claimsSet.getSubject(), "subject");
        assertEquals(claimsSet.getAudience().get(0), "coretech");
        assertEquals(claimsSet.getIssuer(), "athenz");
    }

    @Test
    public void testIdTokenWithSpiffe() throws JOSEException, ParseException {

        long now = System.currentTimeMillis() / 1000;

        IdToken token = createIdToken(now);
        token.setSpiffe("spiffe://athenz.io/dev");

        // verify the getters

        validateIdToken(token, now);
        assertEquals(token.getSpiffe(), "spiffe://athenz.io/dev");

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String idJws = token.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(idJws);

        // now verify our signed token

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);
        SignedJWT signedJWT = SignedJWT.parse(idJws);
        assertTrue(signedJWT.verify(verifier));
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertNotNull(claimsSet);

        assertEquals(claimsSet.getSubject(), "subject");
        assertEquals(claimsSet.getAudience().get(0), "coretech");
        assertEquals(claimsSet.getIssuer(), "athenz");
        assertEquals(claimsSet.getStringClaim("spiffe"), "spiffe://athenz.io/dev");
    }

    @Test
    public void testIdTokenCustomClaims() throws JOSEException, ParseException {

        long now = System.currentTimeMillis() / 1000;

        IdToken token = createIdToken(now);

        // custom claims should return true
        assertTrue(token.setCustomClaim("preferred_email", "noreply@athenz.io"));
        String[] emails = new String[] {"noreply1@athenz.io", "noreply2@athenz.io"};
        assertTrue(token.setCustomClaim("emails", emails));

        // standard claims should return failure

        assertFalse(token.setCustomClaim(IdToken.CLAIM_NONCE, "nonce"));
        assertFalse(token.setCustomClaim(IdToken.CLAIM_SUBJECT, "subject"));

        // verify the getters

        validateIdToken(token, now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String idJws = token.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(idJws);

        // now verify our signed token

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);
        SignedJWT signedJWT = SignedJWT.parse(idJws);
        assertTrue(signedJWT.verify(verifier));
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertNotNull(claimsSet);

        assertEquals(claimsSet.getSubject(), "subject");
        assertEquals(claimsSet.getAudience().get(0), "coretech");
        assertEquals(claimsSet.getIssuer(), "athenz");
        assertEquals(claimsSet.getClaim("preferred_email"), "noreply@athenz.io");
        assertEquals(claimsSet.getClaim("emails"), Arrays.asList(emails));
    }

    @Test
    public void testIdTokenSignedToken() {

        long now = System.currentTimeMillis() / 1000;

        IdToken token = createIdToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String idJws = token.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(idJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        IdToken checkToken = new IdToken(idJws, resolver);
        validateIdToken(checkToken, now);
    }

    @Test
    public void testIdTokenSignedTokenPublicKey() {

        long now = System.currentTimeMillis() / 1000;

        IdToken token = createIdToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String idJws = token.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(idJws);

        // now verify our signed token

        IdToken checkToken = new IdToken(idJws, Crypto.loadPublicKey(ecPublicKey));
        validateIdToken(checkToken, now);
    }

    @Test
    public void testIdTokenEmptyGroups() {

        IdToken token = new IdToken();
        token.setGroups(null);
        assertNull(token.getGroups());
        token.setGroups(Collections.emptyList());
        assertNull(token.getGroups());
    }

    @Test
    public void testGetSignedTokenFailure() {

        long now = System.currentTimeMillis() / 1000;
        IdToken token = createIdToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        assertNull(token.getSignedToken(privateKey, "eckey1", "RS256"));
    }

    @Test
    public void testIdTokenWithJwtProcessor() {

        long now = System.currentTimeMillis() / 1000;

        IdToken idToken = createIdToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = idToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token using jwt processor

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = JwtsHelper.getJWTProcessor(resolver);

        IdToken checkToken = new IdToken(accessJws, jwtProcessor);
        validateIdToken(checkToken, now);
    }

    @Test
    public void testIdTokenWithJwtProcessorInvalidToken() {

        // create an invalid token string
        final String invalidToken = "invalid.token.string";

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = JwtsHelper.getJWTProcessor(resolver);

        try {
            new IdToken(invalidToken, jwtProcessor);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Unable to parse token"));
        }
    }

    @Test
    public void testIdTokenWithJwtProcessorExpiredToken() {

        long now = System.currentTimeMillis() / 1000;

        // we allow clock skew of 60 seconds so we'll go
        // back 3600 + 61 to make our token expired
        IdToken idToken = createIdToken(now - 3661);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = idToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token using jwt processor

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = JwtsHelper.getJWTProcessor(resolver);

        try {
            new IdToken(accessJws, jwtProcessor);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Expired"));
        }
    }

    @Test
    public void testIdTokenWithJwtProcessorNoSignature() {

        long now = System.currentTimeMillis() / 1000;

        IdToken idToken = createIdToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = idToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // remove the signature part from the token

        int idx = accessJws.lastIndexOf('.');
        final String unsignedJws = accessJws.substring(0, idx + 1);

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = JwtsHelper.getJWTProcessor(resolver);

        try {
            new IdToken(unsignedJws, jwtProcessor);
            fail();
        } catch (CryptoException ignored) {
        }
    }

    @Test
    public void testIdTokenWithJwtProcessorNoneAlgorithm() {

        long now = System.currentTimeMillis() / 1000;
        IdToken idToken = createIdToken(now);

        // now get the unsigned token with none algorithm

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(idToken.subject)
                .jwtID(idToken.jwtId)
                .issueTime(Date.from(Instant.ofEpochSecond(idToken.issueTime)))
                .expirationTime(Date.from(Instant.ofEpochSecond(idToken.expiryTime)))
                .issuer(idToken.issuer)
                .audience(idToken.audience)
                .claim(IdToken.CLAIM_AUTH_TIME, idToken.authTime)
                .claim(IdToken.CLAIM_VERSION, idToken.version)
                .build();

        PlainJWT signedJWT = new PlainJWT(claimsSet);
        final String accessJws = signedJWT.serialize();

        // with a jwt processor we must get a failure

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = JwtsHelper.getJWTProcessor(resolver);

        try {
            new IdToken(accessJws, jwtProcessor);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Unsecured (plain) JWTs are rejected"));
        }
    }

    @Test
    public void testIdTokenWithJwtProcessorUnknownKey() {

        long now = System.currentTimeMillis() / 1000;

        IdToken idToken = createIdToken(now);

        // now get the signed token with unknown key

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = idToken.getSignedToken(privateKey, "eckey99", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token with a jwt processor that doesn't have the key

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("athenz-no-keys_jwk.conf")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                JwtsHelper.getJWTProcessor(resolver);

        try {
            new IdToken(accessJws, jwtProcessor);
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testIdTokenWithJwtProcessorInvalidSignature() {

        long now = System.currentTimeMillis() / 1000;

        IdToken idToken = createIdToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = idToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // tamper with the token by modifying the signature
        int lastDot = accessJws.lastIndexOf('.');
        String tamperedToken = accessJws.substring(0, lastDot) + ".invalidsignature";

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = JwtsHelper.getJWTProcessor(resolver);

        try {
            new IdToken(tamperedToken, jwtProcessor);
            fail();
        } catch (CryptoException ignored) {
        }
    }
}
