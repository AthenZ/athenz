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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.*;

import static org.testng.Assert.*;

public class OAuth2TokenTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @Test
    public void testOauth2TokenWithValidValues() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("subject")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("issuer")
                .audience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        OAuth2Token oAuth2Token = new OAuth2Token(token, resolver);

        assertEquals(oAuth2Token.getVersion(), 1);
        assertEquals(oAuth2Token.getAudience(), "audience");
        assertEquals(oAuth2Token.getSubject(), "subject");
        assertEquals(oAuth2Token.getIssueTime(), now);
        assertEquals(oAuth2Token.getExpiryTime(), now);
        assertEquals(oAuth2Token.getNotBeforeTime(), now);
        assertEquals(oAuth2Token.getAuthTime(), now);
        assertEquals(oAuth2Token.getJwtId(), "id001");

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        oAuth2Token = new OAuth2Token(token, publicKey);

        assertEquals(oAuth2Token.getVersion(), 1);
        assertEquals(oAuth2Token.getAudience(), "audience");
        assertEquals(oAuth2Token.getSubject(), "subject");
        assertEquals(oAuth2Token.getIssueTime(), now);
        assertEquals(oAuth2Token.getExpiryTime(), now);
        assertEquals(oAuth2Token.getNotBeforeTime(), now);
        assertEquals(oAuth2Token.getAuthTime(), now);
        assertEquals(oAuth2Token.getJwtId(), "id001");
    }

    @Test
    public void testOauth2TokenWithUnsupportedTypes() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("subject")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("issuer")
                .audience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, "100000000")
                .claim(OAuth2Token.CLAIM_VERSION, "1.0")
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        OAuth2Token oAuth2Token = new OAuth2Token(token, resolver);

        assertEquals(oAuth2Token.getVersion(), 0);
        assertEquals(oAuth2Token.getAudience(), "audience");
        assertEquals(oAuth2Token.getSubject(), "subject");
        assertEquals(oAuth2Token.getIssueTime(), now);
        assertEquals(oAuth2Token.getExpiryTime(), now);
        assertEquals(oAuth2Token.getNotBeforeTime(), 0);
        assertEquals(oAuth2Token.getAuthTime(), 0);
    }

    @Test
    public void testOauth2TokenWithoutSignature() {

        long now = System.currentTimeMillis() / 1000;

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("subject")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("issuer")
                .audience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        PlainJWT plainJWT = new PlainJWT(claimsSet);
        final String token = plainJWT.serialize();

        // with resolver argument

        OAuth2Token oAuth2Token = new OAuth2Token(token, (JwtsSigningKeyResolver) null);

        assertEquals(oAuth2Token.getVersion(), 1);
        assertEquals(oAuth2Token.getAudience(), "audience");
        assertEquals(oAuth2Token.getSubject(), "subject");
        assertEquals(oAuth2Token.getIssueTime(), now);
        assertEquals(oAuth2Token.getExpiryTime(), now);
        assertEquals(oAuth2Token.getNotBeforeTime(), now);
        assertEquals(oAuth2Token.getAuthTime(), now);
        assertEquals(oAuth2Token.getJwtId(), "id001");

        // with public key argument
        oAuth2Token = new OAuth2Token(token, (PublicKey) null);

        assertEquals(oAuth2Token.getVersion(), 1);
        assertEquals(oAuth2Token.getAudience(), "audience");
        assertEquals(oAuth2Token.getSubject(), "subject");
        assertEquals(oAuth2Token.getIssueTime(), now);
        assertEquals(oAuth2Token.getExpiryTime(), now);
        assertEquals(oAuth2Token.getNotBeforeTime(), now);
        assertEquals(oAuth2Token.getAuthTime(), now);
        assertEquals(oAuth2Token.getJwtId(), "id001");
    }

    @Test
    public void testOauth2TokenWithoutSignatureWithKeyResolver() {

        long now = System.currentTimeMillis() / 1000;

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("subject")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("issuer")
                .audience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        PlainJWT plainJWT = new PlainJWT(claimsSet);
        final String token = plainJWT.serialize();

        // with resolver argument

        try {
            final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
            JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

            new OAuth2Token(token, resolver);
            fail();
        } catch (CryptoException ignored) {
        }

        // with key argument

        try {
            PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
            new OAuth2Token(token, publicKey);
            fail();
        } catch (CryptoException ignored) {
        }
    }

    @Test
    public void testOauth2TokenWithInvalidSignature() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("subject")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("issuer")
                .audience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        final String unsignedToken = token.substring(0, token.lastIndexOf('.') + 1);
        final String signedToken = unsignedToken + Base64URL.encode("invalid-signature");

        try {
            final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
            JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

            new OAuth2Token(signedToken, resolver);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid signature"));
        }

        try {
            PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
            new OAuth2Token(signedToken, publicKey);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify token signature"));
        }
    }

    @Test
    public void testOauth2TokenWithSignatureRemoved() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("subject")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("issuer")
                .audience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        final String unsignedToken = token.substring(0, token.lastIndexOf('.') + 1);

        OAuth2Token oAuth2Token = new OAuth2Token(unsignedToken, (JwtsSigningKeyResolver) null);

        assertEquals(oAuth2Token.getVersion(), 1);
        assertEquals(oAuth2Token.getAudience(), "audience");
        assertEquals(oAuth2Token.getSubject(), "subject");
        assertEquals(oAuth2Token.getIssueTime(), now);
        assertEquals(oAuth2Token.getExpiryTime(), now);
        assertEquals(oAuth2Token.getNotBeforeTime(), now);
        assertEquals(oAuth2Token.getAuthTime(), now);
        assertEquals(oAuth2Token.getJwtId(), "id001");
    }

    @Test
    public void testParseFailures() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("string", 1234)
                .claim("stringlist", 1234)
                .claim("integer", "integer")
                .claim("long", "long")
                .build();
        assertNull(JwtsHelper.getStringClaim(claimsSet, "string"));
        assertNull(JwtsHelper.getStringListClaim(claimsSet, "stringlist"));
        assertEquals(JwtsHelper.getIntegerClaim(claimsSet, "integer", 0), 0);
        assertEquals(JwtsHelper.getLongClaim(claimsSet, "long", -1), -1);
        assertNull(JwtsHelper.getAudience(claimsSet));
    }
}
