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
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PublicKeyProvider;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;

import static org.testng.Assert.*;

public class ZTSAccessTokenTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");

    @Test
    public void testZTSAccessToken() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("athenz.api")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("athenz.api")
                .audience("sports")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        PublicKeyProvider publicKeyProvider = (domainName, serviceName, keyId) -> {
            if (domainName.equals("sys.auth") && serviceName.equals("zts") && keyId.equals("eckey1")) {
                try {
                    return Crypto.loadPublicKey(ecPublicKey);
                } catch (CryptoException e) {
                    return null;
                }
            }
            return null;
        };

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("introspect", "sports:token", principal, null))
                .thenReturn(true) // authorize our introspect request
                .thenReturn(false); // unauthorized introspect request

        ZTSAccessToken ztsAccessToken = new ZTSAccessToken(token, publicKeyProvider, authorizer, principal);

        assertEquals(ztsAccessToken.getVersion(), 1);
        assertEquals(ztsAccessToken.getAudience(), "sports");
        assertEquals(ztsAccessToken.getSubject(), "athenz.api");
        assertEquals(ztsAccessToken.getIssueTime(), now);
        assertEquals(ztsAccessToken.getExpiryTime(), now + 3600);
        assertEquals(ztsAccessToken.getNotBeforeTime(), now);
        assertEquals(ztsAccessToken.getAuthTime(), now);
        assertEquals(ztsAccessToken.getJwtId(), "id001");

        // during our second call we should get a failure from the authorizer

        try {
            new ZTSAccessToken(token, publicKeyProvider, authorizer, principal);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("unauthorized introspect request"));
        }
    }

    @Test
    public void testZTSAccessTokenFailuresNullArguments() {

        try {
            new ZTSAccessToken(null, null, null, null);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid arguments: missing token, public key provider, authorizer or principal"));
        }

        try {
            new ZTSAccessToken("token", null, null, null);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid arguments: missing token, public key provider, authorizer or principal"));
        }

        PublicKeyProvider publicKeyProvider = (domainName, serviceName, keyId) -> null;
        try {
            new ZTSAccessToken("token", publicKeyProvider, null, null);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid arguments: missing token, public key provider, authorizer or principal"));
        }

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        try {
            new ZTSAccessToken("token", publicKeyProvider, authorizer, null);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid arguments: missing token, public key provider, authorizer or principal"));
        }

        Principal principal = Mockito.mock(Principal.class);
        try {
            new ZTSAccessToken("token", publicKeyProvider, null, principal);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid arguments: missing token, public key provider, authorizer or principal"));
        }
    }

    @Test
    public void testZTSAccessTokenWithoutAudience() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("athenz.api")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("athenz.api")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        PublicKeyProvider publicKeyProvider = Mockito.mock(PublicKeyProvider.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);

        try {
            new ZTSAccessToken(token, publicKeyProvider, authorizer, principal);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid token: missing audience"));
        }
    }

    @Test
    public void testZTSAccessTokenWithoutKeyId() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("athenz.api")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("athenz.api")
                .audience("sports")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        PublicKeyProvider publicKeyProvider = Mockito.mock(PublicKeyProvider.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("introspect", "sports:token", principal, null))
                .thenReturn(true);

        try {
            new ZTSAccessToken(token, publicKeyProvider, authorizer, principal);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid token: missing key id"));
        }
    }

    @Test
    public void testZTSAccessTokenMissingPublicKey() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("athenz.api")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("athenz.api")
                .audience("sports")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        PublicKeyProvider publicKeyProvider = (domainName, serviceName, keyId) -> null;

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("introspect", "sports:token", principal, null))
                .thenReturn(true);

        try {
            new ZTSAccessToken(token, publicKeyProvider, authorizer, principal);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid token: unable to get public key"));
        }
    }

    @Test
    public void testZTSAccessTokenInvalidSignature() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("athenz.api")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("athenz.api")
                .audience("sports")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        PublicKeyProvider publicKeyProvider = (domainName, serviceName, keyId) -> {
            if (domainName.equals("sys.auth") && serviceName.equals("zts") && keyId.equals("eckey1")) {
                try {
                    return Crypto.loadPublicKey(ecPublicKey);
                } catch (CryptoException e) {
                    return null;
                }
            }
            return null;
        };

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(authorizer.access("introspect", "sports:token", principal, null))
                .thenReturn(true) // authorize our introspect request
                .thenReturn(false); // unauthorized introspect request

        final String unsignedToken = token.substring(0, token.lastIndexOf('.') + 1);
        final String signedToken = unsignedToken + Base64URL.encode("invalid-signature");

        try {
            new ZTSAccessToken(signedToken, publicKeyProvider, authorizer, principal);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify token signature"));
        }
    }
}
