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

import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import io.jsonwebtoken.*;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.*;

import static org.testng.Assert.*;

public class OAuth2TokenTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");

    @Test
    public void testOauth2TokenWithValidValues() {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        String token = Jwts.builder().setSubject("subject")
                    .setId("id001")
                    .setIssuedAt(Date.from(Instant.ofEpochSecond(now)))
                    .setExpiration(Date.from(Instant.ofEpochSecond(now)))
                    .setNotBefore(Date.from(Instant.ofEpochSecond(now)))
                    .setIssuer("issuer")
                    .setAudience("audience")
                    .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                    .claim(OAuth2Token.CLAIM_VERSION, 1)
                    .setHeaderParam(OAuth2Token.HDR_KEY_ID, "eckey1")
                    .signWith(privateKey, SignatureAlgorithm.ES256)
                    .compact();

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

        OAuth2Token oAuth2Token = new OAuth2Token(token, resolver);

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
    public void testOauth2TokenWithUnsupportedTypes() {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        String token = Jwts.builder().setSubject("subject")
                .setIssuedAt(Date.from(Instant.ofEpochSecond(now)))
                .setExpiration(Date.from(Instant.ofEpochSecond(now)))
                .setIssuer("issuer")
                .setAudience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, "100000000")
                .claim(OAuth2Token.CLAIM_VERSION, "1.0")
                .setHeaderParam(OAuth2Token.HDR_KEY_ID, "eckey1")
                .signWith(privateKey, SignatureAlgorithm.ES256)
                .compact();

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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

        String token = Jwts.builder().setSubject("subject")
                .setId("id001")
                .setIssuedAt(Date.from(Instant.ofEpochSecond(now)))
                .setExpiration(Date.from(Instant.ofEpochSecond(now)))
                .setNotBefore(Date.from(Instant.ofEpochSecond(now)))
                .setIssuer("issuer")
                .setAudience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .compact();

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

        String token = Jwts.builder().setSubject("subject")
                .setId("id001")
                .setIssuedAt(Date.from(Instant.ofEpochSecond(now)))
                .setExpiration(Date.from(Instant.ofEpochSecond(now)))
                .setNotBefore(Date.from(Instant.ofEpochSecond(now)))
                .setIssuer("issuer")
                .setAudience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .compact();

        // with resolver argument

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);

        try {
            JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
            resolver.addPublicKey("eckey1", publicKey);
            new OAuth2Token(token, resolver);
            fail();
        } catch (JwtException ignored) {
        }

        // with key argument

        try {
            new OAuth2Token(token, publicKey);
            fail();
        } catch (JwtException ignored) {
        }
    }

    @Test
    public void testOauth2TokenWithSignatureRemoved() {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        String token = Jwts.builder().setSubject("subject")
                .setId("id001")
                .setIssuedAt(Date.from(Instant.ofEpochSecond(now)))
                .setExpiration(Date.from(Instant.ofEpochSecond(now)))
                .setNotBefore(Date.from(Instant.ofEpochSecond(now)))
                .setIssuer("issuer")
                .setAudience("audience")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .setHeaderParam(OAuth2Token.HDR_KEY_ID, "eckey1")
                .signWith(privateKey, SignatureAlgorithm.ES256)
                .compact();

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

}
