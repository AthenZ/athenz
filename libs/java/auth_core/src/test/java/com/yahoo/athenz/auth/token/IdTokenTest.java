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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Collections;
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
        assertEquals("subject", token.getSubject());
        assertEquals(now + 3600, token.getExpiryTime());
        assertEquals(now, token.getIssueTime());
        assertEquals("coretech", token.getAudience());
        assertEquals(1, token.getVersion());
        assertEquals("athenz", token.getIssuer());
        assertEquals("nonce", token.getNonce());
        assertEquals(Collections.singletonList("dev-team"), token.getGroups());
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

        assertEquals("subject", claimsSet.getSubject());
        assertEquals("coretech", claimsSet.getAudience().get(0));
        assertEquals("athenz", claimsSet.getIssuer());
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
}
