/*
 * Copyright 2019 Oath Holdings Inc.
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
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class IdTokenTest {

    private final File ecPrivateKey = new File("./src/test/resources/ec_private.key");
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
    }

    @Test
    public void testIdToken() {

        long now = System.currentTimeMillis() / 1000;

        IdToken token = createIdToken(now);

        // verify the getters

        validateIdToken(token, now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String idJws = token.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(idJws);

        // now verify our signed token

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        Jws<Claims> claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(idJws);
        assertNotNull(claims);

        assertEquals("subject", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals("athenz", claims.getBody().getIssuer());
    }

    @Test
    public void testIdTokenSignedToken() {

        long now = System.currentTimeMillis() / 1000;

        IdToken token = createIdToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String idJws = token.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(idJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

        IdToken checkToken = new IdToken(idJws, resolver);
        validateIdToken(checkToken, now);
    }

    @Test
    public void testIdTokenSignedTokenPublicKey() {

        long now = System.currentTimeMillis() / 1000;

        IdToken token = createIdToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String idJws = token.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(idJws);

        // now verify our signed token

        IdToken checkToken = new IdToken(idJws, Crypto.loadPublicKey(ecPublicKey));
        validateIdToken(checkToken, now);
    }
}
