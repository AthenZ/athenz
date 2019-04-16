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

import com.yahoo.athenz.auth.util.Crypto;
import io.jsonwebtoken.*;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class AccessTokenTest {

    private final File ecPrivateKey = new File("./src/test/resources/ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");

    @Test
    public void testAccessToken() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = new AccessToken();
        accessToken.setAuthTime(now);
        accessToken.setScope(Collections.singletonList("readers"));
        accessToken.setSubject("subject");
        accessToken.setUserId("userid");
        accessToken.setExpiryTime(now + 3600);
        accessToken.setIssueTime(now);
        accessToken.setClientId("clientid");
        accessToken.setAudience("coretech");
        accessToken.setVersion(1);
        accessToken.setIssuer("athenz");

        // verify the getters

        assertEquals(now, accessToken.getAuthTime());
        assertEquals(1, accessToken.getScope().size());
        assertTrue(accessToken.getScope().contains("readers"));
        assertEquals("subject", accessToken.getSubject());
        assertEquals("userid", accessToken.getUserId());
        assertEquals(now + 3600, accessToken.getExpiryTime());
        assertEquals(now, accessToken.getIssueTime());
        assertEquals("clientid", accessToken.getClientId());
        assertEquals("coretech", accessToken.getAudience());
        assertEquals(1, accessToken.getVersion());
        assertEquals("athenz", accessToken.getIssuer());

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        Jws<Claims> claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(accessJws);
        assertNotNull(claims);

        assertEquals("subject", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals("athenz", claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("readers", scopes.get(0));
    }
}
