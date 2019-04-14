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

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;

public class IdToken extends OAuth2Token {

    public String getSignedToken(final PrivateKey key, final String keyId,
            final SignatureAlgorithm keyAlg) {

        return Jwts.builder().setSubject(subject)
                .setIssuedAt(Date.from(Instant.ofEpochSecond(issueTime)))
                .setExpiration(Date.from(Instant.ofEpochSecond(expiryTime)))
                .setIssuer(issuer)
                .setAudience(audience)
                .claim(CLAIM_AUTH_TIME, authTime)
                .claim(CLAIM_VERSION, version)
                .setHeaderParam(HDR_KEY_ID, keyId)
                .signWith(keyAlg, key)
                .compact();
    }
}
