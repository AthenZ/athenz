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
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public class AccessToken extends OAuth2Token {

    public static final String HDR_TOKEN_TYPE = "typ";
    public static final String HDR_TOKEN_JWT = "at+jwt";

    public static final String CLAIM_SCOPE = "scp";
    public static final String CLAIM_UID = "uid";
    public static final String CLAIM_CLIENT_ID = "client_id";

    private String clientId;
    private String userId;
    private List<String> scope;

    public AccessToken() {
        super();
    }

    public AccessToken(final String token, JwtsSigningKeyResolver keyResolver) {

        super(token, keyResolver);
        setAccessTokenFields();
    }

    public AccessToken(final String token, PublicKey publicKey) {

        super(token, publicKey);
        setAccessTokenFields();
    }

    void setAccessTokenFields() {
        final Claims body = claims.getBody();
        setClientId(body.get(CLAIM_CLIENT_ID, String.class));
        setUserId(body.get(CLAIM_UID, String.class));
        setScope(body.get(CLAIM_SCOPE, List.class));
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public List<String> getScope() {
        return scope;
    }

    public void setScope(List<String> scope) {
        this.scope = scope;
    }

    public String getSignedToken(final PrivateKey key, final String keyId,
            final SignatureAlgorithm keyAlg) {

        return Jwts.builder().setSubject(subject)
                .setIssuedAt(Date.from(Instant.ofEpochSecond(issueTime)))
                .setExpiration(Date.from(Instant.ofEpochSecond(expiryTime)))
                .setIssuer(issuer)
                .setAudience(audience)
                .claim(CLAIM_AUTH_TIME, authTime)
                .claim(CLAIM_VERSION, version)
                .claim(CLAIM_SCOPE, scope)
                .claim(CLAIM_UID, userId)
                .claim(CLAIM_CLIENT_ID, clientId)
                .setHeaderParam(HDR_KEY_ID, keyId)
                .setHeaderParam(HDR_TOKEN_TYPE, HDR_TOKEN_JWT)
                .signWith(keyAlg, key)
                .compact();
    }
}
