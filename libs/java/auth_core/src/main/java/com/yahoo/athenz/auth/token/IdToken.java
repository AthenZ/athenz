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
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public class IdToken extends OAuth2Token {

    public static final String CLAIM_GROUPS = "groups";
    public static final String CLAIM_NONCE  = "nonce";

    private List<String> groups;
    private String nonce;

    public IdToken() {
        super();
    }

    public IdToken(final String token, JwtsSigningKeyResolver keyResolver) {
        super(token, keyResolver);
        setIdTokenFields();
    }

    public IdToken(final String token, PublicKey publicKey) {
        super(token, publicKey);
        setIdTokenFields();
    }

    void setIdTokenFields() {
        setNonce(body.get(CLAIM_NONCE, String.class));
        setGroups(body.get(CLAIM_GROUPS, List.class));
    }

    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(List<String> groups) {
        this.groups = (groups == null || groups.isEmpty()) ? null : groups;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
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
                .claim(CLAIM_GROUPS, groups)
                .claim(CLAIM_NONCE, nonce)
                .setHeaderParam(HDR_KEY_ID, keyId)
                .signWith(key, keyAlg)
                .compact();
    }
}
