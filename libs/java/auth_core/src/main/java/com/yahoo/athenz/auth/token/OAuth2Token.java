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
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.security.PublicKey;

public class OAuth2Token {

    public static final String HDR_KEY_ID = "kid";

    public static final String CLAIM_VERSION = "ver";
    public static final String CLAIM_AUTH_TIME = "auth_time";

    protected int version;
    protected long expiryTime;
    protected long issueTime;
    protected long authTime;
    protected String audience;
    protected String issuer;
    protected String subject;
    protected Jws<Claims> claims = null;

    public OAuth2Token() {
    }

    public OAuth2Token(final String token, JwtsSigningKeyResolver keyResolver) {

        claims = Jwts.parser()
                .setSigningKeyResolver(keyResolver)
                .setAllowedClockSkewSeconds(60)
                .parseClaimsJws(token);

        setTokenFields();
    }

    public OAuth2Token(final String token, PublicKey publicKey) {

        claims = Jwts.parser()
                .setSigningKey(publicKey)
                .setAllowedClockSkewSeconds(60)
                .parseClaimsJws(token);

        setTokenFields();
    }

    void setTokenFields() {
        final Claims body = claims.getBody();
        setVersion(body.get(CLAIM_VERSION, Integer.class));
        setAudience(body.getAudience());
        setExpiryTime(body.getExpiration().getTime() / 1000);
        setIssueTime(body.getIssuedAt().getTime() / 1000);
        setAuthTime(body.get(CLAIM_AUTH_TIME, Long.class));
        setIssuer(body.getIssuer());
        setSubject(body.getSubject());
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public long getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(long expiryTime) {
        this.expiryTime = expiryTime;
    }

    public long getIssueTime() {
        return issueTime;
    }

    public void setIssueTime(long issueTime) {
        this.issueTime = issueTime;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public long getAuthTime() {
        return authTime;
    }

    public void setAuthTime(long authTime) {
        this.authTime = authTime;
    }
}
