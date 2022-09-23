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
import io.jsonwebtoken.*;

import java.security.PublicKey;
import java.util.Date;

public class OAuth2Token {

    public static final String HDR_KEY_ID = "kid";

    public static final String CLAIM_VERSION = "ver";
    public static final String CLAIM_AUTH_TIME = "auth_time";

    protected int version;
    protected long expiryTime;
    protected long issueTime;
    protected long authTime;
    protected long notBeforeTime;
    protected String audience;
    protected String issuer;
    protected String subject;
    protected String jwtId;
    protected Claims body = null;

    public OAuth2Token() {
    }

    public OAuth2Token(final String token, JwtsSigningKeyResolver keyResolver) {

        // if the keyresolver is null and the token does not have
        // a signature we're going to treat and parse it as a jwt

        if (keyResolver == null && isSignatureMissing(token)) {
            Jwt<Header, Claims> claims = Jwts.parserBuilder()
                    .setAllowedClockSkewSeconds(60)
                    .build()
                    .parseClaimsJwt(token);
            body = claims.getBody();
        } else {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKeyResolver(keyResolver)
                    .setAllowedClockSkewSeconds(60)
                    .build()
                    .parseClaimsJws(token);
            body = claims.getBody();
        }

        setTokenFields();
    }

    public OAuth2Token(final String token, PublicKey publicKey) {

        if (publicKey == null && isSignatureMissing(token)) {
            Jwt<Header, Claims> claims = Jwts.parserBuilder()
                    .setAllowedClockSkewSeconds(60)
                    .build()
                    .parseClaimsJwt(token);
            body = claims.getBody();
        } else {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .setAllowedClockSkewSeconds(60)
                    .build()
                    .parseClaimsJws(token);
            body = claims.getBody();
        }

        setTokenFields();
    }

    boolean isSignatureMissing(final String token) {
        return token.length() == token.lastIndexOf('.') + 1;
    }

    int parseIntegerValue(Claims body, final String claimName) {

        // if the object is not of our expected integer class
        // then we'll just return 0 and ignore all exceptions

        try {
            return body.get(claimName, Integer.class);
        } catch (Exception ignored) {
        }
        return 0;
    }

    long parseLongValue(Claims body, final String claimName) {

        // if the object is not of our expected long class
        // then we'll just return 0 and ignore all exceptions

        try {
            return body.get(claimName, Long.class);
        } catch (Exception ignored) {
        }
        return 0;
    }

    long parseDateValue(Date date) {

        // our date values are stored in seconds

        return date == null ? 0 : date.getTime() / 1000;
    }

    void setTokenFields() {
        setVersion(parseIntegerValue(body, CLAIM_VERSION));
        setAudience(body.getAudience());
        setExpiryTime(parseDateValue(body.getExpiration()));
        setIssueTime(parseDateValue(body.getIssuedAt()));
        setNotBeforeTime(parseDateValue(body.getNotBefore()));
        setAuthTime(parseLongValue(body, CLAIM_AUTH_TIME));
        setIssuer(body.getIssuer());
        setSubject(body.getSubject());
        setJwtId(body.getId());
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

    public long getNotBeforeTime() {
        return notBeforeTime;
    }

    public void setNotBeforeTime(long notBeforeTime) {
        this.notBeforeTime = notBeforeTime;
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

    public String getJwtId() {
        return jwtId;
    }

    public void setJwtId(String jwtId) {
        this.jwtId = jwtId;
    }
}
