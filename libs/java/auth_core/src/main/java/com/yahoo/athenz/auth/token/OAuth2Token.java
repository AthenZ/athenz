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

import com.nimbusds.jose.*;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.CryptoException;

import java.security.PublicKey;
import java.util.Date;
import java.util.List;

public class OAuth2Token {

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
    protected JWTClaimsSet claimsSet = null;
    protected static DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<>(null, null);

    public OAuth2Token() {
    }

    public OAuth2Token(final String token, JwtsSigningKeyResolver keyResolver) {

        try {

            // if the keyResolver is null and the token does not have
            // a signature we're going to treat and parse it as a jwt
            // without any claim validation

            if (keyResolver == null) {
                claimsSet = JwtsHelper.parseJWTWithoutSignature(token);
            } else {

                // create a processor and process the token which does signature verification
                // along with standard claims validation (expiry, not before, etc.)

                ConfigurableJWTProcessor<SecurityContext> jwtProcessor = JwtsHelper.getJWTProcessor(keyResolver);
                claimsSet = jwtProcessor.process(token, null);
            }

            setTokenFields();

        } catch (Exception ex) {
            throw new CryptoException("Unable to parse token: " + ex.getMessage());
        }
    }

    public OAuth2Token(final String token, PublicKey publicKey) {

        try {

            // if the public key is null and the token does not have
            // a signature we're going to treat and parse it as a jwt
            // without any claim validation

            if (publicKey == null) {
                claimsSet = JwtsHelper.parseJWTWithoutSignature(token);
            } else {

                // Create a verifier and parse the token and verify the signature

                JWSVerifier verifier = JwtsHelper.getJWSVerifier(publicKey);
                SignedJWT signedJWT = SignedJWT.parse(token);
                if (!signedJWT.verify(verifier)) {
                    throw new CryptoException("Unable to verify token signature");
                }

                // Extract and verify the claims (expiry, not before, etc.)

                claimsSet = signedJWT.getJWTClaimsSet();
                claimsVerifier.verify(claimsSet, null);
            }

            setTokenFields();

        } catch (Exception ex) {
            throw new CryptoException("Unable to parse token: " + ex.getMessage());
        }
    }

    // our date values are stored in seconds

    long parseDateValue(Date date) {
        return date == null ? 0 : date.getTime() / 1000;
    }

    void setTokenFields() {

        setVersion(JwtsHelper.getIntegerClaim(claimsSet, CLAIM_VERSION));
        List<String> audiences = claimsSet.getAudience();
        if (audiences != null && !audiences.isEmpty()) {
            setAudience(audiences.get(0));
        }
        setExpiryTime(parseDateValue(claimsSet.getExpirationTime()));
        setIssueTime(parseDateValue(claimsSet.getIssueTime()));
        setNotBeforeTime(parseDateValue(claimsSet.getNotBeforeTime()));
        setAuthTime(JwtsHelper.getLongClaim(claimsSet, CLAIM_AUTH_TIME));
        setIssuer(claimsSet.getIssuer());
        setSubject(claimsSet.getSubject());
        setJwtId(claimsSet.getJWTID());
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
