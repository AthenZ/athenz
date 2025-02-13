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
import com.yahoo.athenz.auth.PublicKeyProvider;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.auth.util.StringUtils;

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
    protected String clientIdDomainName;
    protected String clientIdServiceName;
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

    public OAuth2Token(final String token, PublicKeyProvider publicKeyProvider, final String oauth2Issuer) {

        try {
            // first parse the token to extract the fields from the body and header

            SignedJWT signedJWT = SignedJWT.parse(token);

            // Extract and verify the claims (expiry, not before, etc.)

            claimsSet = signedJWT.getJWTClaimsSet();
            claimsVerifier.verify(claimsSet, null);

            // extract the issuer and subject of the token. for athenz supported case
            // these values must be present and equal

            final String issuer = claimsSet.getIssuer();
            final String subject = claimsSet.getSubject();
            if (StringUtils.isEmpty(issuer) || StringUtils.isEmpty(subject) || !issuer.equals(subject)) {
                throw new CryptoException("Invalid token: missing or mismatched issuer and subject");
            }

            // extract the audience of the token. for athenz support case this
            // value must be present and match the oidc issuer for the server

            final String audience = getClaimAudience();
            if (StringUtils.isEmpty(audience) || !audience.equals(oauth2Issuer)) {
                throw new CryptoException("Invalid token: missing or mismatched audience");
            }

            // our issuer/subject is the service identifier so we'll extract
            // the domain and service values

            int idx = subject.lastIndexOf('.');
            if (idx < 0) {
                throw new CryptoException("Invalid token: missing domain and service");
            }

            clientIdDomainName = subject.substring(0, idx);
            clientIdServiceName = subject.substring(idx + 1);

            // extract the key id from the header

            JWSHeader header = signedJWT.getHeader();
            String keyId = header.getKeyID();
            if (StringUtils.isEmpty(keyId)) {
                throw new CryptoException("Invalid token: missing key id");
            }

            // get the public key for the domain/service/key id
            // and create a verifier

            final PublicKey publicKey = publicKeyProvider.getServicePublicKey(clientIdDomainName, clientIdServiceName, keyId);
            if (publicKey == null) {
                throw new CryptoException("Invalid token: unable to get public key");
            }

            JWSVerifier verifier = JwtsHelper.getJWSVerifier(publicKey);
            if (!signedJWT.verify(verifier)) {
                throw new CryptoException("Unable to verify token signature");
            }

            // if we got this far then we have a valid token so
            // we'll set our claims set and extract the fields

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

        setVersion(JwtsHelper.getIntegerClaim(claimsSet, CLAIM_VERSION, 0));
        setAudience(getClaimAudience());
        setExpiryTime(parseDateValue(claimsSet.getExpirationTime()));
        setIssueTime(parseDateValue(claimsSet.getIssueTime()));
        setNotBeforeTime(parseDateValue(claimsSet.getNotBeforeTime()));
        setAuthTime(JwtsHelper.getLongClaim(claimsSet, CLAIM_AUTH_TIME, 0));
        setIssuer(claimsSet.getIssuer());
        setSubject(claimsSet.getSubject());
        setJwtId(claimsSet.getJWTID());
    }

    String getClaimAudience() {
        List<String> audiences = claimsSet.getAudience();
        if (audiences != null && !audiences.isEmpty()) {
            return audiences.get(0);
        }
        return null;
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

    public String getClientIdDomainName() {
        return clientIdDomainName;
    }

    public String getClientIdServiceName() {
        return clientIdServiceName;
    }
}
