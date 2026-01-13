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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class IdToken extends OAuth2Token {

    private static final Logger LOG = LoggerFactory.getLogger(IdToken.class);

    public static final String CLAIM_GROUPS = "groups";
    public static final String CLAIM_NONCE  = "nonce";
    public static final String CLAIM_SPIFFE  = "spiffe";

    private List<String> groups;
    private String nonce;
    private String spiffe;

    /**
     * Creates an empty id token
     */
    public IdToken() {
        super();
    }

    /**
     * Parses and validates the given token based on the keyResolver
     *
     * @param token       id token
     * @param keyResolver JwtsSigningKeyResolver key resolver providing
     *                    the public key for token signature validation
     */
    public IdToken(final String token, JwtsSigningKeyResolver keyResolver) {
        super(token, keyResolver);
        setIdTokenFields();
    }

    /**
     * Parses and validates the given token based on the given public key
     *
     * @param token     id token
     * @param publicKey the public key for token signature validation
     */
    public IdToken(final String token, PublicKey publicKey) {
        super(token, publicKey);
        setIdTokenFields();
    }

    /**
     * Parse and validates the given token based on the given jwtProcessor
     *
     * @param token        id token
     * @param jwtProcessor jwt processor for token signature validation
     */
    public IdToken(final String token, ConfigurableJWTProcessor<SecurityContext> jwtProcessor) {
        super(token, jwtProcessor);
        setIdTokenFields();
    }

    void setIdTokenFields() {
        setNonce(JwtsHelper.getStringClaim(claimsSet, CLAIM_NONCE));
        setGroups(JwtsHelper.getStringListClaim(claimsSet, CLAIM_GROUPS));
        setSpiffe(JwtsHelper.getStringClaim(claimsSet, CLAIM_SPIFFE));
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

    public String getSpiffe() {
        return spiffe;
    }

    public void setSpiffe(String spiffe) {
        this.spiffe = spiffe;
    }

    public String getSignedToken(final PrivateKey key, final String keyId, final String sigAlg) {

        try {
            JWSSigner signer = JwtsHelper.getJWSSigner(key);
            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issueTime(Date.from(Instant.ofEpochSecond(issueTime)))
                    .expirationTime(Date.from(Instant.ofEpochSecond(expiryTime)))
                    .issuer(issuer)
                    .audience(audience)
                    .claim(CLAIM_AUTH_TIME, authTime)
                    .claim(CLAIM_VERSION, version)
                    .claim(CLAIM_GROUPS, groups)
                    .claim(CLAIM_NONCE, nonce)
                    .claim(CLAIM_SPIFFE, spiffe);
            if (customClaims != null) {
                for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
                    claimsSetBuilder.claim(entry.getKey(), entry.getValue());
                }
            }
            JWTClaimsSet claimsSet = claimsSetBuilder.build();
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.parse(sigAlg))
                            .keyID(keyId)
                            .build(),
                    claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException ex) {
            LOG.error("Unable to sign JWT token", ex);
            return null;
        }
    }

    @Override
    public boolean isStandardClaim(final String claimName) {
        if (super.isStandardClaim(claimName)) {
            return true;
        }
        switch (claimName) {
            case CLAIM_GROUPS:
            case CLAIM_NONCE:
            case CLAIM_SPIFFE:
                return true;
            default:
                return false;
        }
    }
}
