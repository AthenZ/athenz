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
package com.yahoo.athenz.auth.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServiceIdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Date;

public class ServiceIdentityJWTSecretProvider implements ServiceIdentityProvider {

    private static final Logger LOG = LoggerFactory.getLogger(ServiceIdentityJWTSecretProvider.class);

    private static final String OAUTH_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    final String clientId;
    final String audience;
    final byte[] secret;
    final int expiryTimeSecs;
    JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    /**
     * Constructs a new ServiceIdentityJWTSecretProvider.The provider can
     * be used in the ZTS Client when requesting access tokens based on the
     * JWT bearer assertion type.
     *
     * @param clientId the client identifier to use as the JWT subject and issuer
     * @param audience the audience for the JWT
     * @param expiryTimeSecs the expiration time for the JWT, in seconds
     * @param secret the HMAC secret key as a byte array
     */
    public ServiceIdentityJWTSecretProvider(final String clientId, final String audience, int expiryTimeSecs,
            final byte[] secret) {

        this.clientId = clientId;
        this.audience = audience;
        this.expiryTimeSecs = expiryTimeSecs;
        this.secret = secret;
    }

    /**
     * Sets the JWS algorithm to be used for signing the JWT.
     *
     * @param jwsAlgorithm the JWS algorithm as a string (e\.g\., "HS256", "HS384")
     */
    public void setKeyAlgorithm(final String jwsAlgorithm) {
        this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm);
    }

    /**
     * Returns the principal identity for the specified domain and service.
     * This implementation returns null.
     *
     * @param domainName the domain name
     * @param serviceName the service name
     * @return the principal identity, or null if not implemented
     */
    @Override
    public Principal getIdentity(String domainName, String serviceName) {
        return null;
    }

    /**
     * Returns the OAuth client assertion type for JWT bearer.
     *
     * @return the client assertion type string
     */
    @Override
    public String getClientAssertionType() {
        return OAUTH_ASSERTION_TYPE_JWT_BEARER;
    }

    /**
     * Generates and returns a signed JWT client assertion value.
     *
     * @return the serialized signed JWT, or null if an error occurs
     */
    @Override
    public String getClientAssertionValue() {

        try {
            long now = System.currentTimeMillis() / 1000;
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(clientId)
                    .issueTime(Date.from(Instant.ofEpochSecond(now)))
                    .expirationTime(Date.from(Instant.ofEpochSecond(now + expiryTimeSecs)))
                    .issuer(clientId)
                    .audience(audience)
                    .build();

            // Create HMAC signer

            JWSSigner signer = new MACSigner(secret);
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(jwsAlgorithm), claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();

        } catch (Exception ex) {
            LOG.error("Failed to create client assertion token", ex);
            return null;
        }
    }
}
