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

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PublicKeyProvider;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.auth.util.StringUtils;

import java.security.PublicKey;

public class ZTSAccessToken extends AccessToken {

    private static final String ACTION_INTROSPECT = "introspect";
    private static final String RESOURCE_TOKEN = ":token";
    private static final String SYS_AUTH_DOMAIN = "sys.auth";
    private static final String ZTS_SERVICE = "zts";

    public ZTSAccessToken(final String token, PublicKeyProvider publicKeyProvider, Authorizer authorizer, Principal principal) {

        try {
            // make sure the required arguments are provided

            if (token == null || publicKeyProvider == null || authorizer == null || principal == null) {
                throw new CryptoException("Invalid arguments: missing token, public key provider, authorizer or principal");
            }

            // first parse the token to extract the fields from the body and header

            SignedJWT signedJWT = SignedJWT.parse(token);
            claimsSet = signedJWT.getJWTClaimsSet();

            // extract the audience of the token which is our domain name

            final String audience = getClaimAudience();
            if (StringUtils.isEmpty(audience)) {
                throw new CryptoException("Invalid token: missing audience");
            }

            // authorize our introspect request. The action is introspect and the
            // resource is the audience + ":token".

            if (!authorizer.access(ACTION_INTROSPECT, audience + RESOURCE_TOKEN, principal, null)) {
                throw new CryptoException("unauthorized introspect request");
            }

            // verify the claims (expiry, not before, etc.)

            claimsVerifier.verify(claimsSet, null);

            // extract the key id from the header

            JWSHeader header = signedJWT.getHeader();
            String keyId = header.getKeyID();
            if (StringUtils.isEmpty(keyId)) {
                throw new CryptoException("Invalid token: missing key id");
            }

            // get the public key for the zts server for the given key id
            // and create a verifier

            final PublicKey publicKey = publicKeyProvider.getServicePublicKey(SYS_AUTH_DOMAIN, ZTS_SERVICE, keyId);
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
            setAccessTokenFields();

        } catch (Exception ex) {
            throw new CryptoException("Unable to parse token: " + ex.getMessage());
        }
    }
}
