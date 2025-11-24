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

package com.yahoo.athenz.auth;

import com.yahoo.athenz.auth.token.OAuth2Token;

import java.util.List;

public interface TokenExchangeIdentityProvider {

    /**
     * Return the corresponding athenz identity for the principal identity
     * from the given token. The token has already been validated by the server.
     * This could be used when issuing JAG tokens and the subject token is issued
     * by an external Identity Provider. Similarly, it could be used when exchanging
     * JAG tokens from an external Identity Provider with an Athenz issued access
     * token.
     *
     * @param token validated oauth2 token from external Identity Provider
     * @return the identity of the token in Athenz system.
     */
    String getTokenIdentity(OAuth2Token token);

    /**
     * Return the audience value to be used for the token exchange.
     * Typically, if this is an ID token then the audience would be
     * included in the aud claim. However, if this is an access token
     * then the audience might be a different value and the actual client
     * id would be included in the cid or a different claim.
     *
     * @param token validated oauth2 token from external Identity Provider
    *  @return the audience value
     */
    String getTokenAudience(OAuth2Token token);

    /**
     * Return the list of claims that should be included in the
     * generated token as part of the exchange request in addition
     * to the standard claims (iss, sub, aud, exp, iat, scp).
     * @return list of claim names
     */
    List<String> getTokenExchangeClaims();
}
