/*
 * Copyright 2020 Yahoo Inc.
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
package com.yahoo.athenz.auth.oauth.token;

import java.util.Arrays;
import java.util.List;

/**
 * OAuth2 JWT access token object interface
 * @see <a href="https://tools.ietf.org/html/rfc7519" target="_top">RFC7519</a>
 * @see <a href="https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-03" target="_top">draft-ietf-oauth-access-token-jwt-03</a>
 * @see <a href="https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-19" target="_top">draft-ietf-oauth-token-exchange-19</a>
 * @see <a href="https://tools.ietf.org/html/draft-ietf-oauth-mtls-17" target="_top">draft-ietf-oauth-mtls-17</a>
 */
public interface OAuthJwtAccessToken {

    // claims
    public static final String CLAIM_CONFIRM = "cnf";
    public static final String CLAIM_CONFIRM_X509_HASH = "x5t#S256";
    public static final String CLAIM_SCOPE = "scope";
    public static final String CLAIM_CLIENT_ID = "client_id";

    // delimiters
    public static final String SCOPE_DELIMITER = " ";

    /**
     * @return JWT subject (sub)
     */
    public String getSubject();

    /**
     * @return JWT issuer (iss)
     */
    public String getIssuer();

    /**
     * @return JWT audience (aud)
     */
    public String getAudience();

    /**
     * @return JWT audiences (aud) as list
     */
    public List<String> getAudiences();

    /**
     * @return JWT client ID (client_id)
     */
    public String getClientId();

    /**
     * @return JWT certificate thumbprint (cnf['x5t#S256'])
     */
    public String getCertificateThumbprint();

    /**
     * @return JWT scope (scope)
     */
    public String getScope();

    /**
     * @return JWT scopes (scope) as List
     */
    public default List<String> getScopes() {
        if (this.getScope() == null) {
            return null;
        }
        return Arrays.asList(this.getScope().split(SCOPE_DELIMITER));
    }

    /**
     * @return JWT issued at (iat)
     */
    public long getIssuedAt();

    /**
     * @return JWT expiration time (exp)
     */
    public long getExpiration();

    /**
     * @return JWT getSignature
     */
    public String getSignature();

    /**
     * @return JWT as string in JAVA format
     */
    public String toString();

}
