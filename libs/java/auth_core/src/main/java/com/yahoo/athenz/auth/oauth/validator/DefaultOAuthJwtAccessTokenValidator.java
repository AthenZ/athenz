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
package com.yahoo.athenz.auth.oauth.validator;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;

/**
 * Default implementation of OAuthJwtAccessTokenValidator
 */
public class DefaultOAuthJwtAccessTokenValidator implements OAuthJwtAccessTokenValidator {

    private final String trustedIssuer;
    private final Set<String> requiredAudiences;
    private final Set<String> requiredScopes;
    private final Map<String, Set<String>> authorizedClientIds;

    /**
     * create DefaultOAuthJwtAccessTokenValidator
     * @param  trustedIssuer       trusted issuer (not null, not empty)
     * @param  requiredAudiences   required audiences (not null, not empty)
     * @param  requiredScopes      required scopes (not null, not empty)
     * @param  authorizedClientIds whitelist of authorized client IDs (not null)
     */
    public DefaultOAuthJwtAccessTokenValidator(String trustedIssuer, Set<String> requiredAudiences, Set<String> requiredScopes, Map<String, Set<String>> authorizedClientIds) {

        // args checking
        if (trustedIssuer == null || trustedIssuer.isEmpty()) {
            throw new IllegalArgumentException("trusted issuers must be configured");
        }
        if (requiredAudiences == null || requiredAudiences.isEmpty()) {
            throw new IllegalArgumentException("required audiences must be configured");
        }
        if (requiredScopes == null || requiredScopes.isEmpty()) {
            throw new IllegalArgumentException("required scopes must be configured");
        }
        if (authorizedClientIds == null) {
            throw new IllegalArgumentException("client ID mapping must be configured");
        }

        this.trustedIssuer = trustedIssuer;
        this.requiredAudiences = requiredAudiences;
        this.requiredScopes = requiredScopes;
        this.authorizedClientIds = authorizedClientIds;
    }

    private void verifyIssuer(OAuthJwtAccessToken jwt) throws OAuthJwtAccessTokenException {
        String issuer = jwt.getIssuer();
        if (!this.trustedIssuer.equals(issuer)) {
            // trusted issuer NOT match
            throw new OAuthJwtAccessTokenException("iss not trusted: got=" + issuer);
        }
    }

    private void verifyAudiences(OAuthJwtAccessToken jwt) throws OAuthJwtAccessTokenException {
        List<String> audiences = jwt.getAudiences();
        if (audiences == null || !(new HashSet<>(audiences)).containsAll(this.requiredAudiences)) {
            // SOME required audiences NOT found
            String got = (audiences == null) ? "null" : String.join(", ", audiences);
            throw new OAuthJwtAccessTokenException("required aud not found: got=" + got);
        }
    }

    private void verifyScopes(OAuthJwtAccessToken jwt) throws OAuthJwtAccessTokenException {
        List<String> scopes = jwt.getScopes();
        if (scopes == null || !(new HashSet<>(scopes)).containsAll(this.requiredScopes)) {
            // SOME required scopes NOT found
            throw new OAuthJwtAccessTokenException("required scope not found: got=" + jwt.getScope());
        }
    }

    private void verifyCertificateThumbprint(OAuthJwtAccessToken jwt, String certificateThumbprint) throws OAuthJwtAccessTokenException {
        String certThumbprint = jwt.getCertificateThumbprint();
        if (certificateThumbprint == null && certThumbprint == null) {
            // skip when both null
            return;
        }
        if (certificateThumbprint == null || !certificateThumbprint.equals(certThumbprint)) {
            // certificate thumbprint NOT match with JWT
            throw new OAuthJwtAccessTokenException(String.format("client certificate thumbprint (%s) not match: got=%s", certificateThumbprint, certThumbprint));
        }
    }

    private void verifyClientId(OAuthJwtAccessToken jwt, String certificatePrincipal) throws OAuthJwtAccessTokenException {
        String clientId = jwt.getClientId();
        Set<String> validClientIds = this.authorizedClientIds.get(certificatePrincipal);
        if (validClientIds == null) {
            throw new OAuthJwtAccessTokenException(String.format("NO mapping of authorized client IDs for certificate principal (%s)", certificatePrincipal));
        }
        if (!validClientIds.contains(clientId)) {
            throw new OAuthJwtAccessTokenException(String.format("client_id is not authorized for certificate principal (%s): got=%s", certificatePrincipal, clientId));
        }
    }

    @Override
    public void validate(OAuthJwtAccessToken jwt) throws OAuthJwtAccessTokenException {
        this.verifyIssuer(jwt);
        this.verifyAudiences(jwt);
        this.verifyScopes(jwt);

        if (jwt.getExpiration() <= 0L) {
            throw new OAuthJwtAccessTokenException("exp is empty");
        }
    }

    @Override
    public void validateClientId(OAuthJwtAccessToken jwt, String clientId) throws OAuthJwtAccessTokenException {
        this.verifyClientId(jwt, clientId);
    }

    @Override
    public void validateCertificateBinding(OAuthJwtAccessToken jwt, String certificateThumbprint) throws OAuthJwtAccessTokenException {
        this.verifyCertificateThumbprint(jwt, certificateThumbprint);
    }

}
