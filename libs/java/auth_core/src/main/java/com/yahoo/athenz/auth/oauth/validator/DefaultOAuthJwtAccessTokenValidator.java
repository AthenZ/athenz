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

    private String trustedIssuer = null;
    private Set<String> requiredAudiences = null;
    private Set<String> requiredScopes = null;
    private Map<String, Set<String>> clientIdsMap = null;

    /**
     * create DefaultOAuthJwtAccessTokenValidator
     * @param  trustedIssuer     trusted issuer (not null, not empty)
     * @param  requiredAudiences required audiences (not null, not empty)
     * @param  requiredScopes    required scopes (not null, not empty)
     * @param  clientIdsMap      client IDs map (not null)
     */
    public DefaultOAuthJwtAccessTokenValidator(String trustedIssuer, Set<String> requiredAudiences, Set<String> requiredScopes, Map<String, Set<String>> clientIdsMap) {

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
        if (clientIdsMap == null) {
            throw new IllegalArgumentException("client ID mapping must be configured");
        }

        this.trustedIssuer = trustedIssuer;
        this.requiredAudiences = requiredAudiences;
        this.requiredScopes = requiredScopes;
        this.clientIdsMap = clientIdsMap;
    }

    private Set<String> certificatePrincipalToClientIds(String certificatePrincipal) {
        return this.clientIdsMap.get(certificatePrincipal);
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
        if (certificateThumbprint == certThumbprint) {
            return;
        }
        if (certificateThumbprint == null || certThumbprint == null || !certificateThumbprint.equals(certThumbprint)) {
            // certificate thumbprint NOT match with JWT
            throw new OAuthJwtAccessTokenException(String.format("client certificate thumbprint (%s) not match: got=%s", certificateThumbprint, certThumbprint));
        }
    }
    private void verifyClientId(OAuthJwtAccessToken jwt, String certificatePrincipal) throws OAuthJwtAccessTokenException {
        String clientId = jwt.getClientId();
        Set<String> knownClientIds = this.certificatePrincipalToClientIds(certificatePrincipal);
        if (knownClientIds == null) {
            if (certificatePrincipal == clientId) {
                return;
            }
            if (certificatePrincipal == null || clientId == null || !certificatePrincipal.equals(clientId.toLowerCase())) { // Athenz principal is in lowercase
                // non-mapped client certificate principal NOT match with JWT
                throw new OAuthJwtAccessTokenException(String.format("non-mapped client certificate principal (%s) not match with client_id: got=%s", certificatePrincipal, clientId));
            }
        } else {
            if (!knownClientIds.contains(clientId)) {
                // mapped client certificate principal NOT match with JWT
                throw new OAuthJwtAccessTokenException(String.format("mapped client certificate principal (%s) not match with client_id: got=%s", certificatePrincipal, clientId));
            }
        }
    }

    @Override
    public void validate(OAuthJwtAccessToken jwt) throws OAuthJwtAccessTokenException {
        this.verifyIssuer(jwt);
        this.verifyAudiences(jwt);
        this.verifyScopes(jwt);
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
