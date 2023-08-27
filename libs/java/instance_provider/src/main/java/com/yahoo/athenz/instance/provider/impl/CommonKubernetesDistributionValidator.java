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
package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.KubernetesDistributionValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public abstract class CommonKubernetesDistributionValidator implements KubernetesDistributionValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static final String ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE = "athenz.zts.k8s_provider_attestation_expected_audience";
    String k8sAttestationExpectedAudience;

    Map<String, JwtsSigningKeyResolver> issuersMap = new ConcurrentHashMap<>();
    JwtsHelper jwtsHelper = new JwtsHelper();

    @Override
    public void initialize() {
        k8sAttestationExpectedAudience = System.getProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE, "");
    }

    String getIssuerFromToken(IdTokenAttestationData attestationData, StringBuilder errMsg) {
        String tokenWithoutSig = attestationData.getIdentityToken().
                substring(0, attestationData.getIdentityToken().lastIndexOf('.') + 1);

        Jwt<Header, Claims> claims = Jwts.parserBuilder()
                .setAllowedClockSkewSeconds(60)
                .build()
                .parseClaimsJwt(tokenWithoutSig);
        String issuer = claims.getBody().getIssuer();
        if (StringUtil.isEmpty(issuer)) {
            errMsg.append("No issuer present in the attestation data token. Possibly malformed token");
        }
        return issuer;
    }

    JwtsSigningKeyResolver getSigningKeyResolverForIssuer(String idTokenIssuer, StringBuilder errMsg) {
        JwtsSigningKeyResolver signingKeyResolver;
        signingKeyResolver = this.issuersMap.get(idTokenIssuer);
        if (signingKeyResolver == null) {
            String openIdConfigUri = idTokenIssuer + "/.well-known/openid-configuration";
            String oidcProviderJwksUri = this.jwtsHelper.extractJwksUri(openIdConfigUri, null);
            if (StringUtil.isEmpty(oidcProviderJwksUri)) {
                errMsg.append("id_token issuer does not have valid jwks uri.");
                return null;
            }
            signingKeyResolver = new JwtsSigningKeyResolver(oidcProviderJwksUri, null, true);
            if (signingKeyResolver.publicKeyCount() == 0) {
                errMsg.append("No id_token issuer public keys available.");
                return null;
            }
            this.issuersMap.put(idTokenIssuer, signingKeyResolver);
        }
        return signingKeyResolver;
    }

    IdToken validateIdToken(final String issuer, IdTokenAttestationData attestationData, StringBuilder errMsg) {
        JwtsSigningKeyResolver signingKeyResolver = getSigningKeyResolverForIssuer(issuer, errMsg);
        IdToken idToken = null;
        try {
            idToken = new IdToken(attestationData.getIdentityToken(), signingKeyResolver);
        } catch (Exception ex) {
            errMsg.append("invalid attestation data for K8S certificate request.");
        }
        return idToken;
    }

    @Override
    public boolean validateAttestationData(InstanceConfirmation confirmation, IdTokenAttestationData attestationData, String issuer, StringBuilder errMsg) {
        IdToken idToken = validateIdToken(issuer, attestationData, errMsg);
        if (idToken == null) {
            LOGGER.warn("No valid id_token found. Refresh public keys and retry once. current error={}", errMsg);
            this.issuersMap.get(issuer).loadPublicKeysFromServer();
            idToken = validateIdToken(issuer, attestationData, errMsg);
            if (idToken == null) {
                errMsg.append("id_token in the attestation data is invalid.");
                return false;
            }
        }

        // next make sure the id_token audience matches with configuration
        if (!k8sAttestationExpectedAudience.equals(idToken.getAudience())) {
            errMsg.append("attestation id_token does not contain expected audience. provided audience=")
                    .append(idToken.getAudience());
            return false;
        }

        return validateSubject(confirmation, idToken, errMsg);
    }

    boolean validateSubject(final InstanceConfirmation confirmation, final IdToken idToken, final StringBuilder errMsg) {
        // next make sure id_token subject is the right service account name in the form of $domain.$service
        // and K8S workload certificate is requested for the same $domain.$service
        String csrPrincipal = confirmation.getDomain() + "." + confirmation.getService();
        String idTokenSub = InstanceUtils.getServiceAccountNameFromIdTokenSubject(idToken.getSubject());
        if (!csrPrincipal.equals(idTokenSub)) {
            errMsg.append("subject mismatch between attestation id_token=").append(idTokenSub)
                    .append(" and requested certificate=").append(csrPrincipal);
            return false;
        }
        return true;
    }

}
