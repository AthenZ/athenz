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

import com.nimbusds.jwt.JWTClaimsSet;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.instance.provider.AttrValidator;
import com.yahoo.athenz.instance.provider.AttrValidatorFactory;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.KubernetesDistributionValidator;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT;

public abstract class CommonKubernetesDistributionValidator implements KubernetesDistributionValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    static final String ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE = "athenz.zts.k8s_provider_attestation_expected_audience";
    static final String ZTS_PROP_K8S_PROVIDER_SUBJECT_ATTR_VALIDATOR_FACTORY_CLASS = "athenz.zts.k8s_provider_subject_attr_validator_factory_class";
    String k8sAttestationExpectedAudience;

    Map<String, JwtsSigningKeyResolver> issuersMap = new ConcurrentHashMap<>();
    JwtsHelper jwtsHelper = new JwtsHelper();
    Authorizer authorizer;
    static final String ACTION_LAUNCH = "launch";
    AttrValidator subjectValidator;

    @Override
    public void initialize(final SSLContext sslContext, final Authorizer authorizer) {
        k8sAttestationExpectedAudience = System.getProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE, "");
        this.authorizer = authorizer;
        this.subjectValidator = newSubjectAttrValidator(sslContext);
    }

    static AttrValidator newSubjectAttrValidator(final SSLContext sslContext) {
        final String factoryClass = System.getProperty(ZTS_PROP_K8S_PROVIDER_SUBJECT_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.DefaultInstanceK8SProviderSubjectValidatorFactory");
        LOGGER.info("K8S provider attestation Subject AttributeValidatorFactory class: {}", factoryClass);
        AttrValidatorFactory attrValidatorFactory;
        try {
            attrValidatorFactory = (AttrValidatorFactory) Class.forName(factoryClass).getConstructor().newInstance();
        } catch (Exception e) {
            LOGGER.error("Invalid K8S Provider attestation Subject AttributeValidatorFactory class: {}", factoryClass, e);
            throw new IllegalArgumentException("Invalid AttributeValidatorFactory class for K8S Provider attestation Subject AttributeValidatorFactory: ");
        }
        return attrValidatorFactory.create(sslContext);
    }

    String getIssuerFromToken(IdTokenAttestationData attestationData, StringBuilder errMsg) {
        String tokenWithoutSig = attestationData.getIdentityToken().
                substring(0, attestationData.getIdentityToken().lastIndexOf('.') + 1);

        // Split the JWT into its three parts and only parse
        // the second part which is the claims set (payload)

        JWTClaimsSet claimsSet = JwtsHelper.parseJWTWithoutSignature(tokenWithoutSig);
        final String issuer = claimsSet.getIssuer();
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
    public boolean validateAttestationData(InstanceConfirmation confirmation, IdTokenAttestationData attestationData,
            String issuer, StringBuilder errMsg) {
        IdToken idToken = validateIdToken(issuer, attestationData, errMsg);
        if (idToken == null) {
            errMsg.append("id_token in the attestation data is invalid.");
            return false;
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
        if (subjectValidator != null) {
            if (confirmation.getAttributes() != null) {
                confirmation.getAttributes().put(ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT, idToken.getSubject());
            }
            if (!subjectValidator.confirm(confirmation)) {
                errMsg.append("subject mismatch between attestation id_token=").append(idToken.getSubject())
                        .append(" and requested certificate=").append(confirmation.getDomain())
                        .append(".").append(confirmation.getService());
                return false;
            }
        }
        return true;
    }
}
