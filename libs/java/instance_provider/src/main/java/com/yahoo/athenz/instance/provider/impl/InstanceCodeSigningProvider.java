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

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.instance.provider.*;
import com.yahoo.rdl.JSON;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.util.HashMap;
import java.util.Map;

public class InstanceCodeSigningProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceCodeSigningProvider.class);
    static final String CODE_SIGNING_PROP_CERT_VALIDITY = "athenz.zts.code_signing_cert_validity";
    static final String ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS = "athenz.zts.code_signing_attr_validator_factory_class";
    static final String ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI = "athenz.zts.code_signing_oidc_provider_openid_config_uri";
    static final String ZTS_PROP_ZTS_OPENID_ISSUER = "athenz.zts.openid_issuer";

    static final String ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE = "athenz.zts.code_signing_attestation_expected_audience";
    int certValidityTime;
    AttrValidator attrValidator;
    JwtsSigningKeyResolver signingKeyResolver;
    String codeSigningOidcProviderJwksUri;

    String codeSigningAttestationExpectedAudience;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(String provider, String endpoint, SSLContext sslContext, KeyStore keyStore) {
        certValidityTime = Integer.parseInt(System.getProperty(CODE_SIGNING_PROP_CERT_VALIDITY, "15"));
        this.attrValidator = newAttrValidator(sslContext);

        final String ztsOpenIdConfigUri = System.getProperty(ZTS_PROP_ZTS_OPENID_ISSUER) + "/.well-known/openid-configuration";
        final String openIdConfigUri = System.getProperty(ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI, ztsOpenIdConfigUri);
        JwtsHelper helper = new JwtsHelper();
        codeSigningOidcProviderJwksUri = helper.extractJwksUri(openIdConfigUri, sslContext);

        if (StringUtil.isEmpty(codeSigningOidcProviderJwksUri)) {
            LOGGER.error("configured oidc provider for code signing does not have valid jwks uri - no code signing certificates will be issued");
        }
        signingKeyResolver = new JwtsSigningKeyResolver(codeSigningOidcProviderJwksUri, sslContext, true);
         if (signingKeyResolver.publicKeyCount() == 0) {
            LOGGER.error("No code signing oidc provider public keys available - no code signing certificates will be issued");
        }
        codeSigningAttestationExpectedAudience = System.getProperty(ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE, "");
    }

    static AttrValidator newAttrValidator(final SSLContext sslContext) {
        final String factoryClass = System.getProperty(ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS);
        if (factoryClass == null) {
            return null;
        }

        AttrValidatorFactory attrValidatorFactory;
        try {
            attrValidatorFactory = (AttrValidatorFactory) Class.forName(factoryClass).getConstructor().newInstance();
        } catch (Exception e) {
            LOGGER.error("Invalid AttributeValidatorFactory class: {}", factoryClass, e);
            throw new IllegalArgumentException("Invalid AttributeValidatorFactory class");
        }

        return attrValidatorFactory.create(sslContext);
    }
    public ResourceException error(String message) {
        return error(ResourceException.FORBIDDEN, message);
    }

    public ResourceException error(int errorCode, String message) {
        LOGGER.error(message);
        return new ResourceException(errorCode, message);
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {
        IdTokenAttestationData attestationData = JSON.fromString(confirmation.getAttestationData(),
                IdTokenAttestationData.class);

        IdToken idToken;
        // first make sure we have a valid id_token provided by the configured OIDC provider
        try {
            idToken = new IdToken(attestationData.getIdentityToken(), signingKeyResolver);
        } catch (Exception ex) {
            throw error("invalid attestation data for code signing certificate request");
        }

        // next make sure the id_token audience matches with configuration
        if (!codeSigningAttestationExpectedAudience.equals(idToken.getAudience())) {
            throw error("attestation id_token does not contain expected audience. provided audience=" + idToken.getAudience());
        }

        // next make sure code signing certificate is requested for id_token subject
        String csrPrincipal = confirmation.getDomain() + "." + confirmation.getService();
        if (!idToken.getSubject().equals(csrPrincipal)) {
            throw error("subject mismatch between attestation id_token=" + idToken.getSubject() +
                    " and requested certificate=" + csrPrincipal);
        }

        // Confirm the instance attributes as per the attribute validator
        if (attrValidator != null && !attrValidator.confirm(confirmation)) {
            throw error("Unable to validate request instance attributes using attributeValidator=" + attrValidator);
        }

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_CERT_EXPIRY_TIME, Long.toString(certValidityTime));
        attributes.put(ZTS_CERT_USAGE, ZTS_CERT_USAGE_CODE_SIGNING);
        attributes.put(ZTS_CERT_REFRESH, "false");
        confirmation.setAttributes(attributes);

        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {
        // we do not allow refresh of code signing certificates
        throw error("Code signing X.509 Certificates cannot be refreshed");
    }
}
