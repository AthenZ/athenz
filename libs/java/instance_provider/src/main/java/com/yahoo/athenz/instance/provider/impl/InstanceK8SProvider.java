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
import com.yahoo.athenz.instance.provider.*;
import com.yahoo.rdl.JSON;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class InstanceK8SProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceK8SProvider.class);
    static final String ZTS_PROP_K8S_CERT_VALIDITY = "athenz.zts.k8s_cert_validity";
    static final String ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS = "athenz.zts.k8s_provider_distribution_validator_factory_class";
    long certValidityTime;

    KubernetesDistributionValidatorFactory kubernetesDistributionValidatorFactory;

    Map<String, KubernetesDistributionValidator> kubernetesDistributionValidatorMap;
    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    public ResourceException error(String message) {
        return error(ResourceException.FORBIDDEN, message);
    }

    public ResourceException error(int errorCode, String message) {
        LOGGER.error(message);
        return new ResourceException(errorCode, message);
    }

    @Override
    public void initialize(String provider, String endpoint, SSLContext sslContext, KeyStore keyStore) {
        int certValidityDays = Integer.parseInt(System.getProperty(ZTS_PROP_K8S_CERT_VALIDITY, "7"));
        certValidityTime = TimeUnit.MINUTES.convert(certValidityDays, TimeUnit.DAYS);
        kubernetesDistributionValidatorFactory = newKubernetesDistributionValidatorFactory();
        if (kubernetesDistributionValidatorFactory != null) {
            kubernetesDistributionValidatorFactory.initialize();
            kubernetesDistributionValidatorMap = kubernetesDistributionValidatorFactory.getSupportedDistributions();
            kubernetesDistributionValidatorMap.forEach((key, value) -> value.initialize());
        }
    }

     KubernetesDistributionValidatorFactory newKubernetesDistributionValidatorFactory() {
        final String factoryClass = System.getProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS);
        if (factoryClass == null) {
            return null;
        }
         KubernetesDistributionValidatorFactory tempKubernetesDistributionValidatorFactory;
        try {
            tempKubernetesDistributionValidatorFactory = (KubernetesDistributionValidatorFactory) Class.forName(factoryClass).getConstructor().newInstance();
        } catch (Exception e) {
            LOGGER.error("Invalid KubernetesDistributionValidatorFactory class: {}", factoryClass, e);
            throw new IllegalArgumentException("Invalid KubernetesDistributionValidatorFactory class");
        }
        return tempKubernetesDistributionValidatorFactory;
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {
        IdTokenAttestationData attestationData = JSON.fromString(confirmation.getAttestationData(),
                IdTokenAttestationData.class);

        final Map<String, String> instanceAttributes = confirmation.getAttributes();

        KubernetesDistributionValidator kubernetesDistributionValidator =
                kubernetesDistributionValidatorMap.get(instanceAttributes.get(ZTS_INSTANCE_CLOUD));

        if (kubernetesDistributionValidator == null) {
            throw error("Provided cloud is not supported");
        }

        StringBuilder errMsg = new StringBuilder(256);

        // first lets get the issuer from the id_token and verify it
        // no signature verification since we don't have the issuer public keys yet.
        String issuer = kubernetesDistributionValidator.validateIssuer(confirmation, attestationData, errMsg);
        if (StringUtil.isEmpty(issuer)) {
            throw error("Issuer is invalid or issuer validation failed. Additional details=" + errMsg);
        }

        // now that we have verified the issuer, lets validate the id_token signature in attestationData
        if (!kubernetesDistributionValidator.validateAttestationData(confirmation, attestationData, issuer, errMsg)) {
            throw error("id_token in the attestation data is invalid. Additional details=" + errMsg);
        }

        // next validate the san dns entries in the certificate request
        if (!kubernetesDistributionValidator.validateSanDNSEntries(confirmation, errMsg)) {
            throw error("Unable to validate certificate request hostnames. Additional details=" + errMsg);
        }

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_CERT_EXPIRY_TIME, Long.toString(certValidityTime));
        attributes.put(ZTS_CERT_REFRESH, "false");
        confirmation.setAttributes(attributes);

        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {
        // we do not allow refresh of K8S certificates
        throw error("Generic K8S X.509 Certificates cannot be refreshed");
    }
}
