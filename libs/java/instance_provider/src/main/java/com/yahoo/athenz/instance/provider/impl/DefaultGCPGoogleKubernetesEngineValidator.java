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

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv;
import com.yahoo.athenz.instance.provider.AttrValidator;
import com.yahoo.athenz.instance.provider.AttrValidatorFactory;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import javax.net.ssl.SSLContext;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.*;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;
import static com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider.*;

public class DefaultGCPGoogleKubernetesEngineValidator extends CommonKubernetesDistributionValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    Set<String> gcpDNSSuffixes = new HashSet<>();
    List<String> gkeDnsSuffixes;
    DynamicConfigCsv gkeClusterNames;

    private static final DefaultGCPGoogleKubernetesEngineValidator INSTANCE = new DefaultGCPGoogleKubernetesEngineValidator();
    static final String GCP_OIDC_ISSUER_PREFIX = "https://container.googleapis.com/v1/projects/";
    AttrValidator attrValidator;
    static final String ZTS_PROP_K8S_PROVIDER_GCP_ATTR_VALIDATOR_FACTORY_CLASS = "athenz.zts.k8s_provider_gcp_attr_validator_factory_class";

    public static DefaultGCPGoogleKubernetesEngineValidator getInstance() {
        return INSTANCE;
    }
    private DefaultGCPGoogleKubernetesEngineValidator() {
    }

    static AttrValidator newAttrValidator(final SSLContext sslContext) {
        final String factoryClass = System.getProperty(ZTS_PROP_K8S_PROVIDER_GCP_ATTR_VALIDATOR_FACTORY_CLASS);
        LOGGER.info("GCP K8S AttributeValidatorFactory class: {}", factoryClass);
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

    @Override
    public void initialize(final SSLContext sslContext, Authorizer authorizer) {
        super.initialize(sslContext, authorizer);
        final String dnsSuffix = System.getProperty(GCP_PROP_DNS_SUFFIX);
        if (!StringUtil.isEmpty(dnsSuffix)) {
            gcpDNSSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));
        }
        // get our allowed gke dns suffixes
        gkeDnsSuffixes = InstanceUtils.processK8SDnsSuffixList(GCP_PROP_GKE_DNS_SUFFIX);
        // get our dynamic list of gke cluster names
        gkeClusterNames = new DynamicConfigCsv(CONFIG_MANAGER, GCP_PROP_GKE_CLUSTER_NAMES, null);
        this.attrValidator = newAttrValidator(sslContext);
    }

    @Override
    public String validateIssuer(InstanceConfirmation confirmation, IdTokenAttestationData attestationData, StringBuilder errMsg) {
        String issuer = getIssuerFromToken(attestationData, errMsg);
        if (StringUtil.isEmpty(issuer)) {
            return null;
        }
        String gcpProject = confirmation.getAttributes().get(InstanceProvider.ZTS_INSTANCE_GCP_PROJECT);
        if (!issuer.startsWith(GCP_OIDC_ISSUER_PREFIX + gcpProject)) {
            // could be a multi-tenant setup where the issuer is not present in the identity's GCP project
            if (attrValidator != null) {
                confirmation.getAttributes().put(ZTS_INSTANCE_UNATTESTED_ISSUER, issuer);
                // Confirm the issuer as per the attribute validator
                if (!attrValidator.confirm(confirmation)) {
                    return null;
                }
            } else {
                errMsg.append("Issuer is not present in the GCP project associated with the domain");
                return null;
            }
        } else {
            // issuer exists in the same GCP project as the requested identity
            confirmation.getAttributes().put(ZTS_INSTANCE_ISSUER_GCP_PROJECT, gcpProject);
        }

        final String domainName = confirmation.getDomain();
        final String serviceName = confirmation.getService();
        // attribute set after verification above or attribute validation
        final String issuerGcpProject = confirmation.getAttributes().get(ZTS_INSTANCE_ISSUER_GCP_PROJECT);
        final String resource = String.format("%s:%s:%s", domainName, serviceName, issuerGcpProject);

        Principal principal = SimplePrincipal.create(domainName, serviceName, (String) null);
        boolean accessCheck = authorizer.access(ACTION_LAUNCH, resource, principal, null);
        if (!accessCheck) {
            errMsg.append("gke launch authorization check failed for action: ").append(ACTION_LAUNCH)
                    .append(" resource: ").append(resource);
            return null;
        }
        return issuer;
    }

    @Override
    public boolean validateSanDNSEntries(InstanceConfirmation confirmation, StringBuilder errMsg) {
        StringBuilder instanceId = new StringBuilder(256);
        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String gcpProject = InstanceUtils.getInstanceProperty(instanceAttributes, ZTS_INSTANCE_GCP_PROJECT);
        if (StringUtil.isEmpty(gcpProject)) {
            errMsg.append("Unable to find GCP project id");
            return false;
        }
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, confirmation.getDomain(),
                confirmation.getService(), gcpDNSSuffixes, gkeDnsSuffixes, gkeClusterNames.getStringsList(),
                true, instanceId, null)) {
            errMsg.append("Unable to validate certificate request hostnames");
            return false;
        }
        return true;
    }
}
