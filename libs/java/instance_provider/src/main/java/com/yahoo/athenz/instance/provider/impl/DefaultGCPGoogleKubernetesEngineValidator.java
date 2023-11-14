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

import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import org.eclipse.jetty.util.StringUtil;

import java.util.*;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;
import static com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider.*;

public class DefaultGCPGoogleKubernetesEngineValidator extends CommonKubernetesDistributionValidator {

    Set<String> gcpDNSSuffixes = new HashSet<>();
    List<String> gkeDnsSuffixes;
    DynamicConfigCsv gkeClusterNames;

    private static final DefaultGCPGoogleKubernetesEngineValidator INSTANCE = new DefaultGCPGoogleKubernetesEngineValidator();
    static final String GCP_OIDC_ISSUER_PREFIX = "https://container.googleapis.com/v1/projects/";

    public static DefaultGCPGoogleKubernetesEngineValidator getInstance() {
        return INSTANCE;
    }
    private DefaultGCPGoogleKubernetesEngineValidator() {
    }

    @Override
    public void initialize() {
        super.initialize();
        final String dnsSuffix = System.getProperty(GCP_PROP_DNS_SUFFIX);
        if (!StringUtil.isEmpty(dnsSuffix)) {
            gcpDNSSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));
        }
        // get our allowed gke dns suffixes
        gkeDnsSuffixes = InstanceUtils.processK8SDnsSuffixList(GCP_PROP_GKE_DNS_SUFFIX);
        // get our dynamic list of gke cluster names
        gkeClusterNames = new DynamicConfigCsv(CONFIG_MANAGER, GCP_PROP_GKE_CLUSTER_NAMES, null);
    }

    @Override
    public String validateIssuer(InstanceConfirmation confirmation, IdTokenAttestationData attestationData, StringBuilder errMsg) {
        String issuer = getIssuerFromToken(attestationData, errMsg);
        if (StringUtil.isEmpty(issuer)) {
            return null;
        }
        String gcpProject = confirmation.getAttributes().get(InstanceProvider.ZTS_INSTANCE_GCP_PROJECT);
        if (!issuer.startsWith(GCP_OIDC_ISSUER_PREFIX + gcpProject)) {
            errMsg.append("Issuer is not present in the GCP project associated with the domain");
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
