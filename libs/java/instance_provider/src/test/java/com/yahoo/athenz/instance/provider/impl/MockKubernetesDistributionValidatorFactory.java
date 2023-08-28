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

import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.KubernetesDistributionValidator;
import com.yahoo.athenz.instance.provider.KubernetesDistributionValidatorFactory;

import java.util.HashMap;
import java.util.Map;

public class MockKubernetesDistributionValidatorFactory implements KubernetesDistributionValidatorFactory {
    @Override
    public void initialize() {
    }

    @Override
    public Map<String, KubernetesDistributionValidator> getSupportedDistributions() {
        Map<String, KubernetesDistributionValidator> map = new HashMap<>();
        KubernetesDistributionValidator mockValidator = new KubernetesDistributionValidator() {
            @Override
            public void initialize() {

            }
            @Override
            public String validateIssuer(InstanceConfirmation confirmation, IdTokenAttestationData attestationData, StringBuilder errMsg) {
                return "mock-issuer";
            }
            @Override
            public boolean validateAttestationData(InstanceConfirmation confirmation, IdTokenAttestationData attestationData, String issuer, StringBuilder errMsg) {
                return true;
            }
            @Override
            public boolean validateSanDNSEntries(InstanceConfirmation confirmation, StringBuilder errMsg) {
                return true;
            }
        };

        map.put("gcp", mockValidator);
        map.put("aws", mockValidator);

        return map;
    }
}
