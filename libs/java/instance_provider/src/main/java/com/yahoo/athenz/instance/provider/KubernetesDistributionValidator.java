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

package com.yahoo.athenz.instance.provider;

import com.yahoo.athenz.instance.provider.impl.IdTokenAttestationData;

/**
 * KubernetesDistributionValidator verifies the request parameters against the
 * supported Kubernetes distributions.
 */
public interface KubernetesDistributionValidator {
    /**
     * Optionally initialize the validator with the given region
     */
    void initialize();

    /**
     * Retrieves issuer from id_token in attestation data and validates it
     * @param confirmation InstanceConfirmation
     * @param attestationData IdTokenAttestationData
     * @param errMsg StringBuilder
     * @return valid Issuer or null
     */
    String validateIssuer(InstanceConfirmation confirmation, IdTokenAttestationData attestationData, StringBuilder errMsg);

    /**
     * Validates the id_token in attestation data using the verified issuer's public key(s).
     * @param confirmation InstanceConfirmation
     * @param attestationData IdTokenAttestationData
     * @param issuer String
     * @param errMsg StringBuilder
     * @return true if attestation data is valid otherwise false
     */
    boolean validateAttestationData(InstanceConfirmation confirmation, IdTokenAttestationData attestationData, String issuer, StringBuilder errMsg);

    /**
     * Validates the san dns entries in the CSR against configured dns suffixes
     * @param confirmation InstanceConfirmation
     * @param errMsg StringBuilder
     * @return true if SAN DNS entries are valid otherwise false
     */
    boolean validateSanDNSEntries(InstanceConfirmation confirmation, StringBuilder errMsg);

}
