/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.cert;

import java.util.List;

public interface CertificateDataValidator {

    /**
     * Validate the service identity certificate san DNS name
     * @param domainName the domain name
     * @param serviceName the service name
     * @param dnsName the dns name to validate
     * @param serviceDnsSuffix the service dns suffix allowed for the service (can be null)
     * @param providerDnsSuffixList the provider dns suffix list allowed for the provider (can be null)
     * @return true if the certificate data is valid, false otherwise
     */
    boolean validateServiceIdentityCertSanDnsName(String domainName, String serviceName, String dnsName,
        String serviceDnsSuffix, List<String> providerDnsSuffixes);

    /**
     * Validate the role certificate san DNS name
     * @param roleDomainName the role's domain name
     * @param roleName the role's name
     * @param principalName the principal's name requesting this role certificate
     * @param dnsName the dns name to validate
     * @param roleDnsSuffixList the ZTS server's dns suffix list allowed for role certificates
     * @return true if the certificate data is valid, false otherwise
     */
    boolean validateRoleCertSanDnsName(String roleDomainName, String roleName, String principalName,
        String dnsName, List<String> roleDnsSuffixList);
}
