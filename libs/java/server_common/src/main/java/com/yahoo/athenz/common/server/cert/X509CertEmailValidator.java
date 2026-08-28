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

public interface X509CertEmailValidator {

    /**
     * Validate email addresses found in the service certificate request.
     * Service certificates should not contain email addresses.
     * @param domainName the domain name
     * @param serviceName the service name
     * @param emails the list of email addresses from the CSR
     * @return true if the emails are valid or acceptable, false if they should be rejected
     */
    boolean validateServiceCertificateEmails(String domainName, String serviceName, List<String> emails);
}
