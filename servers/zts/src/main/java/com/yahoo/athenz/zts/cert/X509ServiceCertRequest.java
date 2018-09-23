/*
 * Copyright 2018 Oath, Inc.
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
package com.yahoo.athenz.zts.cert;

import java.util.Set;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.zts.ZTSConsts;

public class X509ServiceCertRequest extends X509CertRequest {

    public X509ServiceCertRequest(String csr) throws CryptoException {
        super(csr);
    }

    public boolean validate(Principal providerService, String domain, String service,
            String reqInstanceId, Set<String> validSubjectOValues, Authorizer authorizer,
            StringBuilder errorMsg) {

        // parse the cert request (csr) to extract the DNS entries
        // along with IP addresses. Validate that all hostnames
        // include the same dns suffix and the instance id required
        // hostname is specified

        if (!parseCertRequest(errorMsg)) {
            return false;
        }

        // if specified, we must make sure it matches to the given value

        if (reqInstanceId != null && !instanceId.equals(reqInstanceId)) {
            errorMsg.append("Instance id mismatch - URI: ").append(reqInstanceId)
                    .append(" CSR: ").append(instanceId);
            return false;
        }

        // validate the common name in CSR and make sure it
        // matches to the values specified in the info object

        final String infoCommonName = domain + "." + service;
        if (!validateCommonName(infoCommonName)) {
            errorMsg.append("Unable to validate CSR common name");
            return false;
        }

        // validate that the dnsSuffix used in the dnsName attribute has
        // been authorized to be used by the given provider

        if (dnsSuffix != null && authorizer != null) {
            final String dnsResource = ZTSConsts.ZTS_RESOURCE_DNS + dnsSuffix;
            if (!authorizer.access(ZTSConsts.ZTS_ACTION_LAUNCH, dnsResource, providerService, null)) {
                errorMsg.append("Provider '").append(providerService.getFullName())
                        .append("' not authorized to handle ").append(dnsSuffix).append(" dns entries");
                return false;
            }
        }

        // finally validate the O field in the certificate if necessary

        if (!validateSubjectOField(validSubjectOValues)) {
            errorMsg.append("Unable to validate Subject O Field");
            return false;
        }

        return true;
    }
}
