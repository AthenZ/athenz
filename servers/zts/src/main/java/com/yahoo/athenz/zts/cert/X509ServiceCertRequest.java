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

import java.util.List;
import java.util.Set;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.server.dns.HostnameResolver;

public class X509ServiceCertRequest extends X509CertRequest {

    public X509ServiceCertRequest(String csr) throws CryptoException {
        super(csr);
    }

    public boolean validate(final String domain, final String service,
            final Set<String> validSubjectOValues, final List<String> providerDnsSuffixList,
            final String serviceDnsSuffix, final String instanceHostname,
            HostnameResolver hostnameResolver, StringBuilder errorMsg) {

        // parse the cert request (csr) to extract the DNS entries
        // along with IP addresses. Validate that all hostnames
        // include the same dns suffix and the instance id required
        // hostname is specified

        if (!parseCertRequest(errorMsg)) {
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

        if (!validateDnsNames(providerDnsSuffixList, serviceDnsSuffix, instanceHostname, hostnameResolver)) {
            errorMsg.append("Unable to validate CSR SAN dnsNames - invalid dns suffix");
            return false;
        }

        // validate the O field in the certificate if necessary

        if (!validateSubjectOField(validSubjectOValues)) {
            errorMsg.append("Unable to validate Subject O Field");
            return false;
        }

        // validate spiffe uri if one is provided

        if (!validateSpiffeURI(domain, "sa", service)) {
            errorMsg.append("Unable to validate Service SPIFFE URI");
            return false;
        }

        return true;
    }
}
