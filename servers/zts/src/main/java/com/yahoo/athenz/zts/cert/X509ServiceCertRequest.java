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
package com.yahoo.athenz.zts.cert;

import java.util.List;
import java.util.Set;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.zts.cache.DataCache;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X509ServiceCertRequest extends X509CertRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509ServiceCertRequest.class);

    public static final String SPIFFE_SERVICE_AGENT     = "sa";
    public static final String SPIFFE_NAMESPACE_AGENT   = "ns";
    public static final String SPIFFE_DEFAULT_NAMESPACE = "default";

    public X509ServiceCertRequest(String csr) throws CryptoException {
        super(csr);
    }

    public boolean validate(final String domainName, final String serviceName, final String provider,
            final Set<String> validSubjectOValues, final DataCache athenzSysDomainCache,
            final String serviceDnsSuffix, final String instanceHostname, final List<String> instanceHostCnames,
            HostnameResolver hostnameResolver, final String namespace, StringBuilder errorMsg) {

        // instanceId must be non-empty

        if (StringUtil.isEmpty(instanceId)) {
            errorMsg.append("InstanceId cannot be empty");
            return false;
        }

        // validate the common name in CSR and make sure it
        // matches to the values specified in the info object

        final String infoCommonName = domainName + "." + serviceName;
        if (!validateCommonName(infoCommonName)) {
            errorMsg.append("Unable to validate CSR common name");
            return false;
        }

        // ensure the uri Hostname is same as instance Hostname that gets further verified later

        if (!validateUriHostname(instanceHostname)) {
            errorMsg.append("Instance/Uri hostname mismatch: ").append(instanceHostname)
                .append(" vs. ").append(uriHostname);
            return false;
        }

        // validate that the dnsSuffix used in the dnsName attribute has
        // been authorized to be used by the given provider

        if (!validateDnsNames(domainName, serviceName, provider, athenzSysDomainCache, serviceDnsSuffix,
                instanceHostname, instanceHostCnames, hostnameResolver, errorMsg)) {
            return false;
        }

        // validate the O field in the certificate if necessary

        if (!validateSubjectOField(validSubjectOValues)) {
            errorMsg.append("Unable to validate Subject O Field");
            return false;
        }

        // validate spiffe uri if one is provided

        if (!validateSpiffeURI(domainName, serviceName, namespace)) {
            errorMsg.append("Unable to validate Service SPIFFE URI");
            return false;
        }

        return true;
    }

    public boolean validateSpiffeURI(final String domainName, final String serviceName, final String namespace) {

        // the expected format are:
        //  spiffe://<athenz-domain>/sa/<service-name>
        //   e.g. spiffe://sports/sa/api
        //  spiffe://<trust-domain>/ns/<namespace>/sa/<athenz-service>
        //   e.g. spiffe://athenz.io/ns/default/sa/sports.api

        if (spiffeUri == null) {
            return true;
        }

        final String ns = StringUtil.isEmpty(namespace) ? SPIFFE_DEFAULT_NAMESPACE : namespace;
        final String reqUri1 = "spiffe://" + domainName + "/" + SPIFFE_SERVICE_AGENT + "/" + serviceName;
        final String reqUri2 = "spiffe://" + SPIFFE_TRUST_DOMAIN + "/" + SPIFFE_NAMESPACE_AGENT + "/" +
                ns + "/" + SPIFFE_SERVICE_AGENT + "/" + domainName + "." + serviceName;
        boolean uriVerified = reqUri1.equalsIgnoreCase(spiffeUri) || reqUri2.equalsIgnoreCase(spiffeUri);

        if (!uriVerified) {
            LOGGER.error("validateSpiffeURI: spiffe uri mismatch: {}/{}/{}", spiffeUri, reqUri1, reqUri2);
        }

        return uriVerified;
    }
}
