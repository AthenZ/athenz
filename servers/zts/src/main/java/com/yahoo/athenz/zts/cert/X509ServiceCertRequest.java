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
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.server.cert.CertificateDataValidator;
import com.yahoo.athenz.common.server.cert.X509CertEmailValidator;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.spiffe.SpiffeUriManager;
import com.yahoo.athenz.zts.cache.DataCache;
import org.eclipse.jetty.util.StringUtil;

public class X509ServiceCertRequest extends X509CertRequest {

    private X509CertEmailValidator emailValidator;

    public X509ServiceCertRequest(String csr, SpiffeUriManager spiffeUriManager,
            CertificateDataValidator certificateDataValidator) throws CryptoException {
        super(csr, spiffeUriManager, certificateDataValidator);
    }

    public X509ServiceCertRequest(String csr, SpiffeUriManager spiffeUriManager,
            CertificateDataValidator certificateDataValidator, final String x509CertInstanceId) throws CryptoException {
        super(csr, spiffeUriManager, certificateDataValidator, x509CertInstanceId);
    }

    public void setEmailValidator(X509CertEmailValidator emailValidator) {
        this.emailValidator = emailValidator;
    }

    public boolean validate(final String domainName, final String serviceName, final String provider,
            final Set<String> validSubjectOValues, final DataCache athenzSysDomainCache,
            final String serviceDnsSuffix, final String instanceHostname, final List<String> instanceHostCnames,
            HostnameResolver hostnameResolver, final String namespace, final boolean validateCertUriSchemes,
            StringBuilder errorMsg) {

        // validate and report any invalid URI schemes in the request
        // if we're configured not to reject the request, we'll just
        // log the invalid values so the system admin can follow up with
        // respective users before enabling the feature

        if (!validateSanUriSchemes(validateCertUriSchemes)) {
            return false;
        }

        // validate email addresses in the CSR
        // service certificates should not have any email fields

        if (emailValidator != null) {
            List<String> emails = Crypto.extractX509CSREmails(certReq);
            if (!emailValidator.validateServiceCertificateEmails(domainName, serviceName, emails)) {
                errorMsg.append("Invalid email addresses in service certificate request");
                return false;
            }
        }

        // instanceId must be non-empty

        if (StringUtil.isEmpty(instanceId)) {
            errorMsg.append("InstanceId cannot be empty");
            return false;
        }

        // validate the common name in CSR and make sure it
        // matches to the values specified in the info object.
        // SPIFFE SVIDs carry an empty Subject by spec - for those the identity
        // is carried solely by the SPIFFE URI, which is validated below

        final String infoCommonName = domainName + "." + serviceName;
        if (!StringUtil.isEmpty(cn)) {
            if (!validateCommonName(infoCommonName)) {
                errorMsg.append("Unable to validate CSR common name");
                return false;
            }
        } else if (spiffeUri == null) {
            errorMsg.append("CSR contains neither a CommonName nor a SPIFFE URI");
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

        // validate the spiffe uri according to our configured validators

        if (spiffeUri == null) {
            return true;
        }

        return spiffeUriManager.validateServiceCertUri(spiffeUri, domainName, serviceName, namespace);
    }
}
