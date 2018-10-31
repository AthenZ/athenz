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

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

public class X509RoleCertRequest extends X509CertRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509RoleCertRequest.class);

    public X509RoleCertRequest(String csr) throws CryptoException {
        super(csr);
    }

    String validateAndExtractRoleName(Set<String> roles, final String domainName) {

        // we must have only a single value in our list since we specified
        // what role we're looking for but we'll iterate through the list
        // anyway

        for (String role : roles) {
            final String roleName = domainName + ":role." + role;
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("validateRoleCertificateRequest: validating role {} against {}",
                        roleName, cn);
            }
            if (cn.equals(roleName)) {
                return role;
            }
        }
        return null;
    }

    boolean validateEmail(final String principal) {

        // now let's check if we have an rfc822 field specified in the
        // request. it must be of the following format: principal@[dns-suffix]
        // and we must have only a single value specified

        List<String> emails = Crypto.extractX509CSREmails(certReq);
        if (emails.size() != 1) {
            LOGGER.error("validateRoleCertificateRequest: csr has incorrect number of emails: {}",
                    emails.size());
            return false;
        }

        final String email = emails.get(0);
        final String emailPrefix = principal + "@";
        if (!email.startsWith(emailPrefix) || !email.endsWith(ZTSUtils.ZTS_CERT_DNS_SUFFIX)) {
            LOGGER.error("validateRoleCertificateRequest: fail to validate email {} format {}*{}",
                    email, emailPrefix, ZTSUtils.ZTS_CERT_DNS_SUFFIX);
            return false;
        }

        return true;
    }

    public boolean validate(Set<String> roles, final String domainName,
            final String principal, Set<String> validCertSubjectOrgValues) {

        if (!extractCommonName()) {
            return false;
        }

        // validate that the common name matches to the role name
        // that is being returned in the response

        final String roleName = validateAndExtractRoleName(roles, domainName);
        if (roleName == null) {
            LOGGER.error("validateRoleCertificateRequest: unable to validate role name");
            return false;
        }

        // now let's check if we have an rfc822 field for the principal

        if (!validateEmail(principal)) {
            return false;
        }

        // validate the o field value is specified

        if (!validateSubjectOField(validCertSubjectOrgValues)) {
            return false;
        }

        // validate spiffe uri if one is provided

        return validateSpiffeURI(domainName, "ra", roleName);
    }

    public boolean validateIPAddress(X509Certificate cert, final String ip) {

        // if we have no IP addresses in the request, then we're good

        if (ipAddresses.isEmpty()) {
            return true;
        }

        // if we have a certificate then we need to make sure
        // that all the ip addresses in the request match
        // the ip addresses in the certificate

        if (cert != null) {

            List<String> certIPs = Crypto.extractX509CertIPAddresses(cert);

            // if the certificate has no ip then we'll do
            // validation based on the connection ip

            if (!certIPs.isEmpty()) {
                return certIPs.containsAll(ipAddresses);
            }
        }

        return validateIPAddress(ip);
    }
}
