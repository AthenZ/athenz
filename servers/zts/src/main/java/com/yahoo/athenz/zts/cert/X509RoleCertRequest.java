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

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.utils.X509CertUtils;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.*;

public class X509RoleCertRequest extends X509CertRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509RoleCertRequest.class);

    private static final String SPIFFE_ROLE_AGENT    = "ra";

    protected String reqRoleName;
    protected String reqRoleDomain;
    protected String rolePrincipal;

    public X509RoleCertRequest(String csr) throws CryptoException {

        // parse the csr request

        super(csr);

        // make sure the CN is a valid role name

        int idx = cn.indexOf(AuthorityConsts.ROLE_SEP);
        if (idx == -1 || idx == 0 || idx == cn.length() - AuthorityConsts.ROLE_SEP.length()) {
            throw new CryptoException("Role Certificate CN is not a valid role: " + cn);
        }

        reqRoleDomain = cn.substring(0, idx);
        reqRoleName = cn.substring(idx + AuthorityConsts.ROLE_SEP.length());
        rolePrincipal = X509CertUtils.extractItemFromURI(uris, ZTSConsts.ZTS_CERT_PRINCIPAL_URI);
    }

    public String getReqRoleName() {
        return reqRoleName;
    }

    public void setReqRoleName(final String reqRoleName) {
        this.reqRoleName = reqRoleName;
    }

    public String getReqRoleDomain() {
        return reqRoleDomain;
    }

    public void setReqRoleDomain(final String reqRoleDomain) {
        this.reqRoleDomain = reqRoleDomain;
    }

    boolean validateProxyUserUri(final String proxyUser) {

        // if we have not URI values then it's failure

        if (uris == null || uris.isEmpty()) {
            LOGGER.error("No URI fields available in the CSR");
            return false;
        }

        // we must only have a single spiffe uri in the list

        String proxyUserUri = null;
        for (String uri : uris) {

            if (!uri.toLowerCase().startsWith(ZTSConsts.ZTS_CERT_PROXY_USER_URI)) {
                continue;
            }

            if (proxyUserUri != null) {
                LOGGER.error("Multiple ProxyUser URIs in the CSR: {}/{}", uri, proxyUserUri);
                return false;
            }

            proxyUserUri = uri;
        }

        if (proxyUserUri == null) {
            LOGGER.error("No ProxyUserURI fields available in the CSR");
            return false;
        }

        final String uriCheck = ZTSConsts.ZTS_CERT_PROXY_USER_URI + proxyUser;
        if (!proxyUserUri.equals(uriCheck)) {
            LOGGER.error("ProxyUserURI mismatch: {} vs {}", proxyUserUri, uriCheck);
            return false;
        }

        return true;
    }

    boolean validateRolePrincipal(final String principal) {

        // let's get our email fields which we're going to
        // use for our principal validation (this is the old
        // format)

        List<String> emails = Crypto.extractX509CSREmails(certReq);

        // if we already have a principal extracted from the uri
        // we'll use that for verification

        if (!StringUtil.isEmpty(rolePrincipal)) {

            if (!principal.equalsIgnoreCase(rolePrincipal)) {
                LOGGER.error("role principal mismatch {} vs {}", principal, rolePrincipal);
                return false;
            }

            // we need to make sure we don't have any email
            // fields (old format) specified in the request
            // otherwise we're going to validate that as well

            if (emails.isEmpty()) {
                return true;
            }
        }

        // now let's check if we have an rfc822 field for the principal

        return validateEmail(emails, principal);
    }

    boolean validateEmail(List<String> emails, final String principal) {

        // now let's check if we have an rfc822 field specified in the
        // request. it must be of the following format: principal@[dns-suffix]
        // and we must have only a single value specified

        if (emails.size() != 1) {
            LOGGER.error("csr has incorrect number of emails: {}", emails.size());
            return false;
        }

        final String email = emails.get(0);
        final String emailPrefix = principal + "@";
        if (!email.startsWith(emailPrefix) || !ZTSUtils.valueEndsWith(email, ZTSUtils.ZTS_CERT_DNS_SUFFIX)) {
            LOGGER.error("unable to validate email {} format {}*{}", email, emailPrefix, ZTSUtils.ZTS_CERT_DNS_SUFFIX);
            return false;
        }

        return true;
    }

    public boolean validate(final String principal, final String proxyUser, Set<String> validCertSubjectOrgValues) {

        // now let's check if we have a valid role principal

        if (!validateRolePrincipal(principal)) {
            return false;
        }

        // let's check if we have a uri for the proxy user

        if (proxyUser != null && !validateProxyUserUri(proxyUser)) {
            return false;
        }

        // validate the o field value is specified

        if (!validateSubjectOField(validCertSubjectOrgValues)) {
            return false;
        }

        // validate spiffe uri if one is provided

        return validateSpiffeURI(reqRoleDomain, reqRoleName);
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
                if (!certIPs.containsAll(ipAddresses)) {
                    LOGGER.error("unable to validate certificate IP addresses: '{}' against CSR IP addresses: '{}'",
                            certIPs, ipAddresses);
                    return false;
                }
                return true;
            }
        }

        if (!validateIPAddress(ip)) {
            LOGGER.error("unable to validate connection IP address: '{}' against CSR IP addresses: '{}'",
                    ip, ipAddresses);
            return false;
        }

        return true;
    }

    public boolean validateSpiffeURI(final String domainName, final String roleName) {

        // the expected format are: spiffe://<domain>/ra/<role-name>
        //  e.g. spiffe://sports/ra/hockey-writers

        if (spiffeUri == null) {
            return true;
        }

        final String reqUri = "spiffe://" + domainName + "/" + SPIFFE_ROLE_AGENT + "/" + roleName;
        if (!reqUri.equalsIgnoreCase(spiffeUri)) {
            LOGGER.error("spiffe uri mismatch: {}/{}", spiffeUri, reqUri);
            return false;
        }

        return true;
    }
}
