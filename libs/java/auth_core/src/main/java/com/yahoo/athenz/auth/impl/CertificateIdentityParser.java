/*
 * Copyright 2020 Yahoo Inc.
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
package com.yahoo.athenz.auth.impl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.Crypto;

/**
 * Parser of Athenz identity
 */
public class CertificateIdentityParser {

    /**
     * X509Certificate attribute name
     */
    public static final String JAVAX_CERT_ATTR = "javax.servlet.request.X509Certificate";

    /**
     * Role prefix inside X509Certificate
     */
    public static final String ZTS_CERT_ROLE_URI = "athenz://role/";

    public static final String EMPTY_CERT_ERR_MSG = "No certificate available in request";

    private Set<String> excludedPrincipalSet = null;
    private boolean excludeRoleCertificates;

    /**
     * @param  excludedPrincipalSet    Reject parsing certificate with those principal
     * @param  excludeRoleCertificates Reject parsing role certificates
     */
    public CertificateIdentityParser(Set<String> excludedPrincipalSet, boolean excludeRoleCertificates) {
        this.excludedPrincipalSet = excludedPrincipalSet;
        this.excludeRoleCertificates = excludeRoleCertificates;
    }

    /**
     * Parse from X509Certificate inside the request.
     * @param  request                      HTTPS request
     * @return                              CertificateIdentity
     * @throws CertificateIdentityException parse error
     */
    public CertificateIdentity parse(HttpServletRequest request) throws CertificateIdentityException {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(JAVAX_CERT_ATTR);
        return this.parse(certs);
    }

    /**
     * Parse from X509Certificate chain.
     * @param  certs                        X509Certificate chain
     * @return                              CertificateIdentity
     * @throws CertificateIdentityException parse error
     */
    public CertificateIdentity parse(X509Certificate[] certs) throws CertificateIdentityException {
        // make sure we have at least one valid certificate in our list

        if (certs == null || certs[0] == null) {
            throw new CertificateIdentityException(EMPTY_CERT_ERR_MSG);
        }

        X509Certificate x509Cert = certs[0];
        String principalName = Crypto.extractX509CertCommonName(x509Cert);
        if (principalName == null || principalName.isEmpty()) {
            throw new CertificateIdentityException("Certificate principal is empty");
        }

        // make sure the principal is not on our excluded list

        if (this.excludedPrincipalSet != null && this.excludedPrincipalSet.contains(principalName)) {
            throw new CertificateIdentityException("Principal is excluded");
        }

        // For role cert, the principal information is in the SAN email

        List<String> roles = null;
        int idx = principalName.indexOf(AuthorityConsts.ROLE_SEP);
        if (idx != -1) {

            // check to make sure role certs are allowed for principal

            if (this.excludeRoleCertificates) {
                throw new CertificateIdentityException("Role Certificates not allowed");
            }

            // fist we need to keep the role name in our object

            roles = new ArrayList<>();
            roles.add(principalName);

            // now extract the email field

            List<String> emails = Crypto.extractX509CertEmails(x509Cert);
            if (emails.isEmpty()) {
                throw new CertificateIdentityException("Invalid role cert, no email SAN entry");
            }
            String email = emails.get(0);
            idx = email.indexOf('@');
            if (idx == -1) {
                throw new CertificateIdentityException("Invalid role cert, invalid email SAN entry");
            }
            principalName = email.substring(0, idx);
        }

        // check to see if we have a role certificate where roles
        // are presented as URIs in the SAN

        List<String> uris = Crypto.extractX509CertURIs(x509Cert);
        for (String uri : uris) {
            if (!uri.toLowerCase().startsWith(ZTS_CERT_ROLE_URI)) {
                continue;
            }
            if (roles == null) {
                roles = new ArrayList<>();
            }
            final String roleUri = uri.substring(ZTS_CERT_ROLE_URI.length());
            idx = roleUri.indexOf('/');
            if (idx == -1) {
                throw new CertificateIdentityException("Invalid role cert, invalid uri SAN entry");
            }
            roles.add(roleUri.substring(0, idx) + AuthorityConsts.ROLE_SEP + roleUri.substring(idx + 1));
        }

        if (this.excludeRoleCertificates && roles != null) {
            throw new CertificateIdentityException("Role Certificates not allowed");
        }

        // extract domain and service names from the name. We must have
        // a valid service identity in the form domain.service

        String[] ds = AthenzUtils.splitPrincipalName(principalName);
        if (ds == null) {
            throw new CertificateIdentityException("Principal is not a valid service identity");
        }

        return new CertificateIdentity(
            ds[0],
            ds[1],
            roles,
            x509Cert
        );
    }

}
