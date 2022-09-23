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
package com.yahoo.athenz.auth.impl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
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
    public static final String JAVAX_CERT_ATTR = "jakarta.servlet.request.X509Certificate";

    public static final String EMPTY_CERT_ERR_MSG = "No certificate available in request";
    public static final String ISSUER_DN_MISMATCH = "No Issuer DNs match with trust store";

    private final Set<String> excludedPrincipalSet;
    private final boolean excludeRoleCertificates;

    private CertificateAuthorityValidator certificateAuthorityValidator;

    /**
     * Parse the given certificate and verify it passes the configured restrictions
     * @param excludedPrincipalSet Reject parsing certificate with these principals
     * @param excludeRoleCertificates Reject accepting role certificates
     */
    public CertificateIdentityParser(Set<String> excludedPrincipalSet, boolean excludeRoleCertificates) {
        this.excludedPrincipalSet = excludedPrincipalSet;
        this.excludeRoleCertificates = excludeRoleCertificates;
    }

    /**
     * Parse the given certificate and verify it passes the configured restrictions
     * @param excludedPrincipalSet Reject parsing certificate with these principals
     * @param excludeRoleCertificates Reject accepting role certificates
     * @param certificateAuthorityValidator validate the CA issuer in certificates
     */
    public CertificateIdentityParser(Set<String> excludedPrincipalSet, boolean excludeRoleCertificates,
                                     CertificateAuthorityValidator certificateAuthorityValidator) {
        this.excludedPrincipalSet = excludedPrincipalSet;
        this.excludeRoleCertificates = excludeRoleCertificates;
        this.certificateAuthorityValidator = certificateAuthorityValidator;
    }

    /**
     * Parse from X509Certificate inside the request.
     * @param request HTTPS request
     * @return CertificateIdentity
     * @throws CertificateIdentityException parse error
     */
    public CertificateIdentity parse(HttpServletRequest request) throws CertificateIdentityException {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(JAVAX_CERT_ATTR);
        return this.parse(certs);
    }

    /**
     * Parse from X509Certificate chain.
     * @param certs X509Certificate chain
     * @return CertificateIdentity
     * @throws CertificateIdentityException parse error
     */
    public CertificateIdentity parse(X509Certificate[] certs) throws CertificateIdentityException {

        // make sure we have at least one valid certificate in our list

        if (certs == null || certs[0] == null) {
            throw new CertificateIdentityException(EMPTY_CERT_ERR_MSG);
        }

        X509Certificate x509Cert = certs[0];

        if (this.certificateAuthorityValidator != null && !this.certificateAuthorityValidator.validate(x509Cert)) {
            throw new CertificateIdentityException(ISSUER_DN_MISMATCH, false);
        }

        String principalName = Crypto.extractX509CertCommonName(x509Cert);
        if (principalName == null || principalName.isEmpty()) {
            throw new CertificateIdentityException("Certificate principal is empty");
        }

        // make sure the principal is not on our excluded list

        if (this.excludedPrincipalSet != null && this.excludedPrincipalSet.contains(principalName)) {
            throw new CertificateIdentityException("Principal is excluded");
        }

        // For role cert, the principal information is in the SAN uri and/or email

        List<String> roles = null;
        String rolePrincipalName = null;
        if (principalName.contains(AuthorityConsts.ROLE_SEP)) {

            // check to make sure role certs are allowed for principal

            if (this.excludeRoleCertificates) {
                throw new CertificateIdentityException("Role Certificates not allowed");
            }

            // fist we need to keep the role name in our object

            roles = new ArrayList<>();
            roles.add(principalName);

            // now let's extract our role principal

            rolePrincipalName = AthenzUtils.extractRolePrincipal(x509Cert);
            if (rolePrincipalName == null) {
                throw new CertificateIdentityException("Invalid role cert, no role principal");
            }
            principalName = rolePrincipalName;
        }

        // extract domain and service names from the name. We must have
        // a valid service identity in the form domain.service

        int idx = principalName.lastIndexOf(AuthorityConsts.ATHENZ_PRINCIPAL_DELIMITER_CHAR);
        if (idx == -1 || idx == 0 || idx == principalName.length() - 1) {
            throw new CertificateIdentityException("Principal is not a valid service identity");
        }

        return new CertificateIdentity(principalName.substring(0, idx).toLowerCase(),
                principalName.substring(idx + 1).toLowerCase(), roles, rolePrincipalName, x509Cert);
    }
}
