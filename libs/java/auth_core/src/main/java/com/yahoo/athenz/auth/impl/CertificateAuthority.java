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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.GlobStringsMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;

import static com.yahoo.athenz.auth.AuthorityConsts.ATHENZ_PROP_RESTRICTED_OU;

public class CertificateAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateAuthority.class);

    private static final String ATHENZ_PROP_EXCLUDED_PRINCIPALS = "athenz.auth.certificate.excluded_principals";
    private static final String ATHENZ_PROP_EXCLUDE_ROLE_CERTIFICATES = "athenz.auth.certificate.exclude_role_certificates";

    private static final String ATHENZ_AUTH_CHALLENGE = "AthenzX509Certificate realm=\"athenz\"";

    private CertificateIdentityParser certificateIdentityParser = null;
    private final GlobStringsMatcher globStringsMatcher = new GlobStringsMatcher(ATHENZ_PROP_RESTRICTED_OU);

    @Override
    public void initialize() {
        Set<String> excludedPrincipalSet = null;

        final String exPrincipals = System.getProperty(ATHENZ_PROP_EXCLUDED_PRINCIPALS);
        if (exPrincipals != null && !exPrincipals.isEmpty()) {
            excludedPrincipalSet = new HashSet<>(Arrays.asList(exPrincipals.split(",")));
        }

        boolean excludeRoleCertificates = Boolean.parseBoolean(System.getProperty(ATHENZ_PROP_EXCLUDE_ROLE_CERTIFICATES, "false"));

        this.certificateIdentityParser = new CertificateIdentityParser(excludedPrincipalSet, excludeRoleCertificates,
                new CertificateAuthorityValidator());
    }

    @Override
    public String getID() {
        return "Auth-X509";
    }

    @Override
    public String getDomain() {
        return null;
    }

    @Override
    public String getHeader() {
        return null;
    }

    @Override
    public String getAuthenticateChallenge() {
        return ATHENZ_AUTH_CHALLENGE;
    }

    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        return null;
    }

    @Override
    public CredSource getCredSource() {
        return CredSource.CERTIFICATE;
    }

    void reportError(final String message, boolean reportError, StringBuilder errMsg) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(message);
        }
        if (reportError && errMsg != null) {
            errMsg.append(message);
        }
    }

    @Override
    public Principal authenticate(X509Certificate[] certs, StringBuilder errMsg) {

        if (LOG.isTraceEnabled()) {
            if (certs != null) {
                for (X509Certificate cert : certs) {
                    LOG.trace("CertificateAuthority: TLS Certificate: {}", cert);
                }
            }
        }

        // parse certificate
        CertificateIdentity certId;
        try {
            certId = this.certificateIdentityParser.parse(certs);
        } catch (CertificateIdentityException ex) {
            this.reportError("CertificateAuthority: " + ex.getMessage(), ex.isReportError(), errMsg);
            return null;
        }

        // create principal

        X509Certificate x509Cert = certId.getX509Certificate();

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(certId.getDomain(),
                certId.getService(), x509Cert.toString(), this);
        principal.setUnsignedCreds(x509Cert.getSubjectX500Principal().toString());
        principal.setX509Certificate(x509Cert);
        if (certId.getRoles() != null) {
            principal.setRoles(certId.getRoles());
            principal.setRolePrincipalName(certId.getRolePrincipalName());
        }
        principal.setMtlsRestricted(Crypto.isRestrictedCertificate(x509Cert, globStringsMatcher));

        return principal;
    }
}
