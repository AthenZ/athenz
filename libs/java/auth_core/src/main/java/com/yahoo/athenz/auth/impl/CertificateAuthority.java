/*
 * Copyright 2016 Yahoo Inc.
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
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Crypto;

public class CertificateAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateAuthority.class);

    private static final String ATHENZ_PROP_EXCLUDED_PRINCIPALS = "athenz.auth.certificate.excluded_principals";
    private static final String ATHENZ_PROP_EXCLUDE_ROLE_CERTIFICATES = "athenz.auth.certificate.exclude_role_certificates";

    private static final String ATHENZ_AUTH_CHALLENGE = "AthenzX509Certificate realm=\"athenz\"";
    private static final String ZTS_CERT_ROLE_URI     = "athenz://role/";

    private Set<String> excludedPrincipalSet = null;
    private boolean excludeRoleCertificates;

    @Override
    public void initialize() {
        
        final String exPrincipals = System.getProperty(ATHENZ_PROP_EXCLUDED_PRINCIPALS);
        if (exPrincipals != null && !exPrincipals.isEmpty()) {
            excludedPrincipalSet = new HashSet<>(Arrays.asList(exPrincipals.split(",")));
        }

        excludeRoleCertificates = Boolean.parseBoolean(
                System.getProperty(ATHENZ_PROP_EXCLUDE_ROLE_CERTIFICATES, "false"));
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

    void reportError(final String message, StringBuilder errMsg) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(message);
        }
        if (errMsg != null) {
            errMsg.append(message);
        }
    }

    @Override
    public Principal authenticate(X509Certificate[] certs, StringBuilder errMsg) {

        if (LOG.isDebugEnabled()) {
            if (certs != null) {
                for (X509Certificate cert : certs) {
                    LOG.debug("CertificateAuthority: TLS Certificate: " + cert);
                }
            }
        }

        // make sure we have at least one valid certificate in our list
        
        if (certs == null || certs[0] == null) {
            reportError("CertificateAuthority: No certificate available in request", errMsg);
            return null;
        }
        
        X509Certificate x509Cert = certs[0];
        String principalName = Crypto.extractX509CertCommonName(x509Cert);
        if (principalName == null || principalName.isEmpty()) {
            reportError("CertificateAuthority: Certificate principal is empty", errMsg);
            return null;
        }

        // make sure the principal is not on our excluded list
        
        if (excludedPrincipalSet != null && excludedPrincipalSet.contains(principalName)) {
            reportError("CertificateAuthority: Principal is excluded", errMsg);
            return null;
        }
        
        // For role cert, the principal information is in the SAN email
        
        List<String> roles = null;
        int idx = principalName.indexOf(":role.");
        if (idx != -1) {

            // check to make sure role certs are allowed for principal

            if (excludeRoleCertificates) {
                reportError("CertificateAuthority: Role Certificates not allowed", errMsg);
                return null;
            }

            // fist we need to keep the role name in our object
            
            roles = new ArrayList<>();
            roles.add(principalName);
            
            // now extract the email field
            
            List<String> emails = Crypto.extractX509CertEmails(x509Cert);
            if (emails.isEmpty()) {
                reportError("CertificateAuthority: Invalid role cert, no email SAN entry", errMsg);
                return null;
            }
            String email = emails.get(0);
            idx = email.indexOf('@');
            if (idx == -1) {
                reportError("CertificateAuthority: Invalid role cert, invalid email SAN entry", errMsg);
                return null;
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
                reportError("CertificateAuthority: Invalid role cert, invalid uri SAN entry", errMsg);
                return null;
            }
            roles.add(roleUri.substring(0, idx) + ":role." + roleUri.substring(idx + 1));
        }

        if (excludeRoleCertificates && roles != null) {
            reportError("CertificateAuthority: Role Certificates not allowed", errMsg);
            return null;
        }

        // extract domain and service names from the name. We must have
        // a valid service identity in the form domain.service

        idx = principalName.lastIndexOf('.');
        if (idx == -1) {
            reportError("CertificateAuthority: Principal is not a valid service identity", errMsg);
            return null;
        }

        String domain = principalName.substring(0, idx);
        String name = principalName.substring(idx + 1);
        
        // all the role members in Athenz are normalized to lower case so we need to make
        // sure our principal's name and domain are created with lower case as well
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(domain.toLowerCase(),
                name.toLowerCase(), x509Cert.toString(), this);
        principal.setUnsignedCreds(x509Cert.getSubjectX500Principal().toString());
        principal.setX509Certificate(x509Cert);
        principal.setRoles(roles);
        return principal;
    }
}
