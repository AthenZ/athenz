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

import com.yahoo.athenz.auth.util.Crypto;

import java.security.cert.X509Certificate;
import java.util.Set;

public class CertificateAuthorityValidator {

    private static final String TRUST_STORE_PATH = "athenz.authority.truststore.path";

    private Set<String> issuerDNs;

    public CertificateAuthorityValidator() {
        String trustStorePath = System.getProperty(TRUST_STORE_PATH);
        extractIssuerDNs(trustStorePath);
    }

    public CertificateAuthorityValidator(final String trustStorePath) {
        extractIssuerDNs(trustStorePath);
    }

    private void extractIssuerDNs(final String trustStorePath) {
        if (trustStorePath != null && !trustStorePath.isEmpty()) {
            issuerDNs = Crypto.extractIssuerDn(trustStorePath);
        }
    }

    /**
     *
     * @param x509Cert validate the x509 certificate
     * @return true if the certificate's Issuer DN is present in the allowed Issuer DNs
     */
    public boolean validate(X509Certificate x509Cert) {
        return issuerDNs == null || issuerDNs.isEmpty() || issuerDNs.contains(Crypto.extractIssuerDn(x509Cert));
    }

    /**
     *
     * @return set to allowed Issuer DNs
     */
    public Set<String> getIssuerDNs() {
        return this.issuerDNs;
    }

}
