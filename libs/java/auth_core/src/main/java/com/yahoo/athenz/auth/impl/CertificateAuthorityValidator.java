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


/**
 * Optional issuer DN filter for certificate authorities. This class does not
 * perform certificate validation (signature, expiry, chain-of-trust, etc.).
 * Instead, it restricts which CA issuers are accepted by checking the
 * certificate's Issuer DN against a set of allowed DNs extracted from a
 * configured trust store.
 *
 * When no trust store path is provided, or the trust store contains no
 * entries, the filter is effectively a no-op and all certificates are
 * accepted. Callers (e.g. {@link CertificateIdentityParser}) may also
 * pass a {@code null} validator reference, which has the same effect of
 * accepting certificates from any issuer.
 *
 * The trust store path can be specified either through the system property
 * {@code athenz.authority.truststore.path} (default constructor) or
 * passed directly to the overloaded constructor.
 */
public class CertificateAuthorityValidator {

    private static final String TRUST_STORE_PATH = "athenz.authority.truststore.path";

    private Set<String> issuerDNs;

    /**
     * Create a validator using the trust store path from the
     * {@code athenz.authority.truststore.path} system property.
     * If the property is not set, the filter accepts all issuers.
     */
    public CertificateAuthorityValidator() {
        String trustStorePath = System.getProperty(TRUST_STORE_PATH);
        extractIssuerDNs(trustStorePath);
    }

    /**
     * Create a validator using the given trust store path.
     * If {@code trustStorePath} is {@code null} or empty, the filter
     * accepts all issuers.
     *
     * @param trustStorePath path to the trust store file containing
     *                       allowed CA certificates
     */
    public CertificateAuthorityValidator(final String trustStorePath) {
        extractIssuerDNs(trustStorePath);
    }

    private void extractIssuerDNs(final String trustStorePath) {
        if (trustStorePath != null && !trustStorePath.isEmpty()) {
            issuerDNs = Crypto.extractIssuerDn(trustStorePath);
        }
    }

    /**
     * Check whether the certificate was issued by an allowed CA.
     * Returns {@code true} if no issuer restrictions are configured
     * (i.e. issuerDNs is {@code null} or empty) or if the certificate's
     * Issuer DN is present in the allowed set.
     *
     * @param x509Cert the certificate whose issuer to check
     * @return {@code true} if the issuer is allowed or no restrictions
     *         are configured, {@code false} otherwise
     */
    public boolean validate(X509Certificate x509Cert) {
        return issuerDNs == null || issuerDNs.isEmpty() || issuerDNs.contains(Crypto.extractIssuerDn(x509Cert));
    }

    /**
     * @return the set of allowed Issuer DNs, or {@code null} if no
     *         trust store was configured
     */
    public Set<String> getIssuerDNs() {
        return this.issuerDNs;
    }

}
