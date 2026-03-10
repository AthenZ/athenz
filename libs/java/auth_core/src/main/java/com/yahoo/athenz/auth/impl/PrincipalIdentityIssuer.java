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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class PrincipalIdentityIssuer {

    private static final Logger LOG = LoggerFactory.getLogger(PrincipalIdentityIssuer.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final Map<String, String> issuerCertDnMap;
    private final Map<String, String> issuerSignerKeyMap;
    private String defaultIssuerIdentity;

    public PrincipalIdentityIssuer(final String filename) {

        issuerCertDnMap = new HashMap<>();
        issuerSignerKeyMap = new HashMap<>();

        if (filename == null || filename.isEmpty()) {
            LOG.error("CertificateIdentityIssuer: no filename provided");
            return;
        }

        IssuerConfig config;
        try {
            config = OBJECT_MAPPER.readValue(new File(filename), IssuerConfig.class);
        } catch (Exception ex) {
            LOG.error("CertificateIdentityIssuer: unable to parse file {}: {}", filename, ex.getMessage());
            return;
        }

        defaultIssuerIdentity = config.defaultIssuerIdentity;

        if (config.issuerIdentities == null) {
            return;
        }

        for (IssuerEntry entry : config.issuerIdentities) {
            if (entry.issuerIdentity == null) {
                LOG.error("CertificateIdentityIssuer: skipping entry with null identity");
                continue;
            }
            if (entry.issuerCertDn != null) {
                final String normalizedDn = normalizeDn(entry.issuerCertDn);
                if (normalizedDn != null) {
                    issuerCertDnMap.put(normalizedDn, entry.issuerIdentity);
                }
            }
            if (entry.issuerSignerKey != null) {
                issuerSignerKeyMap.put(entry.issuerSignerKey, entry.issuerIdentity);
            }
        }
    }

    /**
     * Returns the issuer identity for the given certificate by extracting
     * and normalizing its Issuer DN and looking it up in the configured map.
     * Falls back to the default issuer identity if no match is found.
     * @param x509Certificate the certificate to look up
     * @return the issuer identity string, or default identity if the certificate is null
     */
    public String getIssuerIdentity(X509Certificate x509Certificate) {
        if (x509Certificate == null) {
            return defaultIssuerIdentity;
        }
        final String issuerDn = x509Certificate.getIssuerX500Principal().getName();
        final String identity = issuerCertDnMap.get(issuerDn);
        return identity != null ? identity : defaultIssuerIdentity;
    }

    /**
     * Returns the issuer identity for the given signer key id.
     * Falls back to the default issuer identity if no match is found.
     * @param signerKeyId the signer key id to look up
     * @return the issuer identity string, or default identity if the signer key id is null
     */
    public String getIssuerIdentity(final String signerKeyId) {
        if (signerKeyId == null) {
            return defaultIssuerIdentity;
        }
        final String identity = issuerSignerKeyMap.get(signerKeyId);
        return identity != null ? identity : defaultIssuerIdentity;
    }

    static String normalizeDn(final String dn) {
        try {
            return new X500Principal(dn).getName();
        } catch (Exception ex) {
            LOG.error("CertificateIdentityIssuer: unable to normalize dn {}: {}", dn, ex.getMessage());
            return null;
        }
    }

    static class IssuerConfig {
        @JsonProperty("default-issuer-identity")
        String defaultIssuerIdentity;

        @JsonProperty("issuer-identities")
        IssuerEntry[] issuerIdentities;
    }

    static class IssuerEntry {
        @JsonProperty("issuer-cert-dn")
        String issuerCertDn;

        @JsonProperty("issuer-identity")
        String issuerIdentity;

        @JsonProperty("issuer-signer-key")
        String issuerSignerKey;
    }
}
