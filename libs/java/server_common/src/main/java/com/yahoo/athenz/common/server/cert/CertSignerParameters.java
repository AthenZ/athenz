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
package com.yahoo.athenz.common.server.cert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Immutable set of parameters passed to the CertSigner when generating
 * an X.509 certificate. Use {@link #builder()} to create an instance.
 */
public final class CertSignerParameters {

    private final String provider;
    private final String certIssuer;
    private final String csr;
    private final String keyUsage;
    private final int expiryTime;
    private final Priority priority;
    private final String signerKeyId;
    private final Map<String, String> attributes;

    private CertSignerParameters(Builder builder) {
        this.provider = builder.provider;
        this.certIssuer = builder.certIssuer;
        this.csr = builder.csr;
        this.keyUsage = builder.keyUsage;
        this.expiryTime = builder.expiryTime;
        this.priority = builder.priority;
        this.signerKeyId = builder.signerKeyId;
        this.attributes = builder.attributes == null || builder.attributes.isEmpty()
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new HashMap<>(builder.attributes));
    }

    /**
     * @return a new builder for the certificate signer parameters
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * @return (optional) Athenz provider that validated the certificate request
     */
    public String getProvider() {
        return provider;
    }

    /**
     * @return (optional) requested issuer for the certificate
     */
    public String getCertIssuer() {
        return certIssuer;
    }

    /**
     * @return certificate signing request in PEM format
     */
    public String getCsr() {
        return csr;
    }

    /**
     * @return requested key usage (null for both server and client,
     * otherwise specified usage type: server or client)
     */
    public String getKeyUsage() {
        return keyUsage;
    }

    /**
     * @return requested certificate expiration time in minutes
     */
    public int getExpiryTime() {
        return expiryTime;
    }

    /**
     * @return requested priority for processing the request
     */
    public Priority getPriority() {
        return priority;
    }

    /**
     * @return requested signer key id if configured for the domain
     */
    public String getSignerKeyId() {
        return signerKeyId;
    }

    /**
     * Attributes validated by the instance provider and marked for the
     * cert signer. The provider prefix has already been removed from the
     * attribute names. The signer decides whether and how to encode them.
     * @return unmodifiable map of attributes, never null
     */
    public Map<String, String> getAttributes() {
        return attributes;
    }

    /**
     * Builder for {@link CertSignerParameters}.
     */
    public static final class Builder {

        private String provider;
        private String certIssuer;
        private String csr;
        private String keyUsage;
        private int expiryTime;
        private Priority priority;
        private String signerKeyId;
        private Map<String, String> attributes;

        private Builder() {
        }

        public Builder provider(final String provider) {
            this.provider = provider;
            return this;
        }

        public Builder certIssuer(final String certIssuer) {
            this.certIssuer = certIssuer;
            return this;
        }

        public Builder csr(final String csr) {
            this.csr = csr;
            return this;
        }

        public Builder keyUsage(final String keyUsage) {
            this.keyUsage = keyUsage;
            return this;
        }

        public Builder expiryTime(int expiryTime) {
            this.expiryTime = expiryTime;
            return this;
        }

        public Builder priority(final Priority priority) {
            this.priority = priority;
            return this;
        }

        public Builder signerKeyId(final String signerKeyId) {
            this.signerKeyId = signerKeyId;
            return this;
        }

        public Builder attributes(final Map<String, String> attributes) {
            this.attributes = attributes;
            return this;
        }

        public CertSignerParameters build() {
            return new CertSignerParameters(this);
        }
    }
}
