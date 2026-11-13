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
package com.yahoo.athenz.auth.token;

import com.nimbusds.jose.JWSAlgorithm;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Immutable validation policy for {@link DPoPProof}. Instances are created
 * with {@link #builder()} and can be shared across threads.
 */
public final class DPoPProofOptions {

    public static final long DEFAULT_MAX_AGE_SECS = 30;
    public static final long DEFAULT_CLOCK_SKEW_SECS = 10;
    public static final int DEFAULT_MAX_PROOF_SIZE = 8192;
    public static final int DEFAULT_MIN_RSA_KEY_SIZE = 2048;

    /**
     * Asymmetric JWS algorithms accepted by default. EdDSA is not included
     * since Nimbus requires Google Tink for Ed25519 support.
     */
    public static final List<JWSAlgorithm> DEFAULT_ALGORITHMS = List.of(
            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);

    private final Set<JWSAlgorithm> allowedAlgorithms;
    private final Set<String> allowedHtus;
    private final long maxAgeSecs;
    private final long clockSkewSecs;
    private final int maxProofSize;
    private final int minRsaKeySize;

    private DPoPProofOptions(Builder builder) {
        this.allowedAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(builder.allowedAlgorithms));
        this.allowedHtus = Collections.unmodifiableSet(new HashSet<>(builder.allowedHtus));
        this.maxAgeSecs = builder.maxAgeSecs;
        this.clockSkewSecs = builder.clockSkewSecs;
        this.maxProofSize = builder.maxProofSize;
        this.minRsaKeySize = builder.minRsaKeySize;
    }

    public static Builder builder() {
        return new Builder();
    }

    public Set<JWSAlgorithm> getAllowedAlgorithms() {
        return allowedAlgorithms;
    }

    /**
     * @return the set of allowed htu values, already normalized with
     * {@link DPoPProof#normalizeHtu(String)}
     */
    public Set<String> getAllowedHtus() {
        return allowedHtus;
    }

    public long getMaxAgeSecs() {
        return maxAgeSecs;
    }

    public long getClockSkewSecs() {
        return clockSkewSecs;
    }

    public int getMaxProofSize() {
        return maxProofSize;
    }

    public int getMinRsaKeySize() {
        return minRsaKeySize;
    }

    public static final class Builder {

        private Set<JWSAlgorithm> allowedAlgorithms = new LinkedHashSet<>(DEFAULT_ALGORITHMS);
        private final Set<String> allowedHtus = new HashSet<>();
        private long maxAgeSecs = DEFAULT_MAX_AGE_SECS;
        private long clockSkewSecs = DEFAULT_CLOCK_SKEW_SECS;
        private int maxProofSize = DEFAULT_MAX_PROOF_SIZE;
        private int minRsaKeySize = DEFAULT_MIN_RSA_KEY_SIZE;

        private Builder() {
        }

        /**
         * Replace the default algorithm allow-list. Only RSA (RS*, PS*) and
         * EC (ES*) signature algorithms are accepted.
         *
         * @param algorithms non-empty set of allowed algorithms
         * @return this builder
         */
        public Builder allowedAlgorithms(Collection<JWSAlgorithm> algorithms) {
            if (algorithms == null || algorithms.isEmpty()) {
                throw new IllegalArgumentException("DPoP algorithm list must not be empty");
            }
            for (JWSAlgorithm alg : algorithms) {
                if (!JWSAlgorithm.Family.RSA.contains(alg) && !JWSAlgorithm.Family.EC.contains(alg)) {
                    throw new IllegalArgumentException("Unsupported DPoP signing algorithm: " + alg);
                }
            }
            this.allowedAlgorithms = new LinkedHashSet<>(algorithms);
            return this;
        }

        /**
         * Add an allowed htu value. The value is normalized before it's stored.
         *
         * @param htu absolute http(s) uri of the protected endpoint
         * @return this builder
         */
        public Builder addAllowedHtu(final String htu) {
            final String normalized = DPoPProof.normalizeHtu(htu);
            if (normalized == null) {
                throw new IllegalArgumentException("Invalid DPoP htu value: " + htu);
            }
            allowedHtus.add(normalized);
            return this;
        }

        public Builder maxAgeSecs(long maxAgeSecs) {
            if (maxAgeSecs < 0) {
                throw new IllegalArgumentException("DPoP max age must not be negative");
            }
            this.maxAgeSecs = maxAgeSecs;
            return this;
        }

        public Builder clockSkewSecs(long clockSkewSecs) {
            if (clockSkewSecs < 0) {
                throw new IllegalArgumentException("DPoP clock skew must not be negative");
            }
            this.clockSkewSecs = clockSkewSecs;
            return this;
        }

        public Builder maxProofSize(int maxProofSize) {
            if (maxProofSize <= 0) {
                throw new IllegalArgumentException("DPoP max proof size must be positive");
            }
            this.maxProofSize = maxProofSize;
            return this;
        }

        public Builder minRsaKeySize(int minRsaKeySize) {
            if (minRsaKeySize <= 0) {
                throw new IllegalArgumentException("DPoP min RSA key size must be positive");
            }
            this.minRsaKeySize = minRsaKeySize;
            return this;
        }

        public DPoPProofOptions build() {
            if (allowedHtus.isEmpty()) {
                throw new IllegalArgumentException("DPoP allowed htu set must not be empty");
            }
            return new DPoPProofOptions(this);
        }
    }
}
