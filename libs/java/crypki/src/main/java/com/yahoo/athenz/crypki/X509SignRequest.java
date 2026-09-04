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
package com.yahoo.athenz.crypki;

import com.yahoo.athenz.common.server.cert.Priority;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Generic sign request produced by {@link CrypkiRequestFactory} from ZTS
 * {@code CertSigner} arguments.
 */
public final class X509SignRequest {

    private final String keyId;
    private final String csrPem;
    private final int validitySeconds;
    private final List<Integer> extKeyUsage;
    private final Priority priority;

    private X509SignRequest(Builder builder) {
        this.keyId = builder.keyId;
        this.csrPem = Objects.requireNonNull(builder.csrPem, "csrPem");
        this.validitySeconds = builder.validitySeconds;
        this.extKeyUsage = builder.extKeyUsage == null
                ? Collections.emptyList() : List.copyOf(builder.extKeyUsage);
        this.priority = builder.priority == null ? Priority.Unspecified_priority : builder.priority;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getCsrPem() {
        return csrPem;
    }

    public int getValiditySeconds() {
        return validitySeconds;
    }

    public List<Integer> getExtKeyUsage() {
        return extKeyUsage;
    }

    public Priority getPriority() {
        return priority;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String keyId;
        private String csrPem;
        private int validitySeconds;
        private List<Integer> extKeyUsage;
        private Priority priority;

        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder csrPem(String csrPem) {
            this.csrPem = csrPem;
            return this;
        }

        public Builder validitySeconds(int validitySeconds) {
            this.validitySeconds = validitySeconds;
            return this;
        }

        public Builder extKeyUsage(List<Integer> extKeyUsage) {
            this.extKeyUsage = extKeyUsage;
            return this;
        }

        public Builder priority(Priority priority) {
            this.priority = priority;
            return this;
        }

        public X509SignRequest build() {
            return new X509SignRequest(this);
        }
    }
}
