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
package com.yahoo.athenz.crypki.signer;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;

public final class SigningKey {

    private final String identifier;
    private final PrivateKey privateKey;
    private final X509Certificate caCertificate;

    public SigningKey(String identifier, PrivateKey privateKey, X509Certificate caCertificate) {
        this.identifier = Objects.requireNonNull(identifier, "identifier");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        this.caCertificate = Objects.requireNonNull(caCertificate, "caCertificate");
    }

    public String getIdentifier() {
        return identifier;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getCaCertificate() {
        return caCertificate;
    }
}
