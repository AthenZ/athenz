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
package com.yahoo.athenz.auth;

import io.jsonwebtoken.SignatureAlgorithm;

import java.security.PrivateKey;

public class ServerPrivateKey {

    public static final String RSA   = "RSA";
    public static final String ECDSA = "ECDSA";

    private final String id;
    private final PrivateKey key;
    private final SignatureAlgorithm algorithm;

    public ServerPrivateKey(final PrivateKey key, final String id) {

        this.key = key;
        this.id = id;

        algorithm = ECDSA.equalsIgnoreCase(key.getAlgorithm()) ?
                SignatureAlgorithm.ES256 : SignatureAlgorithm.RS256;
    }

    public PrivateKey getKey() {
        return key;
    }

    public String getId() {
        return id;
    }

    public SignatureAlgorithm getAlgorithm() {
        return algorithm;
    }
}
