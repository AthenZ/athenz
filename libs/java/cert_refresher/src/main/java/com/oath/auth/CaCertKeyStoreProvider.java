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
package com.oath.auth;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.function.Supplier;

/**
 * creates a key store and adds a certificate authority certificate
 */
class CaCertKeyStoreProvider implements KeyStoreProvider {

    private final String caCertFilePath;
    private final Supplier<InputStream> caCertsInputStream;

    public CaCertKeyStoreProvider(final String caCertFilePath) {
        this.caCertFilePath = caCertFilePath;
        this.caCertsInputStream = null;
    }

    public CaCertKeyStoreProvider(final Supplier<InputStream> caCertsInputStream) {
        this.caCertsInputStream = caCertsInputStream;
        this.caCertFilePath = null;
    }

    @Override
    public KeyStore provide() throws KeyRefresherException, IOException {
        KeyStore keyStore;
        if (caCertFilePath != null) {
            try (InputStream inputStream = new FileInputStream(caCertFilePath)) {
                keyStore = Utils.generateTrustStore(inputStream);
            }
        } else {
            keyStore = Utils.generateTrustStore(caCertsInputStream.get());
        }
        return keyStore;
    }
}
