/*
 * Copyright 2017 Yahoo Holdings, Inc.
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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

/**
 * creates a key store and adds a certificate authority certificate
 */
class CaCertKeyStoreProvider implements KeyStoreProvider {

    private final String caCertFilePath;

    public CaCertKeyStoreProvider(final String caCertFilePath) {
        this.caCertFilePath = caCertFilePath;
    }

    @Override
    public KeyStore provide() throws KeyRefresherException, FileNotFoundException, IOException {
        KeyStore keyStore = null;
        try (InputStream inputStream = new FileInputStream(caCertFilePath)) {
            keyStore = Utils.generateTrustStore(inputStream);
        }
        return keyStore;
    }
}
