package com.oath.auth;

/**
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

import java.security.KeyStore;

/**
 * Creates a key store provider from a given jks file
 * along with the keystore password.
 */
class JavaKeyStoreProvider implements KeyStoreProvider {

    private final String jksFilePath;
    private final String password;

    public JavaKeyStoreProvider(final String jksFilePath, final String password) {
        this.jksFilePath = jksFilePath;
        this.password = password;
    }

    @Override
    public KeyStore provide() throws Exception {
        return Utils.getKeyStore(jksFilePath, password);
    }
}
