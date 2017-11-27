package com.oath.auth;

/**
 * Copyright 2017 Yahoo Holdings, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

import java.security.KeyStore;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * A trust store built from a jks file by default. Or from the keystore provided by the
 */
class TrustStore {

    private final String filePath;
    private final KeyStoreProvider keyStoreProvider;

    public TrustStore(final String filePath, final KeyStoreProvider keyStoreProvider) {
        this.filePath = filePath;
        this.keyStoreProvider = keyStoreProvider;
    }

    public TrustManager[] getTrustManagers() throws Exception {
        final KeyStore keystore = keyStoreProvider.provide();

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keystore);
        return trustManagerFactory.getTrustManagers();
    }

    public String getFilePath() {
        return filePath;
    }

}
