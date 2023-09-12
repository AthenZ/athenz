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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * A trust store built from a jks file by default. Or from the keystore provided by the
 */
public class TrustStore {

    private final String filePath;
    private final KeyStoreProvider keyStoreProvider;

    public TrustStore(final String filePath, final KeyStoreProvider keyStoreProvider) {
        this.filePath = filePath;
        this.keyStoreProvider = keyStoreProvider;
    }

    public TrustManager[] getTrustManagers() throws KeyRefresherException, IOException  {
        final KeyStore keystore = keyStoreProvider.provide();

        TrustManagerFactory trustManagerFactory;
        try {
            trustManagerFactory = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keystore);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyRefresherException("No Provider supports a TrustManagerFactorySpi implementation for the specified algorithm.", e);
        } catch (KeyStoreException e) {
            throw new KeyRefresherException("Unable to generate TrustManagerFactory.", e);
        }
        return trustManagerFactory.getTrustManagers();
    }

    public String getFilePath() {
        return filePath;
    }

}
