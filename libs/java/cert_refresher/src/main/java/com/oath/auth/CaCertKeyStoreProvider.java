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

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * creates a key store and adds a certificate authority certificate
 */
class CaCertKeyStoreProvider implements KeyStoreProvider {

    private final String caCertFilePath;

    public CaCertKeyStoreProvider(final String caCertFilePath) {
        this.caCertFilePath = caCertFilePath;
    }

    @Override
    public KeyStore provide() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream inputStream = new FileInputStream(caCertFilePath)) {
            X509Certificate certificate = (X509Certificate) factory
                .generateCertificate(inputStream);
            String alias = certificate.getSubjectX500Principal().getName();
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null);
            keyStore.setCertificateEntry(alias, certificate);
            return keyStore;
        }
    }
}
