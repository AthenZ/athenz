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
package com.yahoo.athenz.zts.cert.impl;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.function.BiFunction;

import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.CertSignerFactory;
import com.yahoo.athenz.zts.ZTSConsts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyStoreCertSignerFactory implements CertSignerFactory {

    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreCertSignerFactory.class);

    private static final String ZTS_PROP_CERT_SIGNER_KEYSTORE_PASSWORD = "athenz.zts.keystore_signer.keystore_password";
    private static final String ZTS_PROP_CERT_SIGNER_KEYSTORE_PATH = "athenz.zts.keystore_signer.keystore_path";
    private static final String ZTS_PROP_CERT_SIGNER_KEYSTORE_TYPE = "athenz.zts.keystore_signer.keystore_type";
    private static final String ZTS_PROP_CERT_SIGNER_CA_ALIAS = "athenz.zts.keystore_signer.keystore_ca_alias";

    private static final BiFunction<String, String, RuntimeException> CREATE_ILLEGAL_ARGUMENT_EXCEPTION = (variableName, propertyName) -> {
        String message = String.format("Failed to get %s from %s property.", variableName, propertyName);
        LOG.error(message);
        return new IllegalArgumentException(message);
    };

    @Override
    public CertSigner create() {
        final String keyStorePassword = System.getProperty(ZTS_PROP_CERT_SIGNER_KEYSTORE_PASSWORD);
        final String keyStorePath = System.getProperty(ZTS_PROP_CERT_SIGNER_KEYSTORE_PATH);
        final String keyStoreType = System.getProperty(ZTS_PROP_CERT_SIGNER_KEYSTORE_TYPE, "PKCS12");
        final String caAlias = System.getProperty(ZTS_PROP_CERT_SIGNER_CA_ALIAS, "1");
        final int maxCertExpiryTimeMins = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME, "43200"));

        // check null or empty
        if (keyStorePassword == null || keyStorePassword.isEmpty()) {
            throw CREATE_ILLEGAL_ARGUMENT_EXCEPTION.apply("keyStorePassword", ZTS_PROP_CERT_SIGNER_KEYSTORE_PASSWORD);
        }
        if (keyStorePath == null || keyStorePath.isEmpty()) {
            throw CREATE_ILLEGAL_ARGUMENT_EXCEPTION.apply("keyStorePath", ZTS_PROP_CERT_SIGNER_KEYSTORE_PATH);
        }

        try (FileInputStream fis = new FileInputStream(keyStorePath)) {
            // read ca certificate and key
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            ks.load(fis, keyStorePassword.toCharArray());
            PrivateKey caPrivateKey = (PrivateKey) ks.getKey(caAlias, keyStorePassword.toCharArray());
            X509Certificate caCertificate = (X509Certificate) ks.getCertificate(caAlias);

            if (caPrivateKey == null || caCertificate == null) {
                throw CREATE_ILLEGAL_ARGUMENT_EXCEPTION.apply("caPrivateKey/caCertificate", ZTS_PROP_CERT_SIGNER_CA_ALIAS);
            }

            return new KeyStoreCertSigner(caCertificate, caPrivateKey, maxCertExpiryTimeMins);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
