package com.yahoo.athenz.zts.cert.impl;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.function.BiFunction;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.CertSignerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyStoreCertSignerFactory implements CertSignerFactory {

    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreCertSignerFactory.class);

    private static final String ZTS_PROP_CERT_SIGNER_KEYSTORE = "athenz.zts.keystore_signer.keystore";
    private static final String ZTS_PROP_CERT_SIGNER_KEYSTORE_PASS = "athenz.zts.keystore_signer.keystore.password";
    private static final String ZTS_PROP_CERT_SIGNER_CA_KEY_ALIAS = "athenz.zts.keystore_signer.keystore.ca_alias";
    private static final String ZTS_PROP_CERT_SIGNER_MAX_CERT_EXPIRY_TIME = "athenz.zts.keystore_signer.keystore.max_cert_expire_time";

    private static final BiFunction<String, String, RuntimeException> createIllegalArgumentException = (variableName, propertyName) -> {
        String message = String.format("Failed to get %s from %s property.", variableName, propertyName);
        LOG.error(message);
        return new IllegalArgumentException(message);
    };

    @Override
    public CertSigner create() {
        System.out.println("KeyStoreCertSignerFactory.create() called");

        final String keyStorePath = System.getProperty(ZTS_PROP_CERT_SIGNER_KEYSTORE);
        final String keyStorePassword = System.getProperty(ZTS_PROP_CERT_SIGNER_KEYSTORE_PASS);
        final String caAlias = System.getProperty(ZTS_PROP_CERT_SIGNER_CA_KEY_ALIAS);
        final int maxCertExpiryTime = Integer.parseInt(System.getProperty(ZTS_PROP_CERT_SIGNER_MAX_CERT_EXPIRY_TIME, "43200"));

        // check null or empty
        if (keyStorePath == null || keyStorePath.isEmpty()) {
            throw createIllegalArgumentException.apply("keyStorePath", ZTS_PROP_CERT_SIGNER_KEYSTORE);
        }
        if (keyStorePassword == null || keyStorePassword.isEmpty()) {
            throw createIllegalArgumentException.apply("keyStorePassword", ZTS_PROP_CERT_SIGNER_KEYSTORE_PASS);
        }
        if (caAlias == null || caAlias.isEmpty()) {
            throw createIllegalArgumentException.apply("caAlias", ZTS_PROP_CERT_SIGNER_CA_KEY_ALIAS);
        }

        try (FileInputStream fis = new FileInputStream(keyStorePath)) {

            // read ca certificate and key
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, keyStorePassword.toCharArray());
            PrivateKey caPrivateKey = (PrivateKey) ks.getKey(caAlias, keyStorePassword.toCharArray());
            X509Certificate caCertificate = (X509Certificate) ks.getCertificate(caAlias);

            return new KeyStoreCertSigner(caCertificate, caPrivateKey, maxCertExpiryTime);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
