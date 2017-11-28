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

import com.google.common.io.Resources;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {

    private static final Logger LOG = LoggerFactory.getLogger(Utils.class);

    private static final String SSLCONTEXT_ALGORITHM = "TLSv1.2";
    private static final String KEYSTORE_PASSWORD = "secret";
    
    public static KeyStore getKeyStore(final String jksFilePath) throws Exception {
        return getKeyStore(jksFilePath, KEYSTORE_PASSWORD);
    }

    public static KeyStore getKeyStore(final String jksFilePath, final String password) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        ///CLOVER:OFF
        if (Paths.get(jksFilePath).isAbsolute()) {
            // Can not cover this branch in unit test. Can not refer any files by absolute paths
            try (InputStream jksFileInputStream = new FileInputStream(jksFilePath)) {
                keyStore.load(jksFileInputStream, password.toCharArray());
                return keyStore;
            }
        }
        ///CLOVER:ON

        try (InputStream jksFileInputStream = Resources.getResource(jksFilePath).openStream()) {
            keyStore.load(jksFileInputStream, password.toCharArray());
            return keyStore;
        }
    }

    public static KeyManager[] getKeyManagers(final String athensPublicKey, final String athensPrivateKey) throws Exception {
        final KeyStore keystore = createKeyStore(athensPublicKey, athensPrivateKey);
        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keystore, KEYSTORE_PASSWORD.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    /**
     * Generate the KeyRefresher object first as the server will need access to
     * it (to turn it off and on as needed). It requires that the proxies are
     * created which are then stored in the KeyRefresher. This method requires
     * the paths to the private key and certificate files along with the
     * trust-store path which has been created already and just needs to be
     * monitored for changes. Using default password of "secret" for both stores.
     * @param trustStorePath path to the trust-store
     * @param certPath path to the certificate file
     * @param keyPath path to the private key file
     * @return KeyRefresher object
     */
    public static KeyRefresher generateKeyRefresher(final String trustStorePath,
            final String athensPublicKey, final String athensPrivateKey) throws Exception {
        return generateKeyRefresher(trustStorePath, KEYSTORE_PASSWORD, athensPublicKey,
                athensPrivateKey);
    }

    /**
     * Generate the KeyRefresher object first as the server will need access to
     * it (to turn it off and on as needed). It requires that the proxies are
     * created which are then stored in the KeyRefresher. This method requires
     * the paths to the private key and certificate files along with the
     * trust-store path which has been created already and just needs to be
     * monitored for changes.
     * @param trustStorePath path to the trust-store
     * @param trustStorePassword trust store password
     * @param certPath path to the certificate file
     * @param keyPath path to the private key file
     * @return KeyRefresher object
     */
    public static KeyRefresher generateKeyRefresher(final String trustStorePath,
            final String trustStorePassword, final String athensPublicKey,
            final String athensPrivateKey) throws Exception {
        TrustStore trustStore = new TrustStore(trustStorePath,
                new JavaKeyStoreProvider(trustStorePath, trustStorePassword));
        return getKeyRefresher(athensPublicKey, athensPrivateKey, trustStore);
    }
    
    /**
     * Generate the KeyRefresher object first as the server will need access to
     * it (to turn it off and on as needed). It requires that the proxies are
     * created which are then stored in the KeyRefresher. This method requires
     * the paths to the private key and certificate files along with the
     * trust-store path which has been created already and just needs to be
     * monitored for changes. Using default password of "secret" for both stores.
     * @param trustStorePath path to the trust-store
     * @param certPath path to the certificate file
     * @param keyPath path to the private key file
     * @return KeyRefresher object
     */
    public static KeyRefresher generateKeyRefresherFromCaCert(final String caCertPath,
            final String athensPublicKey, final String athensPrivateKey) throws Exception {
        TrustStore trustStore = new TrustStore(caCertPath, new CaCertKeyStoreProvider(caCertPath));
        return getKeyRefresher(athensPublicKey, athensPrivateKey, trustStore);
    }
    
    static KeyRefresher getKeyRefresher(String athensPublicKey, String athensPrivateKey,
            TrustStore trustStore) throws Exception {
        KeyManagerProxy keyManagerProxy =
                new KeyManagerProxy(getKeyManagers(athensPublicKey, athensPrivateKey));
        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(trustStore.getTrustManagers());
        return new KeyRefresher(athensPublicKey, athensPrivateKey, trustStore, keyManagerProxy, trustManagerProxy);
        }

    /**
     * this method will create a new SSLContext object that can be updated on the fly should the
     * public/private keys / trustStore change.
     * @param keyManagerProxy uses standard KeyManager interface except also allows
     *        for the updating of KeyManager on the fly
     * @param trustManagerProxy uses standard TrustManager interface except also allows
     *        for the updating of TrustManager on the fly
     * @return a valid SSLContext object using the passed in key/trust managers
     * @throws Exception sslContext.init can throw exceptions
     */
    public static SSLContext buildSSLContext(KeyManagerProxy keyManagerProxy,
            TrustManagerProxy trustManagerProxy) throws Exception {
        final SSLContext sslContext = SSLContext.getInstance(SSLCONTEXT_ALGORITHM);
        sslContext.init(new KeyManager[]{ keyManagerProxy }, new TrustManager[] { trustManagerProxy }, null);
        return sslContext;
    }
    
    /**
     * @param athensPublicKey the location on the public key file
     * @param athensPrivateKey the location of the private key file
     * @return a KeyStore with loaded key and certificate
     * @throws Exception KeyStore generation can throw Exception for many reasons
     */
    public static KeyStore createKeyStore(final String athensPublicKey, final String athensPrivateKey) throws Exception {

        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();

        X509Certificate certificate;
        PrivateKey privateKey = null;

        final InputStream publicCertStream;
        final InputStream privateKeyStream;

        try {
            if (Paths.get(athensPublicKey).isAbsolute() && Paths.get(athensPrivateKey).isAbsolute()) {
                // Can not cover this branch in unit test. Can not refer any files by absolute paths
                File certFile = new File(athensPublicKey);
                File keyFile = new File(athensPrivateKey);

                while (!certFile.exists() || !keyFile.exists()) {
                    LOG.error("Missing Athenz public or private key files");
                    Thread.sleep(1000);
                }
                publicCertStream = new FileInputStream(athensPublicKey);
                privateKeyStream = new FileInputStream(athensPrivateKey);
            } else {
                publicCertStream = Resources.getResource(athensPublicKey).openStream();
                privateKeyStream = Resources.getResource(athensPrivateKey).openStream();
            }
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }

        try (PEMParser pemParser = new PEMParser(new InputStreamReader(privateKeyStream))) {

            Object key = pemParser.readObject();
            if (key instanceof PEMKeyPair) {
                PrivateKeyInfo pKeyInfo = ((PEMKeyPair) key).getPrivateKeyInfo();
                privateKey = pemConverter.getPrivateKey(pKeyInfo);
            } else if (key instanceof PrivateKeyInfo) {
                privateKey = pemConverter.getPrivateKey((PrivateKeyInfo) key);
            } else {
                throw new IllegalStateException("Unknown object type: " + key.getClass().getName());
            }
        } catch (IOException e) {
            throw new IllegalStateException("Unable to parse private key", e);
        }

        certificate = (X509Certificate) cf.generateCertificate(publicCertStream);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String alias = certificate.getSubjectX500Principal().getName();
        keyStore.load(null);
        keyStore.setKeyEntry(alias, privateKey, KEYSTORE_PASSWORD.toCharArray(), new X509Certificate[]{certificate});
        return keyStore;
    }
}
