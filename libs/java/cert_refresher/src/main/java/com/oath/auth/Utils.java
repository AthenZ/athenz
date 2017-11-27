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

    public static KeyStore getKeyStore(final String jksFilePath) throws Exception {
        return getKeyStore(jksFilePath, "secret");
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
        keyManagerFactory.init(keystore, "secret".toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    /**
     *  as the server will need access to the KeyRefresher (to turn it off and on as needed) we generate it first.
     *  It requires that the proxies are created which are then stored in the KeyRefresher
     */
    public static KeyRefresher generateKeyRefresher(final String trustStorePath, final String athensPublicKey, final String athensPrivateKey) throws Exception {
//        TrustStore trustStore = new TrustStore(trustStorePath, new JavaKeyStoreProvider(trustStorePath, "secret"));
        TrustStore trustStore = new TrustStore(trustStorePath, new JavaKeyStoreProvider(trustStorePath, "secret"));
        return getKeyRefresher(athensPublicKey, athensPrivateKey, trustStore);
    }

    public static KeyRefresher generateKeyRefresherFromCaCert(final String caCertPath, final String athensPublicKey, final String athensPrivateKey) throws Exception {
        TrustStore trustStore = new TrustStore(caCertPath, new CaCertKeyStoreProvider(caCertPath));
        return getKeyRefresher(athensPublicKey, athensPrivateKey, trustStore);
    }

    static KeyRefresher getKeyRefresher(String athensPublicKey, String athensPrivateKey, TrustStore trustStore) throws Exception {
        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(getKeyManagers(athensPublicKey, athensPrivateKey));
        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(trustStore.getTrustManagers());
        return new KeyRefresher(athensPublicKey, athensPrivateKey, trustStore, keyManagerProxy, trustManagerProxy);
    }

    /**
     * this method will create a new SSLContext object that can be updated on the fly should the
     * public/private keys / trustStore change.
     * @param keyManagerProxy uses standard KeyManager interface except also allows for the updating of KeyManager on the fly
     * @param trustManagerProxy uses standard TrustManager interface except also allows for the updating of TrustManager on the fly
     * @return a valid SSLContext object using the passed in key/trust managers
     * @throws Exception sslContext.init can throw exceptions
     */
    public static SSLContext buildSSLContext(KeyManagerProxy keyManagerProxy, TrustManagerProxy trustManagerProxy) throws Exception {
        final SSLContext sslContext = SSLContext.getInstance(SSLCONTEXT_ALGORITHM);
        sslContext.init(new KeyManager[]{ keyManagerProxy }, new TrustManager[] { trustManagerProxy }, null);
        return sslContext;
    }

    /**
     *
     * @param publicKeyLocation the location on the public key file
     * @param privateKeyLocation the location of hte private key file
     * @return a KeyStore with loaded certificate
     * @throws Exception KeyStore generation can throw Exception for many reasons
     */
    public static KeyStore createKeyStore(final String publicKeyLocation, final String privateKeyLocation) throws Exception {

        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();

        X509Certificate certificate;
        PrivateKey privateKey = null;

        final InputStream publicCertStream;
        final InputStream privateKeyStream;

        try {
            if (Paths.get(publicKeyLocation).isAbsolute() && Paths.get(privateKeyLocation).isAbsolute()) {
                // Can not cover this branch in unit test. Can not refer any files by absolute paths
                File certFile = new File(publicKeyLocation);
                File keyFile = new File(publicKeyLocation);

                while (!certFile.exists() || !keyFile.exists()) {
                    LOG.error("Missing Athenz public or private key files");
                    Thread.sleep(1000);
                }
                publicCertStream = new FileInputStream(publicKeyLocation);
                privateKeyStream = new FileInputStream(privateKeyLocation);
            } else {
                publicCertStream = Resources.getResource(publicKeyLocation).openStream();
                privateKeyStream = Resources.getResource(privateKeyLocation).openStream();
            }
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }

        try (PEMParser pemParser = new PEMParser(new InputStreamReader(privateKeyStream))) {
            Object key = pemParser.readObject();
            PrivateKeyInfo pKeyInfo = ((PEMKeyPair) key).getPrivateKeyInfo();
            privateKey = pemConverter.getPrivateKey(pKeyInfo);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to parse private key", e);
        }

        certificate = (X509Certificate) cf.generateCertificate(publicCertStream);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String alias = certificate.getSubjectX500Principal().getName();
        keyStore.load(null);
        keyStore.setKeyEntry(alias, privateKey, "secret".toCharArray(), new X509Certificate[]{certificate});
        return keyStore;
    }
}
