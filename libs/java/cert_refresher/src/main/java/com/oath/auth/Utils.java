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
package com.oath.auth;

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
import java.util.concurrent.TimeUnit;

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

import com.google.common.io.Resources;

public class Utils {

    private static final Logger LOG = LoggerFactory.getLogger(Utils.class);

    private static final String SSLCONTEXT_ALGORITHM = "TLSv1.2";
    private static final String PROP_KEY_WAIT_TIME = "athenz.cert_refresher.key_wait_time";
    
    private static final char[] KEYSTORE_PASSWORD = "secret".toCharArray();
    
    // how long to wait for keys - default 10 mins
    
    private static final long KEY_WAIT_TIME_MILLIS = TimeUnit.MINUTES.toMillis(
            Integer.parseInt(System.getProperty(PROP_KEY_WAIT_TIME, "10")));
    
    public static KeyStore getKeyStore(final String jksFilePath) throws Exception {
        return getKeyStore(jksFilePath, KEYSTORE_PASSWORD);
    }

    public static KeyStore getKeyStore(final String jksFilePath, final char[] password) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        ///CLOVER:OFF
        if (Paths.get(jksFilePath).isAbsolute()) {
            // Can not cover this branch in unit test. Can not refer any files by absolute paths
            try (InputStream jksFileInputStream = new FileInputStream(jksFilePath)) {
                keyStore.load(jksFileInputStream, password);
                return keyStore;
            }
        }
        ///CLOVER:ON

        try (InputStream jksFileInputStream = Resources.getResource(jksFilePath).openStream()) {
            keyStore.load(jksFileInputStream, password);
            return keyStore;
        }
    }

    public static KeyManager[] getKeyManagers(final String athenzPublicCert, final String athenzPrivateKey) throws Exception {
        final KeyStore keystore = createKeyStore(athenzPublicCert, athenzPrivateKey);
        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keystore, KEYSTORE_PASSWORD);
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
            final String athenzPublicCert, final String athenzPrivateKey) throws Exception {
        return generateKeyRefresher(trustStorePath, KEYSTORE_PASSWORD, athenzPublicCert,
                athenzPrivateKey);
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
            final String trustStorePassword, final String athenzPublicCert,
            final String athenzPrivateKey) throws Exception {
        return generateKeyRefresher(trustStorePath, trustStorePassword.toCharArray(),
                athenzPublicCert, athenzPrivateKey);
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
            final char[] trustStorePassword, final String athenzPublicCert,
            final String athenzPrivateKey) throws Exception {
        TrustStore trustStore = new TrustStore(trustStorePath,
                new JavaKeyStoreProvider(trustStorePath, trustStorePassword));
        return getKeyRefresher(athenzPublicCert, athenzPrivateKey, trustStore);
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
            final String athenzPublicCert, final String athenzPrivateKey) throws Exception {
        TrustStore trustStore = new TrustStore(caCertPath, new CaCertKeyStoreProvider(caCertPath));
        return getKeyRefresher(athenzPublicCert, athenzPrivateKey, trustStore);
    }
    
    static KeyRefresher getKeyRefresher(String athenzPublicCert, String athenzPrivateKey,
            TrustStore trustStore) throws Exception {
        KeyManagerProxy keyManagerProxy =
                new KeyManagerProxy(getKeyManagers(athenzPublicCert, athenzPrivateKey));
        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(trustStore.getTrustManagers());
        return new KeyRefresher(athenzPublicCert, athenzPrivateKey, trustStore, keyManagerProxy, trustManagerProxy);
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
     * @param athenzPublicCert the location on the public certificate file
     * @param athenzPrivateKey the location of the private key file
     * @return a KeyStore with loaded key and certificate
     * @throws Exception KeyStore generation can throw Exception for many reasons
     */
    public static KeyStore createKeyStore(final String athenzPublicCert, final String athenzPrivateKey) throws Exception {

        X509Certificate certificate;
        PrivateKey privateKey = null;
        KeyStore keyStore = null;
        File certFile = null;
        File keyFile = null;

        try {
            if (Paths.get(athenzPublicCert).isAbsolute() && Paths.get(athenzPrivateKey).isAbsolute()) {
                certFile = new File(athenzPublicCert);
                keyFile = new File(athenzPrivateKey);
                long startTime = System.currentTimeMillis();
                while (!certFile.exists() || !keyFile.exists()) {
                    long durationInMillis = System.currentTimeMillis() - startTime;
                    if (durationInMillis > KEY_WAIT_TIME_MILLIS) {
                        throw new RuntimeException("Keyfresher waited " + durationInMillis + " ms for valid public or private key files. Giving up.");
                    }
                    LOG.error("Missing Athenz public certificate or private key files. Waiting {} ms", durationInMillis);
                    Thread.sleep(1000);
                }
            } else {
                certFile = new File(Resources.getResource(athenzPublicCert).getFile());
                keyFile = new File(Resources.getResource(athenzPrivateKey).getFile());
            }
        } catch (Throwable t) {
            throw new IllegalArgumentException(t);
        }

        try (InputStream publicCertStream  = new FileInputStream(certFile);
                InputStream privateKeyStream =  new FileInputStream(keyFile);
                PEMParser pemParser = new PEMParser(new InputStreamReader(privateKeyStream))) {

            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            final JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
            Object key = pemParser.readObject();
            
            if (key instanceof PEMKeyPair) {
                PrivateKeyInfo pKeyInfo = ((PEMKeyPair) key).getPrivateKeyInfo();
                privateKey = pemConverter.getPrivateKey(pKeyInfo);
            } else if (key instanceof PrivateKeyInfo) {
                privateKey = pemConverter.getPrivateKey((PrivateKeyInfo) key);
            } else {
                throw new IllegalStateException("Unknown object type: " + key.getClass().getName());
            }
            
            certificate = (X509Certificate) cf.generateCertificate(publicCertStream);
            keyStore = KeyStore.getInstance("JKS");
            String alias = certificate.getSubjectX500Principal().getName();
            keyStore.load(null);
            keyStore.setKeyEntry(alias, privateKey, KEYSTORE_PASSWORD, new X509Certificate[]{certificate});
        
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
        
        return keyStore;
    }
}
