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

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

public class Utils {

    private static final Logger LOG = LoggerFactory.getLogger(Utils.class);

    private static final String SSLCONTEXT_ALGORITHM = "TLSv1.2";
    private static final String PROP_KEY_WAIT_TIME = "athenz.cert_refresher.key_wait_time";

    private static final char[] KEYSTORE_PASSWORD = "secret".toCharArray();

    private static final String DEFAULT_KEYSTORE_TYPE = "JKS";

    // how long to wait for keys - default 10 mins

    private static final long KEY_WAIT_TIME_MILLIS = TimeUnit.MINUTES.toMillis(
            Integer.parseInt(System.getProperty(PROP_KEY_WAIT_TIME, "10")));

    public static KeyStore getKeyStore(final String jksFilePath) throws FileNotFoundException, IOException, KeyRefresherException {
        return getKeyStore(jksFilePath, KEYSTORE_PASSWORD);
    }

    public static KeyStore getKeyStore(final String jksFilePath, final char[] password) throws FileNotFoundException, IOException, KeyRefresherException {
        if (jksFilePath == null || jksFilePath.isEmpty()) {
            throw new FileNotFoundException("jksFilePath is empty");
        }
        KeyStore keyStore = null;
        String keyStoreFailMsg = "Unable to load " + jksFilePath + " as a KeyStore.  Please check the validity of the file.";
        try {
            keyStore = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);

            ///CLOVER:OFF
            if (Paths.get(jksFilePath).isAbsolute()) {
                // Can not cover this branch in unit test. Can not refer any files by absolute paths
                try (InputStream jksFileInputStream = new FileInputStream(jksFilePath)) {
                    keyStore.load(jksFileInputStream, password);
                    return keyStore;
                } catch (NoSuchAlgorithmException | CertificateException e) {
                    throw new KeyRefresherException(keyStoreFailMsg, e);
                }
            }
            ///CLOVER:ON

            try (InputStream jksFileInputStream = Utils.class.getClassLoader().getResourceAsStream(jksFilePath)) {
                keyStore.load(jksFileInputStream, password);
                return keyStore;
            } catch (NoSuchAlgorithmException | CertificateException e) {
                throw new KeyRefresherException(keyStoreFailMsg, e);
            }

        } catch (KeyStoreException ignored) {
            LOG.error("No Provider supports a KeyStoreSpi implementation for the specified type.", ignored);
        }
        return keyStore;
    }

    public static KeyManager[] getKeyManagers(final String athenzPublicCert, final String athenzPrivateKey) throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        final KeyStore keystore = createKeyStore(athenzPublicCert, athenzPrivateKey);
        KeyManagerFactory keyManagerFactory = null;
        try {
            keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keystore, KEYSTORE_PASSWORD);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyRefresherException("No Provider supports a KeyManagerFactorySpi implementation for the specified algorithm.", e);
        } catch (UnrecoverableKeyException e) {
            throw new KeyRefresherException("key cannot be recovered (e.g. the given password is wrong).", e);
        } catch (KeyStoreException e) {
            throw new KeyRefresherException("Unable to initialize KeyManagerFactory.", e);
        }
        return keyManagerFactory.getKeyManagers();
    }

    /**
     * Generate the KeyRefresher object first as the server will need access to
     * it (to turn it off and on as needed). It requires that the proxies are
     * created which are then stored in the KeyRefresher. This method requires
     * the paths to the private key and certificate files along with the
     * trust-store path which has been created already and just needs to be
     * monitored for changes. Using default password of "secret" for both stores.
     *
     * @param trustStorePath   path to the trust-store
     * @param athenzPublicCert path to the certificate file
     * @param athenzPrivateKey path to the private key file
     * @return KeyRefresher object
     * @throws KeyRefresherException
     * @throws InterruptedException
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static KeyRefresher generateKeyRefresher(final String trustStorePath,
                                                    final String athenzPublicCert, final String athenzPrivateKey)
            throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        return generateKeyRefresher(trustStorePath, KEYSTORE_PASSWORD, athenzPublicCert,
                athenzPrivateKey, null);
    }

    /**
     * Generate the KeyRefresher object first as the server will need access to
     * it (to turn it off and on as needed). It requires that the proxies are
     * created which are then stored in the KeyRefresher. This method requires
     * the paths to the private key and certificate files along with the
     * trust-store path which has been created already and just needs to be
     * monitored for changes.
     *
     * @param trustStorePath     path to the trust-store
     * @param trustStorePassword trust store password
     * @param athenzPublicCert   path to the certificate file
     * @param athenzPrivateKey   path to the private key file
     * @return KeyRefresher object
     * @throws KeyRefresherException
     * @throws InterruptedException
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static KeyRefresher generateKeyRefresher(final String trustStorePath,
                                                    final String trustStorePassword, final String athenzPublicCert, final String athenzPrivateKey)
            throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        return generateKeyRefresher(trustStorePath, trustStorePassword.toCharArray(),
                athenzPublicCert, athenzPrivateKey, null);
    }

    /**
     * Generate the KeyRefresher object first as the server will need access to
     * it (to turn it off and on as needed). It requires that the proxies are
     * created which are then stored in the KeyRefresher. This method requires
     * the paths to the private key and certificate files along with the
     * trust-store path which has been created already and just needs to be
     * monitored for changes.
     *
     * @param trustStorePath     path to the trust-store
     * @param trustStorePassword trust store password
     * @param athenzPublicCert   path to the certificate file
     * @param athenzPrivateKey   path to the private key file
     * @return KeyRefresher object
     * @throws KeyRefresherException
     * @throws InterruptedException
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static KeyRefresher generateKeyRefresher(final String trustStorePath,
                                                    final char[] trustStorePassword, final String athenzPublicCert, final String athenzPrivateKey)
            throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        return generateKeyRefresher(trustStorePath, trustStorePassword,
                athenzPublicCert, athenzPrivateKey, null);
    }

    /**
     * Generate the KeyRefresher object first as the server will need access to
     * it (to turn it off and on as needed). It requires that the proxies are
     * created which are then stored in the KeyRefresher. This method requires
     * the paths to the private key and certificate files along with the
     * trust-store path which has been created already and just needs to be
     * monitored for changes.
     *
     * @param trustStorePath       path to the trust-store
     * @param trustStorePassword   trust store password
     * @param athenzPublicCert     path to the certificate file
     * @param athenzPrivateKey     path to the private key file
     * @param keyRefresherListener notify listener that key/cert has changed
     * @return KeyRefresher object
     * @throws KeyRefresherException
     * @throws InterruptedException
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static KeyRefresher generateKeyRefresher(final String trustStorePath,
                                                    final char[] trustStorePassword, final String athenzPublicCert,
                                                    final String athenzPrivateKey, final KeyRefresherListener keyRefresherListener)
            throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
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
     *
     * @param caCertPath       path to the trust-store
     * @param athenzPublicCert path to the certificate file
     * @param athenzPrivateKey path to the private key file
     * @return KeyRefresher object
     * @throws KeyRefresherException
     * @throws InterruptedException
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static KeyRefresher generateKeyRefresherFromCaCert(final String caCertPath,
                                                              final String athenzPublicCert, final String athenzPrivateKey) throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        TrustStore trustStore = new TrustStore(caCertPath, new CaCertKeyStoreProvider(caCertPath));
        return getKeyRefresher(athenzPublicCert, athenzPrivateKey, trustStore);
    }

    static KeyRefresher getKeyRefresher(String athenzPublicCert, String athenzPrivateKey,
                                        TrustStore trustStore) throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        return getKeyRefresher(athenzPublicCert, athenzPrivateKey, trustStore, null);
    }

    static KeyRefresher getKeyRefresher(String athenzPublicCert, String athenzPrivateKey,
                                        TrustStore trustStore, final KeyRefresherListener keyRefresherListener)
            throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        KeyRefresher keyRefresher = null;
        KeyManagerProxy keyManagerProxy =
                new KeyManagerProxy(getKeyManagers(athenzPublicCert, athenzPrivateKey));
        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(trustStore.getTrustManagers());
        try {
            keyRefresher = new KeyRefresher(athenzPublicCert, athenzPrivateKey, trustStore,
                    keyManagerProxy, trustManagerProxy, keyRefresherListener);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyRefresherException(e);
        }
        return keyRefresher;
    }

    /**
     * this method will create a new SSLContext object that can be updated on the fly should the
     * public/private keys / trustStore change.
     *
     * @param keyManagerProxy   uses standard KeyManager interface except also allows
     *                          for the updating of KeyManager on the fly
     * @param trustManagerProxy uses standard TrustManager interface except also allows
     *                          for the updating of TrustManager on the fly
     * @return a valid SSLContext object using the passed in key/trust managers
     * @throws KeyRefresherException
     */
    public static SSLContext buildSSLContext(KeyManagerProxy keyManagerProxy,
                                             TrustManagerProxy trustManagerProxy) throws KeyRefresherException {
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance(SSLCONTEXT_ALGORITHM);
            sslContext.init(new KeyManager[]{keyManagerProxy}, new TrustManager[]{trustManagerProxy}, null);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyRefresherException("No Provider supports a SSLContextSpi implementation for the specified protocol " + SSLCONTEXT_ALGORITHM, e);
        } catch (KeyManagementException e) {
            throw new KeyRefresherException("Unable to create SSLContext.", e);
        }
        return sslContext;
    }

    static Supplier<InputStream> inputStreamSupplierFromFile(File file) throws UncheckedIOException {
        return () -> {
            try {
                return new FileInputStream(file);
            } catch (FileNotFoundException e) {
                throw new UncheckedIOException(e);
            }
        };
    }

    static Supplier<InputStream> inputStreamSupplierFromResource(String resource) throws UncheckedIOException {
        return () -> {
            InputStream ret = Utils.class.getClassLoader().getResourceAsStream(resource);
            if (ret == null) {
                throw new UncheckedIOException(new FileNotFoundException("Certificate or private key file is empty " + resource));
            }
            return ret;
        };
    }

    static Supplier<InputStream> inputStreamSupplierFromString(String s) throws UncheckedIOException {
        return () -> new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * @param athenzPublicCert the location on the public certificate file
     * @param athenzPrivateKey the location of the private key file
     * @return a KeyStore with loaded key and certificate
     * @throws IOException
     * @throws FileNotFoundException
     * @throws InterruptedException
     * @throws KeyRefresherException
     */
    public static KeyStore createKeyStore(final String athenzPublicCert, final String athenzPrivateKey) throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        if (athenzPublicCert == null || athenzPublicCert.isEmpty()) {
            throw new FileNotFoundException("athenzPublicCert can not be empty");
        }
        if (athenzPrivateKey == null || athenzPrivateKey.isEmpty()) {
            throw new FileNotFoundException("athenzPrivateKey can not be empty");
        }

        final Supplier<InputStream> certFileSupplier;
        final Supplier<InputStream> keyFileSupplier;
        final Supplier<String> certLocationSupplier = () -> athenzPublicCert;
        final Supplier<String> keyLocationSupplier = () -> athenzPrivateKey;
        if (Paths.get(athenzPublicCert).isAbsolute() && Paths.get(athenzPrivateKey).isAbsolute()) {
            final File certFile = new File(athenzPublicCert);
            final File keyFile = new File(athenzPrivateKey);
            certFileSupplier = inputStreamSupplierFromFile(certFile);
            keyFileSupplier = inputStreamSupplierFromFile(keyFile);
            long startTime = System.currentTimeMillis();
            while (!certFile.exists() || !keyFile.exists()) {
                long durationInMillis = System.currentTimeMillis() - startTime;
                if (durationInMillis > KEY_WAIT_TIME_MILLIS) {
                    throw new KeyRefresherException("Keyfresher waited " + durationInMillis
                            + " ms for valid public cert: " + athenzPublicCert + " or private key: "
                            + athenzPrivateKey + " files. Giving up.");
                }
                LOG.error("Missing Athenz public certificate {} or private key {} files. Waiting {} ms",
                        athenzPublicCert, athenzPrivateKey, durationInMillis);
                Thread.sleep(1000);
            }
        } else {
            certFileSupplier = inputStreamSupplierFromResource(athenzPublicCert);
            keyFileSupplier = inputStreamSupplierFromResource(athenzPrivateKey);
        }

        // Pass input stream providers that throw unchecked exceptions which are caught and rethrown from here.
        try {
            return createKeyStore(certFileSupplier, certLocationSupplier, keyFileSupplier, keyLocationSupplier);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    /**
     * Create a {@link KeyStore} from in-memory pem strings.
     *
     * @param athenzPublicCertPem The public certificate pem
     * @param athenzPrivateKeyPem The private key pem
     * @return a KeyStore with loaded key and certificate
     * @throws IOException
     * @throws KeyRefresherException
     */
    public static KeyStore createKeyStoreFromPems(
            final String athenzPublicCertPem,
            final String athenzPrivateKeyPem) throws IOException, KeyRefresherException {
        return createKeyStore(
                inputStreamSupplierFromString(athenzPublicCertPem),
                () -> "in memory certificate pem",
                inputStreamSupplierFromString(athenzPrivateKeyPem),
                () -> "in memory private key pem");
    }

    /**
     * Create a {@link KeyStore} from suppliers of {@link InputStream} for cert and key.
     *
     * @param athenzPublicCertInputStream      Supplier of the certificate input stream
     * @param athenzPublicCertLocationSupplier Supplier of the location of the certificate (for error logging)
     * @param athenzPrivateKeyInputStream      Supplier of the private key input stream
     * @param athenzPrivateKeyLocationSupplier Supplier of the location of the certificate (for error logging)
     * @return a KeyStore with loaded key and certificate
     * @throws IOException
     * @throws KeyRefresherException
     */
    public static KeyStore createKeyStore(
            final Supplier<InputStream> athenzPublicCertInputStream,
            final Supplier<String> athenzPublicCertLocationSupplier,
            final Supplier<InputStream> athenzPrivateKeyInputStream,
            final Supplier<String> athenzPrivateKeyLocationSupplier) throws IOException, KeyRefresherException {
        List<? extends Certificate> certificates;
        PrivateKey privateKey;
        KeyStore keyStore = null;

        try (InputStream publicCertStream = athenzPublicCertInputStream.get();
             InputStream privateKeyStream = athenzPrivateKeyInputStream.get();
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
                throw new KeyRefresherException("Unknown object type: " + key.getClass().getName());
            }

            //noinspection unchecked
            certificates = (List<? extends Certificate>) cf.generateCertificates(publicCertStream);
            if (certificates.isEmpty()) {
                throw new KeyRefresherException("Certificate file contains empty certificate or an invalid certificate.");
            }
            //We are going to assume that the first one is the main certificate which will be used for the alias
            String alias = ((X509Certificate) certificates.get(0)).getSubjectX500Principal().getName();
            if (LOG.isDebugEnabled()) {
                LOG.debug("{} number of certificates found.  Using {} alias to create the keystore", certificates.size(), alias);
            }
            keyStore = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
            keyStore.load(null);
            keyStore.setKeyEntry(alias, privateKey, KEYSTORE_PASSWORD,
                    certificates.toArray((Certificate[]) new X509Certificate[certificates.size()]));

        } catch (CertificateException | NoSuchAlgorithmException e) {
            String keyStoreFailMsg = "Unable to load " + athenzPublicCertLocationSupplier.get() + " as a KeyStore.  Please check the validity of the file.";
            throw new KeyRefresherException(keyStoreFailMsg, e);
        } catch (KeyStoreException ignored) {
            LOG.error("No Provider supports a KeyStoreSpi implementation for the specified type.", ignored);
        }

        return keyStore;
    }

    /**
     * Generate JKS X.509 Truststore based on given input stream.
     * It is expected that the input stream is a list of x.509
     * certificates.
     *
     * @param inputStream input stream for the x.509 certificates.
     *                    caller responsible for closing the stream
     * @return KeyStore including all x.509 certificates
     * @throws IOException
     * @throws KeyRefresherException
     */
    public static KeyStore generateTrustStore(InputStream inputStream) throws IOException, KeyRefresherException {
        CertificateFactory factory;
        KeyStore keyStore = null;
        try {
            factory = CertificateFactory.getInstance("X.509");
            keyStore = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
            keyStore.load(null);
            for (Certificate certificate : factory.generateCertificates(inputStream)) {
                String alias = ((X509Certificate) certificate).getSubjectX500Principal().getName();
                keyStore.setCertificateEntry(alias, certificate);
            }
        } catch (CertificateException | NoSuchAlgorithmException e) {
            String keyStoreFailMsg = "Unable to load the inputstream as a KeyStore.  Please check the content.";
            throw new KeyRefresherException(keyStoreFailMsg, e);
        } catch (KeyStoreException ignored) {
            LOG.error("No Provider supports a KeyStoreSpi implementation for the specified type " + DEFAULT_KEYSTORE_TYPE, ignored);
        }
        return keyStore;
    }
}
