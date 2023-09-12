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
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECParameterSpec;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

public class Utils {

    private static final Logger LOG = LoggerFactory.getLogger(Utils.class);

    private static final String SSLCONTEXT_ALGORITHM_TLS12 = "TLSv1.2";
    private static final String SSLCONTEXT_ALGORITHM_TLS13 = "TLSv1.3";

    private static final String PROP_KEY_WAIT_TIME         = "athenz.cert_refresher.key_wait_time";
    private static final String PROP_TLS_ALGORITHM         = "athenz.cert_refresher.tls_algorithm";
    private static final String PROP_DISABLE_PUB_KEY_CHECK = "athenz.cert_refresher.disable_public_key_check";
    private static final String PROP_SKIP_BC_PROVIDER      = "athenz.cert_refresher.skip_bc_provider";

    private static final char[] KEYSTORE_PASSWORD = "secret".toCharArray();

    private static final String DEFAULT_KEYSTORE_TYPE = "JKS";

    // how long to wait for keys - default 10 mins

    private static final long KEY_WAIT_TIME_MILLIS = TimeUnit.MINUTES.toMillis(
            Integer.parseInt(System.getProperty(PROP_KEY_WAIT_TIME, "10")));

    private static boolean disablePublicKeyCheck = Boolean.parseBoolean(
            System.getProperty(PROP_DISABLE_PUB_KEY_CHECK, "false"));

    static {
        boolean skipBCProvider = Boolean.parseBoolean(System.getProperty(PROP_SKIP_BC_PROVIDER, "false"));
        if (!skipBCProvider) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    public static void setDisablePublicKeyCheck(boolean state) {
        disablePublicKeyCheck = state;
    }

    public static KeyStore getKeyStore(final String jksFilePath) throws IOException, KeyRefresherException {
        return getKeyStore(jksFilePath, KEYSTORE_PASSWORD);
    }

    public static KeyStore getKeyStore(final String jksFilePath, final char[] password)
            throws IOException, KeyRefresherException {

        if (jksFilePath == null || jksFilePath.isEmpty()) {
            throw new FileNotFoundException("jksFilePath is empty");
        }
        String keyStoreFailMsg = "Unable to load " + jksFilePath + " as a KeyStore.  Please check the validity of the file.";
        try {
            KeyStore keyStore = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);

            if (Paths.get(jksFilePath).isAbsolute()) {
                // Can not cover this branch in unit test. Can not refer any files by absolute paths
                try (InputStream jksFileInputStream = new FileInputStream(jksFilePath)) {
                    keyStore.load(jksFileInputStream, password);
                    return keyStore;
                } catch (NoSuchAlgorithmException | CertificateException e) {
                    throw new KeyRefresherException(keyStoreFailMsg, e);
                }
            }

            try (InputStream jksFileInputStream = Utils.class.getClassLoader().getResourceAsStream(jksFilePath)) {
                keyStore.load(jksFileInputStream, password);
                return keyStore;
            } catch (NoSuchAlgorithmException | CertificateException e) {
                throw new KeyRefresherException(keyStoreFailMsg, e);
            }

        } catch (KeyStoreException ex) {
            LOG.error("No Provider supports a KeyStoreSpi implementation for the specified type.", ex);
        }
        return null;
    }

    public static KeyManager[] getKeyManagers(final String athenzPublicCert, final String athenzPrivateKey)
            throws IOException, InterruptedException, KeyRefresherException {

        final KeyStore keystore = createKeyStore(athenzPublicCert, athenzPrivateKey);
        return getKeyManagersFromKeyStore(keystore);
    }

    public static KeyManager[] getKeyManagersFromPems(final String athenzPublicCertPem, final String athenzPrivateKeyPem)
            throws IOException, KeyRefresherException {

        final KeyStore keystore = Utils.createKeyStoreFromPems(athenzPublicCertPem, athenzPrivateKeyPem);
        return getKeyManagersFromKeyStore(keystore);
    }

    private static KeyManager[] getKeyManagersFromKeyStore(final KeyStore keystore) throws KeyRefresherException {
        KeyManagerFactory keyManagerFactory;
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
     * @param trustStorePath path to the trust-store
     * @param athenzPublicCert path to the x.509 certificate file
     * @param athenzPrivateKey path to the private key file
     * @return KeyRefresher object
     * @throws KeyRefresherException in case of any key refresher errors processing the request
     * @throws InterruptedException in case of interrupted thread
     * @throws IOException in case of any errors with reading files
     * @throws FileNotFoundException in case key/cert are not found
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
     * @param trustStorePath path to the trust-store
     * @param trustStorePassword trust store password
     * @param athenzPublicCert path to the x.509 certificate file
     * @param athenzPrivateKey path to the private key file
     * @return KeyRefresher object
     * @throws KeyRefresherException in case of any key refresher errors processing the request
     * @throws InterruptedException in case of interrupted thread
     * @throws IOException in case of any errors with reading files
     * @throws FileNotFoundException in case key/cert are not found
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
     * @param trustStorePath path to the trust-store
     * @param trustStorePassword trust store password
     * @param athenzPublicCert path to the x.509 certificate file
     * @param athenzPrivateKey path to the private key file
     * @return KeyRefresher object
     * @throws KeyRefresherException in case of any key refresher errors processing the request
     * @throws InterruptedException in case of interrupted thread
     * @throws IOException in case of any errors with reading files
     * @throws FileNotFoundException in case key/cert are not found
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
     * @param trustStorePath path to the trust-store
     * @param trustStorePassword trust store password
     * @param athenzPublicCert path to the x.509 certificate file
     * @param athenzPrivateKey path to the private key file
     * @param keyRefresherListener notify listener that key/cert has changed
     * @return KeyRefresher object
     * @throws KeyRefresherException in case of any key refresher errors processing the request
     * @throws InterruptedException in case of interrupted thread
     * @throws IOException in case of any errors with reading files
     * @throws FileNotFoundException in case key/cert are not found
     */
    public static KeyRefresher generateKeyRefresher(final String trustStorePath,
                                                    final char[] trustStorePassword, final String athenzPublicCert,
                                                    final String athenzPrivateKey, final KeyRefresherListener keyRefresherListener)
            throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        TrustStore trustStore = new TrustStore(trustStorePath,
                new JavaKeyStoreProvider(trustStorePath, trustStorePassword));
        return getKeyRefresher(athenzPublicCert, athenzPrivateKey, trustStore, keyRefresherListener);
    }

    /**
     * Generate the KeyRefresher object first as the server will need access to
     * it (to turn it off and on as needed). It requires that the proxies are
     * created which are then stored in the KeyRefresher. This method requires
     * the paths to the private key and certificate files along with the
     * trust-store path which has been created already and just needs to be
     * monitored for changes. Using default password of "secret" for both stores.
     *
     * @param caCertPath path to the trust-store
     * @param athenzPublicCert path to the x.509 certificate file
     * @param athenzPrivateKey path to the private key file
     * @return KeyRefresher object
     * @throws KeyRefresherException in case of any key refresher errors processing the request
     * @throws InterruptedException in case of interrupted thread
     * @throws IOException in case of any errors with reading files
     * @throws FileNotFoundException in case key/cert are not found
     */
    public static KeyRefresher generateKeyRefresherFromCaCert(final String caCertPath,
            final String athenzPublicCert, final String athenzPrivateKey)
            throws IOException, InterruptedException, KeyRefresherException {
        TrustStore trustStore = new TrustStore(caCertPath, new CaCertKeyStoreProvider(caCertPath));
        return getKeyRefresher(athenzPublicCert, athenzPrivateKey, trustStore);
    }

    static KeyRefresher getKeyRefresher(String athenzPublicCert, String athenzPrivateKey, TrustStore trustStore)
            throws IOException, InterruptedException, KeyRefresherException {
        return getKeyRefresher(athenzPublicCert, athenzPrivateKey, trustStore, null);
    }

    static KeyRefresher getKeyRefresher(String athenzPublicCert, String athenzPrivateKey,
            TrustStore trustStore, final KeyRefresherListener keyRefresherListener)
            throws IOException, InterruptedException, KeyRefresherException {
        KeyRefresher keyRefresher;
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
     * this method will create a new SSLContext object with the given tls protocol
     * that can be updated on the fly should the public/private keys / trustStore change.
     *
     * @param keyManagerProxy   uses standard KeyManager interface except also allows
     *                          for the updating of KeyManager on the fly
     * @param trustManagerProxy uses standard TrustManager interface except also allows
     *                          for the updating of TrustManager on the fly
     * @param protocol          TLS protocol supported by the context
     * @return a valid SSLContext object using the passed in key/trust managers
     * @throws KeyRefresherException in case of any errors
     */
    public static SSLContext buildSSLContext(KeyManagerProxy keyManagerProxy, TrustManagerProxy trustManagerProxy,
            final String protocol) throws KeyRefresherException {
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance(protocol);
            sslContext.init(new KeyManager[]{keyManagerProxy},
                    trustManagerProxy == null ? null : new TrustManager[]{trustManagerProxy}, null);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyRefresherException("No Provider supports a SSLContextSpi implementation for the specified protocol " + protocol, e);
        } catch (KeyManagementException e) {
            throw new KeyRefresherException("Unable to create SSLContext.", e);
        }
        return sslContext;
    }

    /**
     * this method will create a new SSLContext object that can be updated on the fly should the
     * public/private keys / trustStore change. It defaults to TLS 1.3 protocol. If the 1.3
     * is not supported, then it'll fall back to TLS 1.2 protocol.
     *
     * @param keyManagerProxy   uses standard KeyManager interface except also allows
     *                          for the updating of KeyManager on the fly
     * @param trustManagerProxy uses standard TrustManager interface except also allows
     *                          for the updating of TrustManager on the fly
     * @return a valid SSLContext object using the passed in key/trust managers
     * @throws KeyRefresherException in case of any errors
     */
    public static SSLContext buildSSLContext(KeyManagerProxy keyManagerProxy, TrustManagerProxy trustManagerProxy)
            throws KeyRefresherException {

        // if the user has configured our tls property then that's what we'll
        // be using for our ssl context

        final String protocol = System.getProperty(PROP_TLS_ALGORITHM);
        if (protocol != null && !protocol.isEmpty()) {
            return buildSSLContext(keyManagerProxy, trustManagerProxy, protocol);
        }

        // we're going to default to 1.3 protocol and if it fails, we're
        // going to fall back and try tls 1.2

        try {
            return buildSSLContext(keyManagerProxy, trustManagerProxy, SSLCONTEXT_ALGORITHM_TLS13);
        } catch (KeyRefresherException ignored) {
            return buildSSLContext(keyManagerProxy, trustManagerProxy, SSLCONTEXT_ALGORITHM_TLS12);
        }
    }

    /**
     * this method will create a new SSLContext object based on the given strings representing
     * the trust CA certificates, x.509 certificate and private key all in PEM format. There is
     * no refresh capability for the SSL context since it is created based on given strings
     * that cannot change.
     *
     * @param caCertsPem CA certificates in PEM format
     * @param athenzPublicCertPem x.509 certificate in PEM format
     * @param athenzPrivateKeyPem private key in PEM format
     * @return a valid SSLContext object
     */
    public static SSLContext buildSSLContext(final String caCertsPem, final String athenzPublicCertPem,
            final String athenzPrivateKeyPem) throws KeyRefresherException, IOException {

        TrustManagerProxy trustManagerProxy = null;
        if (caCertsPem != null) {
            TrustStore trustStore = new TrustStore(null, new CaCertKeyStoreProvider(inputStreamSupplierFromString(caCertsPem)));
            trustManagerProxy = new TrustManagerProxy(trustStore.getTrustManagers());
        }

        KeyManagerProxy keyManagerProxy =
                new KeyManagerProxy(getKeyManagersFromPems(athenzPublicCertPem, athenzPrivateKeyPem));

        // if the user has configured our tls property then that's what we'll
        // be using for our ssl context otherwise we'll default to TLS 1.3

        final String protocol = System.getProperty(PROP_TLS_ALGORITHM, SSLCONTEXT_ALGORITHM_TLS13);
        return buildSSLContext(keyManagerProxy, trustManagerProxy, protocol);
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
     * @throws KeyRefresherException in case of any key refresher errors processing the request
     * @throws InterruptedException in case of interrupted thread
     * @throws IOException in case of any errors with reading files
     * @throws FileNotFoundException in case key/cert are not found
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
                    throw new KeyRefresherException("KeyRefresher waited " + durationInMillis
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
     * @throws KeyRefresherException in case of any key refresher errors processing the request
     * @throws IOException in case of any errors with reading files
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
     * @param athenzPrivateKeyLocationSupplier Supplier of the location of the private key (for error logging)
     * @return a KeyStore with loaded key and certificate
     * @throws KeyRefresherException in case of any key refresher errors processing the request
     * @throws IOException in case of any errors with reading files
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
                throw new KeyRefresherException("Unknown object type: " + (key == null ? "null" : key.getClass().getName()));
            }

            certificates = (List<? extends Certificate>) cf.generateCertificates(publicCertStream);
            if (certificates.isEmpty()) {
                throw new KeyRefresherException("Certificate file contains empty certificate or an invalid certificate.");
            }
            //We are going to assume that the first one is the main certificate which will be used for the alias
            String alias = ((X509Certificate) certificates.get(0)).getSubjectX500Principal().getName();
            if (LOG.isDebugEnabled()) {
                LOG.debug("{} number of certificates found. Using {} alias to create the keystore", certificates.size(), alias);
            }
            // if configured (default - true) verify that the private key and certificate match
            // you would only want to disable this check if the library does not support
            // the private key type (currently RSA and EC keys are supported)
            verifyPrivateKeyCertsMatch(privateKey, certificates);
            keyStore = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
            keyStore.load(null);
            keyStore.setKeyEntry(alias, privateKey, KEYSTORE_PASSWORD,
                    certificates.toArray((Certificate[]) new X509Certificate[certificates.size()]));

        } catch (CertificateException | NoSuchAlgorithmException ex) {
            String keyStoreFailMsg = "Unable to load private key: " + athenzPrivateKeyLocationSupplier.get() +
                    " and certificate: " + athenzPublicCertLocationSupplier.get() +
                    " as a KeyStore. Please check the validity of the files.";
            throw new KeyRefresherException(keyStoreFailMsg, ex);
        } catch (KeyStoreException ex) {
            LOG.error("No Provider supports a KeyStoreSpi implementation for the specified type.", ex);
        }

        return keyStore;
    }

    static boolean verifyPrivatePublicKeyMatch(PrivateKey privateKey, PublicKey publicKey) {
        if (publicKey instanceof RSAKey) {
            if (!(privateKey instanceof RSAKey)) {
                return false;
            }
            RSAKey pubRSAKey = (RSAKey) publicKey;
            RSAKey prvRSAKey = (RSAKey) privateKey;
            return pubRSAKey.getModulus().compareTo(prvRSAKey.getModulus()) == 0;
        } else if (publicKey instanceof ECKey) {
            if (!(privateKey instanceof ECKey)) {
                return false;
            }
            ECKey pubECKey = (ECKey) publicKey;
            ECKey prvECKey = (ECKey) privateKey;
            ECParameterSpec pubECParam = pubECKey.getParams();
            ECParameterSpec prvECParam = prvECKey.getParams();
            return (pubECParam.getCurve().equals(prvECParam.getCurve()) &&
                    pubECParam.getGenerator().equals(prvECParam.getGenerator()) &&
                    pubECParam.getOrder().compareTo(prvECParam.getOrder()) == 0 &&
                    pubECParam.getCofactor() == prvECParam.getCofactor());
        }
        return false;
    }

    static void verifyPrivateKeyCertsMatch(PrivateKey privateKey, List<? extends Certificate> certificates) throws KeyRefresherException {
        // if the check is disabled then we have nothing to do
        if (disablePublicKeyCheck) {
            return;
        }
        // we need to make sure at least one of the certificates matches
        // the public key for the given private key
        for (Certificate certificate : certificates) {
            if (verifyPrivatePublicKeyMatch(privateKey, certificate.getPublicKey())) {
                return;
            }
        }
        throw new KeyRefresherException("Public key mismatch");
    }

    /**
     * Generate JKS X.509 Truststore based on given input stream.
     * It is expected that the input stream is a list of x.509
     * certificates.
     *
     * @param inputStream input stream for the x.509 certificates.
     *                    caller responsible for closing the stream
     * @return KeyStore including all x.509 certificates
     * @throws KeyRefresherException in case of any key refresher errors processing the request
     * @throws IOException in case of any errors with reading files
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
            String keyStoreFailMsg = "Unable to load the input stream as a KeyStore. Please check the content.";
            throw new KeyRefresherException(keyStoreFailMsg, e);
        } catch (KeyStoreException ex) {
            LOG.error("No Provider supports a KeyStoreSpi implementation for the specified type {}", DEFAULT_KEYSTORE_TYPE, ex);
        }
        return keyStore;
    }
}
