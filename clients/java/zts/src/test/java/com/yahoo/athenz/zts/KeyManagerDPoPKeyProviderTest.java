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
package com.yahoo.athenz.zts;

import com.oath.auth.KeyManagerProxy;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import com.yahoo.athenz.auth.token.DPoPProof;
import com.yahoo.athenz.auth.token.DPoPProofOptions;
import com.yahoo.athenz.auth.util.Crypto;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.mockito.AdditionalMatchers;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;
import java.io.File;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import static org.testng.Assert.*;

public class KeyManagerDPoPKeyProviderTest {

    private static final String IDENTITY_CERT = new File("src/test/resources/unit.cert.pem").getAbsolutePath();
    private static final String IDENTITY_KEY = new File("src/test/resources/unit.key.pem").getAbsolutePath();
    private static final Pattern EC_PARAMETERS_BLOCK =
            Pattern.compile("-----BEGIN EC PARAMETERS-----.*?-----END EC PARAMETERS-----\\s*", Pattern.DOTALL);
    private static final String ROTATED_CERT = new File("src/test/resources/ec_public_x509.cert").getAbsolutePath();
    private static final String ROTATED_KEY = new File("src/test/resources/unit_test_ec_private.key").getAbsolutePath();

    private static final String ALIAS = "svc";
    private static final String[] KEY_TYPES = { "EC", "RSA" };
    private static final String PROOF_ZTS_URL = "https://zts.athenz.io/zts/v1";
    private static final String CORETECH_REQUEST = "grant_type=client_credentials&expires_in=3600&scope=coretech%3Adomain";

    private KeyPair keyA;
    private KeyPair keyB;
    private X509Certificate[] chainA;
    private X509Certificate[] chainB;

    @BeforeClass
    public void init() throws Exception {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE, "false");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        keyA = generator.generateKeyPair();
        keyB = generator.generateKeyPair();
        chainA = certChain(keyA);
        chainB = certChain(keyB);
    }

    @BeforeMethod
    public void setup() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ZTSClient.ACCESS_TOKEN_CACHE.clear();
    }

    @AfterMethod
    public void cleanup() {
        ZTSClient.ACCESS_TOKEN_CACHE.clear();
        System.clearProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF);
        ZTSClient.initConfigValues();
    }

    /**
     * The identity key file starts with an EC PARAMETERS block that the key
     * refresher's pem parser does not support, so we load it without that block
     */
    private static KeyManager[] identityKeyManagers() throws Exception {
        final String certPem = Files.readString(Paths.get(IDENTITY_CERT));
        final String keyPem = EC_PARAMETERS_BLOCK.matcher(Files.readString(Paths.get(IDENTITY_KEY))).replaceAll("");
        return Utils.getKeyManagersFromPems(certPem, keyPem);
    }

    /**
     * The same EC key may be encoded with named or explicit curve parameters
     * depending on the provider that loaded it, so we compare the key value
     */
    private static BigInteger privateScalar(PrivateKey privateKey) {
        return ((ECPrivateKey) privateKey).getS();
    }

    private static PublicKey certPublicKey(final String certFile) {
        return Crypto.loadX509Certificate(new File(certFile)).getPublicKey();
    }

    private static X509Certificate[] certChain(KeyPair keyPair) {
        X509Certificate cert = Mockito.mock(X509Certificate.class);
        Mockito.when(cert.getPublicKey()).thenReturn(keyPair.getPublic());
        return new X509Certificate[] { cert };
    }

    private static X509KeyManager keyManager() {
        X509KeyManager keyManager = Mockito.mock(X509KeyManager.class);
        Mockito.when(keyManager.chooseClientAlias(AdditionalMatchers.aryEq(KEY_TYPES), ArgumentMatchers.isNull(),
                ArgumentMatchers.isNull())).thenReturn(ALIAS);
        return keyManager;
    }

    private static void assertKeyPairRejected(DPoPKeyProvider provider, final String message) {
        try {
            provider.getKeyPair();
            fail();
        } catch (IllegalStateException ex) {
            assertTrue(ex.getMessage().contains(message), ex.getMessage());
        }
    }

    @Test
    public void testKeyFollowsKeyRefresher() throws Exception {

        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(identityKeyManagers());
        KeyRefresher keyRefresher = new KeyRefresher(IDENTITY_CERT, IDENTITY_KEY, null, keyManagerProxy, null);
        KeyManagerDPoPKeyProvider provider = new KeyManagerDPoPKeyProvider(keyRefresher);

        KeyPair keyPair = provider.getKeyPair();
        assertEquals(keyPair.getPublic().getEncoded(), certPublicKey(IDENTITY_CERT).getEncoded());
        assertEquals(privateScalar(keyPair.getPrivate()), privateScalar(Crypto.loadPrivateKey(new File(IDENTITY_KEY))));

        // once the key refresher reloads a new key and certificate the
        // provider returns the new identity key

        keyManagerProxy.setKeyManager(Utils.getKeyManagers(ROTATED_CERT, ROTATED_KEY));
        keyPair = provider.getKeyPair();
        assertEquals(keyPair.getPublic().getEncoded(), certPublicKey(ROTATED_CERT).getEncoded());
        assertEquals(privateScalar(keyPair.getPrivate()), privateScalar(Crypto.loadPrivateKey(new File(ROTATED_KEY))));
    }

    @Test
    public void testExplicitAlias() {

        X509KeyManager keyManager = Mockito.mock(X509KeyManager.class);
        Mockito.when(keyManager.getPrivateKey(ALIAS)).thenReturn(keyA.getPrivate());
        Mockito.when(keyManager.getCertificateChain(ALIAS)).thenReturn(chainA);

        KeyPair keyPair = new KeyManagerDPoPKeyProvider(keyManager, ALIAS).getKeyPair();
        assertEquals(keyPair.getPrivate(), keyA.getPrivate());
        assertEquals(keyPair.getPublic(), keyA.getPublic());
    }

    @Test
    public void testNullKeyManager() {
        try {
            new KeyManagerDPoPKeyProvider((X509KeyManager) null);
            fail();
        } catch (NullPointerException ex) {
            assertEquals(ex.getMessage(), "keyManager must not be null");
        }
    }

    @Test
    public void testMissingClientKey() {

        // a missing key must fail the request instead of silently disabling dpop

        X509KeyManager noAlias = Mockito.mock(X509KeyManager.class);
        assertKeyPairRejected(new KeyManagerDPoPKeyProvider(noAlias), "has no EC or RSA client key");

        X509KeyManager noKey = keyManager();
        Mockito.when(noKey.getCertificateChain(ALIAS)).thenReturn(chainA);
        assertKeyPairRejected(new KeyManagerDPoPKeyProvider(noKey), "no private key or certificate for alias: svc");

        X509KeyManager noChain = keyManager();
        Mockito.when(noChain.getPrivateKey(ALIAS)).thenReturn(keyA.getPrivate());
        assertKeyPairRejected(new KeyManagerDPoPKeyProvider(noChain), "no private key or certificate for alias: svc");

        X509KeyManager emptyChain = keyManager();
        Mockito.when(emptyChain.getPrivateKey(ALIAS)).thenReturn(keyA.getPrivate());
        Mockito.when(emptyChain.getCertificateChain(ALIAS)).thenReturn(new X509Certificate[0]);
        assertKeyPairRejected(new KeyManagerDPoPKeyProvider(emptyChain), "no private key or certificate for alias: svc");
    }

    @Test
    public void testKeyManagerChangedDuringRead() {

        // the first read sees key A, the re-read sees key B: the provider
        // reads again and returns key B with its matching certificate

        X509KeyManager keyManager = keyManager();
        Mockito.when(keyManager.getPrivateKey(ALIAS)).thenReturn(keyA.getPrivate(), keyB.getPrivate());
        Mockito.when(keyManager.getCertificateChain(ALIAS)).thenReturn(chainA, chainB);

        KeyPair keyPair = new KeyManagerDPoPKeyProvider(keyManager).getKeyPair();
        assertEquals(keyPair.getPrivate(), keyB.getPrivate());
        assertEquals(keyPair.getPublic(), keyB.getPublic());

        // the certificate changed but the key re-read did not

        X509KeyManager certChanged = keyManager();
        Mockito.when(certChanged.getPrivateKey(ALIAS)).thenReturn(keyA.getPrivate());
        Mockito.when(certChanged.getCertificateChain(ALIAS)).thenReturn(chainA, chainB,
                chainA);
        keyPair = new KeyManagerDPoPKeyProvider(certChanged).getKeyPair();
        assertEquals(keyPair.getPublic(), keyA.getPublic());

        // the re-read finds a key manager without our alias

        X509KeyManager aliasRemoved = keyManager();
        Mockito.when(aliasRemoved.getPrivateKey(ALIAS)).thenReturn(keyA.getPrivate());
        Mockito.when(aliasRemoved.getCertificateChain(ALIAS)).thenReturn(chainA, null, chainA,
                new X509Certificate[0], chainA);
        keyPair = new KeyManagerDPoPKeyProvider(aliasRemoved).getKeyPair();
        assertEquals(keyPair.getPublic(), keyA.getPublic());
    }

    @Test
    public void testKeyManagerKeepsChanging() {

        final AtomicInteger reads = new AtomicInteger();
        X509KeyManager keyManager = keyManager();
        Mockito.when(keyManager.getPrivateKey(ALIAS)).thenAnswer(invocation ->
                reads.getAndIncrement() % 2 == 0 ? keyA.getPrivate() : keyB.getPrivate());
        Mockito.when(keyManager.getCertificateChain(ALIAS)).thenReturn(chainA);

        assertKeyPairRejected(new KeyManagerDPoPKeyProvider(keyManager), "key manager changed while reading the key");
    }

    @Test
    public void testZTSClientProofsFollowKeyRefresher() throws Exception {

        // the ssl context and the dpop proofs use the same key refresher

        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(identityKeyManagers());
        KeyRefresher keyRefresher = new KeyRefresher(IDENTITY_CERT, IDENTITY_KEY, null, keyManagerProxy, null);

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        ZTSClient client = new ZTSClient("http://localhost:4080", keyRefresher);
        assertNull(client.getDPoPKeyPair());
        client.enableDPoPWithIdentityKey();
        client.setZTSRDLGeneratedClient(rdlClient);

        DPoPRequestInterceptor interceptor = new DPoPRequestInterceptor(PROOF_ZTS_URL, client::getRequestDPoPKeyPair);
        DPoPProofOptions options = DPoPProofOptions.builder().addAllowedHtu(PROOF_ZTS_URL + "/oauth2/token").build();
        Mockito.when(rdlClient.postAccessTokenRequest(CORETECH_REQUEST)).thenAnswer(invocation -> {
            BasicHttpRequest request = new BasicHttpRequest("POST", "/zts/v1/oauth2/token");
            interceptor.process(request, null, null);
            DPoPProof proof = new DPoPProof(request.getFirstHeader(DPoPProof.HTTP_HEADER).getValue(), "POST",
                    options, System.currentTimeMillis() / 1000);
            return new AccessTokenResponse().setAccess_token("token-" + proof.getJwkThumbprint())
                    .setToken_type("DPoP").setExpires_in(3600);
        });

        final String identityThumbprint = DPoPProof.computeJwkThumbprint(certPublicKey(IDENTITY_CERT));
        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "token-" + identityThumbprint);

        // after the key refresher reloads the identity, new tokens are bound to the new key

        keyManagerProxy.setKeyManager(Utils.getKeyManagers(ROTATED_CERT, ROTATED_KEY));
        final String rotatedThumbprint = DPoPProof.computeJwkThumbprint(certPublicKey(ROTATED_CERT));
        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "token-" + rotatedThumbprint);
        client.close();
    }

    @Test
    public void testZTSClientWithKeyRefresher() throws Exception {

        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(identityKeyManagers());
        KeyRefresher keyRefresher = new KeyRefresher(IDENTITY_CERT, IDENTITY_KEY, null, keyManagerProxy, null);

        try (ZTSClient client = new ZTSClient("https://zts.athenz.io/zts/v1", "https://proxy.athenz.io:4080",
                keyRefresher)) {

            // dpop stays disabled until the caller enables it

            assertNull(client.getDPoPKeyPair());
            client.enableDPoPWithIdentityKey();
            assertEquals(client.getDPoPKeyPair().getPublic().getEncoded(), certPublicKey(IDENTITY_CERT).getEncoded());
        }
    }

    @Test
    public void testZTSClientWithInvalidKeyRefresher() throws Exception {

        for (KeyRefresher keyRefresher : new KeyRefresher[] { null,
                new KeyRefresher(IDENTITY_CERT, IDENTITY_KEY, null, null, null) }) {
            try {
                new ZTSClient("https://zts.athenz.io/zts/v1", keyRefresher);
                fail();
            } catch (IllegalArgumentException ex) {
                assertEquals(ex.getMessage(), "KeyRefresher object with a key manager must be specified");
            }
        }

        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(identityKeyManagers());
        KeyRefresher keyRefresher = new KeyRefresher(IDENTITY_CERT, IDENTITY_KEY, null, keyManagerProxy, null);
        System.setProperty("athenz.cert_refresher.tls_algorithm", "unknown-protocol");
        try {
            new ZTSClient("https://zts.athenz.io/zts/v1", keyRefresher);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().startsWith("Unable to create SSLContext from KeyRefresher"), ex.getMessage());
        } finally {
            System.clearProperty("athenz.cert_refresher.tls_algorithm");
        }
    }

    private static final TrustManager[] TRUST_ALL = { new X509ExtendedTrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) { }
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) { }
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) { }
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) { }
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    } };

    /**
     * Token endpoint that requires the DPoP proof key to be the key of the
     * client certificate on the TLS connection the request arrived on, like
     * ZTS with athenz.zts.dpop_require_cert_key_match enabled
     */
    private static HttpsServer startCertKeyMatchTokenServer(List<String> peerThumbprints) throws Exception {

        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(identityKeyManagers(), TRUST_ALL, null);
        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters sslParameters = serverContext.getDefaultSSLParameters();
                sslParameters.setWantClientAuth(true);
                params.setSSLParameters(sslParameters);
            }
        });
        final String htu = "https://localhost:" + server.getAddress().getPort() + "/zts/v1/oauth2/token";
        final DPoPProofOptions options = DPoPProofOptions.builder().addAllowedHtu(htu).build();
        server.createContext("/zts/v1/oauth2/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            final PublicKey peerKey = ((HttpsExchange) exchange).getSSLSession().getPeerCertificates()[0].getPublicKey();
            final String peerThumbprint = DPoPProof.computeJwkThumbprint(peerKey);
            peerThumbprints.add(peerThumbprint);
            final String proofThumbprint = new DPoPProof(exchange.getRequestHeaders().getFirst(DPoPProof.HTTP_HEADER),
                    "POST", options, System.currentTimeMillis() / 1000).getJwkThumbprint();
            final int status = proofThumbprint.equals(peerThumbprint) ? 200 : 400;
            final byte[] body = (status == 200
                    ? "{\"access_token\":\"token-" + proofThumbprint + "\",\"token_type\":\"DPoP\",\"expires_in\":3600}"
                    : "{\"code\":400,\"message\":\"invalid_dpop_proof: proof key does not match certificate key\"}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        return server;
    }

    @Test
    public void testZTSClientIdentityKeyRotationOverTls() throws Exception {

        // after the identity key and certificate are rotated, requests must not
        // reach the server over a connection or resumed session authenticated
        // with the old certificate while the proof is signed with the new key

        final List<String> peerThumbprints = new CopyOnWriteArrayList<>();
        HttpsServer server = startCertKeyMatchTokenServer(peerThumbprints);

        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(identityKeyManagers());
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[] { keyManagerProxy }, TRUST_ALL, null);

        final String identityThumbprint = DPoPProof.computeJwkThumbprint(certPublicKey(IDENTITY_CERT));
        final String rotatedThumbprint = DPoPProof.computeJwkThumbprint(certPublicKey(ROTATED_CERT));

        try (ZTSClient client = new ZTSClient("https://localhost:" + server.getAddress().getPort(), sslContext)) {
            client.setDPoPKeyProvider(new KeyManagerDPoPKeyProvider(keyManagerProxy));

            assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "token-" + identityThumbprint);
            assertEquals(client.getAccessToken("sports", null, 3600).getAccess_token(), "token-" + identityThumbprint);

            keyManagerProxy.setKeyManager(Utils.getKeyManagers(ROTATED_CERT, ROTATED_KEY));

            assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "token-" + rotatedThumbprint);
            assertEquals(client.getAccessToken("weather", null, 3600).getAccess_token(), "token-" + rotatedThumbprint);
        } finally {
            server.stop(0);
        }
        assertEquals(peerThumbprints, List.of(identityThumbprint, identityThumbprint,
                rotatedThumbprint, rotatedThumbprint));
    }

    @Test
    public void testEnableDPoPWithIdentityKeyRequiresKeyRefresher() throws Exception {

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        try (ZTSClient client = new ZTSClient("https://zts.athenz.io/zts/v1", sslContext)) {
            client.enableDPoPWithIdentityKey();
            fail();
        } catch (IllegalStateException ex) {
            assertEquals(ex.getMessage(), "DPoP with the identity key requires a ZTSClient created with a KeyRefresher");
        }
    }
}
