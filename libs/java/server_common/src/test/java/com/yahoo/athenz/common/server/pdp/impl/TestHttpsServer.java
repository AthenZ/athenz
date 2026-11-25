/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.pdp.impl;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;

/**
 * HTTPS test server with a freshly generated self-signed certificate whose
 * only SAN is "localhost". Handlers map a request body to a response.
 */
final class TestHttpsServer implements AutoCloseable {

    static final class Reply {
        final int status;
        final String body;
        final long delayMs;

        Reply(int status, String body) {
            this(status, body, 0);
        }

        Reply(int status, String body, long delayMs) {
            this.status = status;
            this.body = body;
            this.delayMs = delayMs;
        }
    }

    private static final char[] PASSWORD = "changeit".toCharArray();

    private final HttpsServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final SSLContext clientSslContext;
    final Map<String, String> lastBodies = new ConcurrentHashMap<>();
    final Map<String, Map<String, String>> lastHeaders = new ConcurrentHashMap<>();

    TestHttpsServer() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        X500Name name = new X500Name("CN=localhost");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                new Date(System.currentTimeMillis() - 60000), new Date(System.currentTimeMillis() + 3600000),
                name, keyPair.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", keyPair.getPrivate(), PASSWORD, new X509Certificate[] { cert });
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, PASSWORD);
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("server", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        clientSslContext = SSLContext.getInstance("TLS");
        clientSslContext.init(null, tmf.getTrustManagers(), null);

        server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        server.setExecutor(executor);
        server.start();
    }

    SSLContext clientSslContext() {
        return clientSslContext;
    }

    int port() {
        return server.getAddress().getPort();
    }

    String baseUrl() {
        return "https://localhost:" + port();
    }

    void handle(final String path, final Function<String, Reply> handler) {
        server.createContext(path, exchange -> {
            final String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            lastBodies.put(path, body);
            Map<String, String> headers = new ConcurrentHashMap<>();
            exchange.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(), v.get(0)));
            lastHeaders.put(path, headers);
            Reply reply = handler.apply(body);
            sleep(reply.delayMs);
            if (reply.body == null) {
                exchange.sendResponseHeaders(reply.status, -1);
                exchange.close();
                return;
            }
            byte[] bytes = reply.body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(reply.status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            } catch (IOException ignored) {
                // client went away
            }
        });
    }

    private static void sleep(long ms) {
        if (ms <= 0) {
            return;
        }
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}
