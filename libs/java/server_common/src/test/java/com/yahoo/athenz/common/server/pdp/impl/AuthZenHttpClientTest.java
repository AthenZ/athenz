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

import com.yahoo.athenz.common.server.pdp.ExternalPdpException;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.*;

public class AuthZenHttpClientTest {

    private TestHttpsServer server;

    @BeforeClass
    public void setup() throws Exception {
        server = new TestHttpsServer();
        server.handle("/ok", body -> new TestHttpsServer.Reply(200, "{\"echo\":" + (body.isEmpty() ? "null" : body) + "}"));
        server.handle("/unavailable", body -> new TestHttpsServer.Reply(503, "{}"));
        server.handle("/throttled", body -> new TestHttpsServer.Reply(429, "{}"));
        server.handle("/bad", body -> new TestHttpsServer.Reply(400, "{}"));
        server.handle("/empty", body -> new TestHttpsServer.Reply(204, null));
        server.handle("/large", body -> new TestHttpsServer.Reply(200, "x".repeat(5000)));
        server.handle("/slow", body -> new TestHttpsServer.Reply(200, "{}", 1500));
    }

    @AfterClass
    public void shutdown() {
        server.close();
    }

    private AuthZenHttpClient client(int maxBytes) {
        return new AuthZenHttpClient(server.clientSslContext(), 1000, 500, 4, maxBytes);
    }

    @Test
    public void testPostAndGet() throws ExternalPdpException {
        try (AuthZenHttpClient client = client(1024)) {
            assertEquals(client.postJson(server.baseUrl() + "/ok", "{\"a\":1}", Map.of("X-Request-ID", "r1")),
                    "{\"echo\":{\"a\":1}}");
            Map<String, String> headers = server.lastHeaders.get("/ok");
            assertEquals(headers.get("x-request-id"), "r1");
            assertTrue(headers.get("content-type").startsWith("application/json"));
            assertEquals(headers.get("accept"), "application/json");

            assertEquals(client.getJson(server.baseUrl() + "/ok", Collections.emptyMap()), "{\"echo\":null}");
        }
    }

    @Test
    public void testErrorStatus() {
        try (AuthZenHttpClient client = client(1024)) {
            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> client.postJson(server.baseUrl() + "/unavailable", "{}", Collections.emptyMap()));
            assertEquals(ex.getCode(), ExternalPdpException.Code.UNAVAILABLE);
            ex = expectThrows(ExternalPdpException.class,
                    () -> client.postJson(server.baseUrl() + "/throttled", "{}", Collections.emptyMap()));
            assertEquals(ex.getCode(), ExternalPdpException.Code.UNAVAILABLE);
            ex = expectThrows(ExternalPdpException.class,
                    () -> client.postJson(server.baseUrl() + "/bad", "{}", Collections.emptyMap()));
            assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
            ex = expectThrows(ExternalPdpException.class,
                    () -> client.postJson(server.baseUrl() + "/empty", "{}", Collections.emptyMap()));
            assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
        }
    }

    @Test
    public void testResponseTooLarge() {
        try (AuthZenHttpClient client = client(1024)) {
            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> client.postJson(server.baseUrl() + "/large", "{}", Collections.emptyMap()));
            assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
        }
    }

    @Test
    public void testStreamingResponseTooLargeAbortsExchange() throws Exception {
        CountDownLatch clientGone = new CountDownLatch(1);
        server.handleStream("/stream", "x".repeat(512).getBytes(StandardCharsets.UTF_8), 50, 20000, clientGone);
        try (AuthZenHttpClient client = client(1024)) {
            long start = System.currentTimeMillis();
            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> client.postJson(server.baseUrl() + "/stream", "{}", Collections.emptyMap()));
            assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
            assertTrue(System.currentTimeMillis() - start < 5000);
            assertTrue(clientGone.await(5, TimeUnit.SECONDS));
        }
    }

    @Test
    public void testTimeout() {
        try (AuthZenHttpClient client = client(1024)) {
            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> client.postJson(server.baseUrl() + "/slow", "{}", Collections.emptyMap()));
            assertEquals(ex.getCode(), ExternalPdpException.Code.TIMEOUT);
        }
    }

    @Test
    public void testHostnameVerification() {
        // the certificate is only valid for localhost so connecting via the ip must fail
        try (AuthZenHttpClient client = client(1024)) {
            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> client.postJson("https://127.0.0.1:" + server.port() + "/ok", "{}", Collections.emptyMap()));
            assertEquals(ex.getCode(), ExternalPdpException.Code.UNAVAILABLE);
        }
    }

    @Test
    public void testUntrustedServer() {
        try (AuthZenHttpClient client = new AuthZenHttpClient(null, 1000, 1000, 2, 1024)) {
            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> client.postJson(server.baseUrl() + "/ok", "{}", Collections.emptyMap()));
            assertEquals(ex.getCode(), ExternalPdpException.Code.UNAVAILABLE);
        }
    }

    @Test
    public void testNoEntityAndCloseFailure() throws ExternalPdpException {
        CloseableHttpClient httpClient = new CloseableHttpClient() {
            @Override
            protected org.apache.hc.client5.http.impl.classic.CloseableHttpResponse doExecute(HttpHost target,
                    ClassicHttpRequest request, HttpContext context) {
                throw new UnsupportedOperationException();
            }

            @Override
            public <T> T execute(ClassicHttpRequest request, HttpClientResponseHandler<? extends T> handler)
                    throws IOException {
                try {
                    return handler.handleResponse(new BasicClassicHttpResponse(200));
                } catch (org.apache.hc.core5.http.HttpException ex) {
                    throw new IOException(ex);
                }
            }

            @Override
            public void close(org.apache.hc.core5.io.CloseMode closeMode) {
            }

            @Override
            public void close() throws IOException {
                throw new IOException("close failed");
            }
        };
        AuthZenHttpClient client = new AuthZenHttpClient(httpClient, 1024);
        assertEquals(client.getJson("https://localhost/none", Collections.emptyMap()), "");
        client.close();
    }
}
