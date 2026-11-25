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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.pdp.ExternalPdpContext;
import com.yahoo.athenz.common.server.pdp.ExternalPdpException;
import com.yahoo.athenz.common.server.pdp.authzen.*;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.net.URI;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.*;

public class AuthZenHttpPdpTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String[] PROPS = {
        AuthZenHttpPdp.PROP_BATCH_ENABLED, AuthZenHttpPdp.PROP_EVALUATIONS_PATH, AuthZenHttpPdp.PROP_EVALUATION_PATH,
        AuthZenHttpPdp.PROP_DISCOVERY,
        AuthZenHttpPdp.PROP_MAX_RESPONSE_BYTES, AuthZenHttpPdp.PROP_AUTH_HEADER_NAME,
        AuthZenHttpPdp.PROP_AUTH_HEADER_PREFIX, AuthZenHttpPdp.PROP_AUTH_SECRET_APP_NAME,
        AuthZenHttpPdp.PROP_AUTH_SECRET_KEYGROUP_NAME, AuthZenHttpPdp.PROP_AUTH_SECRET_KEY_NAME,
        AuthZenHttpPdp.PROP_AUTH_SECRET_REFRESH_SECS
    };

    private TestHttpsServer server;
    private ExecutorService executor;
    private final AtomicReference<String> discoveryDoc = new AtomicReference<>("{}");

    @BeforeClass
    public void setup() throws Exception {
        server = new TestHttpsServer();
        executor = Executors.newFixedThreadPool(4);
        server.handle("/pdp/access/v1/evaluations", body -> new TestHttpsServer.Reply(200,
                "{\"evaluations\":[{\"decision\":true,\"context\":{\"claims\":{\"tier\":\"gold\"}}},{\"decision\":false}]}"));
        server.handle("/pdp/access/v1/evaluation", body -> new TestHttpsServer.Reply(200,
                body.contains("permit") ? "{\"decision\":true}" : "{\"decision\":false}"));
        server.handle("/pdp/custom/eval", body -> new TestHttpsServer.Reply(200, "{\"decision\":true}"));
        server.handle("/pdp/bad-json", body -> new TestHttpsServer.Reply(200, "not-json"));
        server.handle("/pdp/null-json", body -> new TestHttpsServer.Reply(200, "null"));
        server.handle("/.well-known/authzen-configuration/pdp", body -> new TestHttpsServer.Reply(200, discoveryDoc.get()));
    }

    @AfterClass
    public void shutdown() {
        server.close();
        executor.shutdownNow();
    }

    @AfterMethod
    public void clearProperties() {
        for (String prop : PROPS) {
            System.clearProperty(prop);
        }
    }

    private ExternalPdpContext context(String endpoint, PrivateKeyStore keyStore) {
        return new ExternalPdpContext.Builder().endpoint(endpoint).sslContext(server.clientSslContext())
                .privateKeyStore(keyStore).executor(executor).connectTimeoutMs(1000).readTimeoutMs(1000)
                .maxConnections(4).build();
    }

    private AuthZenHttpPdp pdp(PrivateKeyStore keyStore) throws ExternalPdpException {
        AuthZenHttpPdp pdp = new AuthZenHttpPdp();
        pdp.initialize(context(server.baseUrl() + "/pdp/", keyStore));
        return pdp;
    }

    private static EvaluationsRequest batch(String... ids) {
        List<EvaluationRequest> items = new ArrayList<>();
        for (String id : ids) {
            items.add(new EvaluationRequest(null, null, new Resource("athenz_role", id, null), null));
        }
        return new EvaluationsRequest(new Subject("service", "sports.api", null), new Action("assume_role", null),
                null, Map.of("request_id", "req-123"), items, new EvaluationsOptions(EvaluationsOptions.EXECUTE_ALL));
    }

    @Test
    public void testParseEndpoint() {
        for (String endpoint : new String[] { null, "https://bad host", "http://localhost", "https:///path", "class://x" }) {
            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> AuthZenHttpPdp.parseEndpoint(endpoint));
            assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);
        }
    }

    @Test
    public void testDefaults() throws ExternalPdpException {
        AuthZenHttpPdp pdp = pdp(null);
        assertTrue(pdp.isBatchEnabled());
        assertEquals(pdp.getEvaluationsUrl(), server.baseUrl() + "/pdp/access/v1/evaluations");
        assertEquals(pdp.getEvaluationUrl(), server.baseUrl() + "/pdp/access/v1/evaluation");
        pdp.close();
    }

    @Test
    public void testBatchEvaluations() throws Exception {
        AuthZenHttpPdp pdp = pdp(null);
        EvaluationsResponse response = pdp.evaluations(batch("sports:role.readers", "sports:role.writers"));
        assertEquals(response.getEvaluations().size(), 2);
        assertTrue(response.getEvaluations().get(0).getDecision());
        assertEquals(((Map<?, ?>) response.getEvaluations().get(0).getContext().get("claims")).get("tier"), "gold");
        assertFalse(response.getEvaluations().get(1).getDecision());

        Map<?, ?> sent = MAPPER.readValue(server.lastBodies.get("/pdp/access/v1/evaluations"), Map.class);
        assertEquals(((Map<?, ?>) sent.get("subject")).get("id"), "sports.api");
        assertEquals(((List<?>) sent.get("evaluations")).size(), 2);
        assertEquals(server.lastHeaders.get("/pdp/access/v1/evaluations").get("x-request-id"), "req-123");
        pdp.close();
    }

    @Test
    public void testSingleEvaluationFanOut() throws ExternalPdpException {
        System.setProperty(AuthZenHttpPdp.PROP_BATCH_ENABLED, "false");
        AuthZenHttpPdp pdp = pdp(null);
        assertFalse(pdp.isBatchEnabled());
        EvaluationsResponse response = pdp.evaluations(batch("permit-role", "deny-role", "permit-other"));
        assertTrue(response.getEvaluations().get(0).getDecision());
        assertFalse(response.getEvaluations().get(1).getDecision());
        assertTrue(response.getEvaluations().get(2).getDecision());

        EvaluationResponse single = pdp.evaluate(new EvaluationRequest(new Subject("user", "user.joe", null),
                new Action("assume_role", null), new Resource("athenz_role", "deny", null), null));
        assertFalse(single.getDecision());
        assertNotNull(server.lastHeaders.get("/pdp/access/v1/evaluation").get("x-request-id"));
        pdp.close();
    }

    @Test
    public void testPathOverride() throws ExternalPdpException {
        System.setProperty(AuthZenHttpPdp.PROP_EVALUATION_PATH, "/custom/eval");
        AuthZenHttpPdp pdp = pdp(null);
        assertEquals(pdp.getEvaluationUrl(), server.baseUrl() + "/pdp/custom/eval");
        assertTrue(pdp.evaluate(batch("x").getEvaluations().get(0)).getDecision());
    }

    @Test
    public void testInvalidResponses() throws ExternalPdpException {
        System.setProperty(AuthZenHttpPdp.PROP_EVALUATION_PATH, "/bad-json");
        System.setProperty(AuthZenHttpPdp.PROP_EVALUATIONS_PATH, "/null-json");
        AuthZenHttpPdp pdp = pdp(null);
        ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                () -> pdp.evaluate(batch("x").getEvaluations().get(0)));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
        ex = expectThrows(ExternalPdpException.class, () -> pdp.evaluations(batch("x")));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);

        ex = expectThrows(ExternalPdpException.class,
                () -> pdp.post(pdp.getEvaluationUrl(), new Object(), null, Map.class));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);
    }

    @Test
    public void testResponseSizeLimit() throws ExternalPdpException {
        System.setProperty(AuthZenHttpPdp.PROP_MAX_RESPONSE_BYTES, "10");
        AuthZenHttpPdp pdp = pdp(null);
        ExternalPdpException ex = expectThrows(ExternalPdpException.class, () -> pdp.evaluations(batch("x")));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
    }

    @Test
    public void testDiscovery() throws ExternalPdpException {
        System.setProperty(AuthZenHttpPdp.PROP_DISCOVERY, "true");
        final String base = server.baseUrl() + "/pdp";
        discoveryDoc.set("{\"policy_decision_point\":\"" + base + "\",\"access_evaluation_endpoint\":\""
                + base + "/custom/eval\"}");
        AuthZenHttpPdp pdp = pdp(null);
        assertFalse(pdp.isBatchEnabled());
        assertEquals(pdp.getEvaluationUrl(), base + "/custom/eval");
        assertEquals(pdp.getEvaluationsUrl(), base + "/access/v1/evaluations");

        // explicit properties override discovered values
        System.setProperty(AuthZenHttpPdp.PROP_BATCH_ENABLED, "true");
        System.setProperty(AuthZenHttpPdp.PROP_EVALUATION_PATH, "/access/v1/evaluation");
        pdp = pdp(null);
        assertTrue(pdp.isBatchEnabled());
        assertEquals(pdp.getEvaluationUrl(), base + "/access/v1/evaluation");
    }

    @Test
    public void testDiscoveryPolicyDecisionPoint() throws ExternalPdpException {
        System.setProperty(AuthZenHttpPdp.PROP_DISCOVERY, "true");
        final String base = server.baseUrl() + "/pdp";

        // a trailing slash on the identifier is accepted
        discoveryDoc.set("{\"policy_decision_point\":\"" + base + "/\"}");
        assertNotNull(pdp(null));

        for (String doc : new String[] { "{}", "{\"policy_decision_point\":\"" + server.baseUrl() + "\"}",
                "{\"policy_decision_point\":\"" + base + "/tenant1\"}" }) {
            discoveryDoc.set(doc);
            ExternalPdpException ex = expectThrows(ExternalPdpException.class, () -> pdp(null));
            assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
        }
    }

    @Test
    public void testTransportRequiresMtlsOrLoopback() {
        // initialization fails before any connection is made
        AuthZenHttpPdp pdp = new AuthZenHttpPdp();
        ExternalPdpException ex = expectThrows(ExternalPdpException.class, () -> pdp.initialize(
                new ExternalPdpContext.Builder().endpoint("https://pdp.example.com").executor(executor).build()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);
    }

    @Test
    public void testDiscoveryUrl() throws Exception {
        assertEquals(AuthZenHttpPdp.discoveryUrl(new URI("https://pdp.example.com")),
                "https://pdp.example.com/.well-known/authzen-configuration");
        assertEquals(AuthZenHttpPdp.discoveryUrl(new URI("https://pdp.example.com/")),
                "https://pdp.example.com/.well-known/authzen-configuration");
        assertEquals(AuthZenHttpPdp.discoveryUrl(new URI("https://pdp.example.com:8443/tenant1/")),
                "https://pdp.example.com:8443/.well-known/authzen-configuration/tenant1");
        assertEquals(AuthZenHttpPdp.discoveryUrl(new URI("https://pdp.example.com/a/b")),
                "https://pdp.example.com/.well-known/authzen-configuration/a/b");
    }

    @Test
    public void testDiscoveryRejectsForeignOrigin() {
        System.setProperty(AuthZenHttpPdp.PROP_DISCOVERY, "true");
        for (String url : new String[] { "https://evil.example.com/eval", "http://localhost:" + server.port() + "/eval",
                "https://localhost:1/eval", "https://bad host/eval" }) {
            discoveryDoc.set("{\"policy_decision_point\":\"" + server.baseUrl() + "/pdp\","
                    + "\"access_evaluations_endpoint\":\"" + url + "\"}");
            ExternalPdpException ex = expectThrows(ExternalPdpException.class, () -> pdp(null));
            assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
        }
    }

    @Test
    public void testVerifySameOrigin() throws Exception {
        AuthZenHttpPdp.verifySameOrigin(new URI("https://pdp.athenz.io:4443/base"), "https://PDP.athenz.io:4443/x");
        AuthZenHttpPdp.verifySameOrigin(new URI("https://pdp.athenz.io:443"), "https://pdp.athenz.io/access/v1/evaluation");
        AuthZenHttpPdp.verifySameOrigin(new URI("https://pdp.athenz.io"), "https://pdp.athenz.io:443/access/v1/evaluation");
        ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                () -> AuthZenHttpPdp.verifySameOrigin(new URI("https://pdp.athenz.io"), "https://pdp.athenz.io:4443/x"));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
    }

    static final class FakeKeyStore implements PrivateKeyStore {
        final AtomicReference<String> secret = new AtomicReference<>();
        final List<String> lookups = new ArrayList<>();
        volatile boolean failing;
        volatile java.util.concurrent.CountDownLatch entered;
        volatile java.util.concurrent.CountDownLatch release;

        @Override
        public char[] getSecret(String appName, String keygroupName, String keyName) {
            lookups.add(appName + "/" + keygroupName + "/" + keyName);
            if (failing) {
                throw new IllegalStateException("secret backend unavailable");
            }
            if (release != null) {
                entered.countDown();
                try {
                    release.await(5, java.util.concurrent.TimeUnit.SECONDS);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            }
            String value = secret.get();
            return value == null ? null : value.toCharArray();
        }
    }

    private static void setAuthProps() {
        System.setProperty(AuthZenHttpPdp.PROP_AUTH_HEADER_NAME, "Authorization");
        System.setProperty(AuthZenHttpPdp.PROP_AUTH_HEADER_PREFIX, "Bearer ");
        System.setProperty(AuthZenHttpPdp.PROP_AUTH_SECRET_APP_NAME, "zts");
        System.setProperty(AuthZenHttpPdp.PROP_AUTH_SECRET_KEYGROUP_NAME, "pdp");
        System.setProperty(AuthZenHttpPdp.PROP_AUTH_SECRET_KEY_NAME, "token");
    }

    @Test
    public void testAuthHeader() throws ExternalPdpException {
        setAuthProps();
        FakeKeyStore keyStore = new FakeKeyStore();
        keyStore.secret.set("secret-1");
        AuthZenHttpPdp pdp = pdp(keyStore);
        assertEquals(keyStore.lookups.get(0), "zts/pdp/token");

        pdp.evaluations(batch("x"));
        assertEquals(server.lastHeaders.get("/pdp/access/v1/evaluations").get("authorization"), "Bearer secret-1");

        // rotation is picked up once the refresh interval passes
        final long start = System.currentTimeMillis();
        pdp.clock = () -> start + 3600 * 1000L + 1;
        keyStore.secret.set("secret-2");
        pdp.evaluations(batch("x"));
        assertEquals(server.lastHeaders.get("/pdp/access/v1/evaluations").get("authorization"), "Bearer secret-2");

        // failure to refresh keeps the previous value
        pdp.clock = () -> start + 3 * 3600 * 1000L;
        keyStore.secret.set("");
        pdp.evaluations(batch("x"));
        assertEquals(server.lastHeaders.get("/pdp/access/v1/evaluations").get("authorization"), "Bearer secret-2");

        // a store exception keeps the previous value and is not retried until the next interval
        pdp.clock = () -> start + 5 * 3600 * 1000L;
        keyStore.failing = true;
        pdp.evaluations(batch("x"));
        assertEquals(server.lastHeaders.get("/pdp/access/v1/evaluations").get("authorization"), "Bearer secret-2");
        final int lookups = keyStore.lookups.size();
        pdp.evaluations(batch("x"));
        assertEquals(keyStore.lookups.size(), lookups);
        assertEquals(server.lastHeaders.get("/pdp/access/v1/evaluations").get("authorization"), "Bearer secret-2");
    }

    @Test
    public void testAuthHeaderSingleRefresh() throws Exception {
        setAuthProps();
        FakeKeyStore keyStore = new FakeKeyStore();
        keyStore.secret.set("secret-1");
        AuthZenHttpPdp pdp = pdp(keyStore);

        final long start = System.currentTimeMillis();
        pdp.clock = () -> start + 3600 * 1000L + 1;
        keyStore.secret.set("secret-2");
        keyStore.entered = new java.util.concurrent.CountDownLatch(1);
        keyStore.release = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.Future<String> refresher = executor.submit(pdp::currentAuthHeaderValue);
        assertTrue(keyStore.entered.await(5, java.util.concurrent.TimeUnit.SECONDS));

        // while one caller refreshes, others get the current value without a lookup
        final int lookups = keyStore.lookups.size();
        assertEquals(pdp.currentAuthHeaderValue(), "Bearer secret-1");
        assertEquals(keyStore.lookups.size(), lookups);

        keyStore.release.countDown();
        assertEquals(refresher.get(5, java.util.concurrent.TimeUnit.SECONDS), "Bearer secret-2");
        assertEquals(pdp.currentAuthHeaderValue(), "Bearer secret-2");
        assertEquals(keyStore.lookups.size(), lookups);
    }

    @Test
    public void testAuthHeaderInitialStoreFailure() {
        setAuthProps();
        FakeKeyStore keyStore = new FakeKeyStore();
        keyStore.failing = true;
        expectThrows(IllegalStateException.class, () -> pdp(keyStore));
    }

    @Test
    public void testAuthHeaderFailures() {
        setAuthProps();
        ExternalPdpException ex = expectThrows(ExternalPdpException.class, () -> pdp(null));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);

        ex = expectThrows(ExternalPdpException.class, () -> pdp(new FakeKeyStore()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);

        System.setProperty(AuthZenHttpPdp.PROP_AUTH_HEADER_NAME, "");
        try {
            assertNotNull(pdp(null));
        } catch (ExternalPdpException unexpected) {
            fail();
        }
    }

    @Test
    public void testRequestHeaders() throws ExternalPdpException {
        AuthZenHttpPdp pdp = pdp(null);
        assertNotNull(pdp.requestHeaders(null).get(AuthZenHttpPdp.HDR_REQUEST_ID));
        assertNotEquals(pdp.requestHeaders(Map.of("request_id", 12)).get(AuthZenHttpPdp.HDR_REQUEST_ID), "12");
        assertEquals(pdp.requestHeaders(Collections.emptyMap()).size(), 1);
    }

    @Test
    public void testCloseUninitialized() {
        new AuthZenHttpPdp().close();
    }

    @Test
    public void testStripTrailingSlash() {
        assertEquals(AuthZenHttpPdp.stripTrailingSlash("https://a/"), "https://a");
        assertEquals(AuthZenHttpPdp.stripTrailingSlash("https://a"), "https://a");
    }
}
