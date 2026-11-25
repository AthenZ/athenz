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

package com.yahoo.athenz.common.server.pdp;

import com.yahoo.athenz.common.server.pdp.authzen.*;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import static org.testng.Assert.*;

public class ExternalPdpSupportTest {

    static final class RecordingPdp implements ExternalPolicyDecisionPoint {
        final List<EvaluationRequest> requests = Collections.synchronizedList(new ArrayList<>());

        @Override
        public void initialize(ExternalPdpContext context) {
        }

        @Override
        public EvaluationResponse evaluate(EvaluationRequest request) throws ExternalPdpException {
            requests.add(request);
            final String id = request.getResource().getId();
            if ("fail".equals(id)) {
                throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE, "down");
            }
            if ("boom".equals(id)) {
                throw new IllegalStateException("boom");
            }
            return new EvaluationResponse(id.startsWith("permit"), null);
        }
    }

    private static EvaluationsRequest batch(String semantic, String... ids) {
        List<EvaluationRequest> items = new ArrayList<>();
        for (String id : ids) {
            items.add(new EvaluationRequest(null, null, new Resource("athenz_role", id, null), null));
        }
        return new EvaluationsRequest(new Subject("user", "user.joe", null), new Action("assume_role", null),
                null, Map.of("request_id", "r1"), items, semantic == null ? null : new EvaluationsOptions(semantic));
    }

    @Test
    public void testApplyDefaults() {
        EvaluationsRequest request = batch(null, "permit1");
        EvaluationRequest item = new EvaluationRequest(new Subject("service", "sports.api", null),
                new Action("issue_token", null), new Resource("athenz_token", "sports", null), Map.of("k", "v"));
        EvaluationRequest merged = ExternalPdpSupport.applyDefaults(request, item);
        assertEquals(merged.getSubject().getId(), "sports.api");
        assertEquals(merged.getAction().getName(), "issue_token");
        assertEquals(merged.getContext().get("k"), "v");

        merged = ExternalPdpSupport.applyDefaults(request, request.getEvaluations().get(0));
        assertEquals(merged.getSubject().getId(), "user.joe");
        assertEquals(merged.getAction().getName(), "assume_role");
        assertEquals(merged.getResource().getId(), "permit1");
        assertEquals(merged.getContext().get("request_id"), "r1");
    }

    @Test
    public void testDefaultInterfaceMethods() throws ExternalPdpException {
        ExternalPolicyDecisionPoint pdp = context -> { };
        pdp.initialize(null);
        ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                () -> pdp.evaluate(batch(null, "permit1").getEvaluations().get(0)));
        assertEquals(ex.getCode(), ExternalPdpException.Code.UNSUPPORTED);
        ex = expectThrows(ExternalPdpException.class, () -> pdp.evaluations(batch(null, "permit1")));
        assertEquals(ex.getCode(), ExternalPdpException.Code.UNSUPPORTED);
        pdp.close();
    }

    @Test
    public void testSequentialExecuteAll() throws ExternalPdpException {
        RecordingPdp pdp = new RecordingPdp();
        EvaluationsResponse response = pdp.evaluations(batch(EvaluationsOptions.EXECUTE_ALL, "permit1", "deny1", "permit2"));
        assertEquals(response.getEvaluations().size(), 3);
        assertTrue(response.getEvaluations().get(0).getDecision());
        assertFalse(response.getEvaluations().get(1).getDecision());
        assertTrue(response.getEvaluations().get(2).getDecision());
        assertEquals(pdp.requests.get(1).getSubject().getId(), "user.joe");
    }

    @Test
    public void testSequentialShortCircuit() throws ExternalPdpException {
        RecordingPdp pdp = new RecordingPdp();
        EvaluationsResponse response = ExternalPdpSupport.expandBatch(pdp,
                batch(EvaluationsOptions.DENY_ON_FIRST_DENY, "permit1", "deny1", "permit2"), null);
        assertEquals(response.getEvaluations().size(), 2);

        response = ExternalPdpSupport.expandBatch(pdp,
                batch(EvaluationsOptions.PERMIT_ON_FIRST_PERMIT, "deny1", "permit1", "deny2"), null);
        assertEquals(response.getEvaluations().size(), 2);

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            response = ExternalPdpSupport.expandBatch(pdp,
                    batch(EvaluationsOptions.DENY_ON_FIRST_DENY, "deny1", "permit1"), executor);
            assertEquals(response.getEvaluations().size(), 1);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void testEmptyBatch() throws ExternalPdpException {
        EvaluationsRequest request = new EvaluationsRequest(null, null, null, null, null, null);
        assertTrue(ExternalPdpSupport.expandBatch(new RecordingPdp(), request, null).getEvaluations().isEmpty());
    }

    @Test
    public void testParallel() throws ExternalPdpException {
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            RecordingPdp pdp = new RecordingPdp();
            EvaluationsResponse response = ExternalPdpSupport.expandBatch(pdp,
                    batch(null, "permit1", "deny1", "permit2", "deny2"), executor);
            assertEquals(response.getEvaluations().size(), 4);
            assertTrue(response.getEvaluations().get(0).getDecision());
            assertFalse(response.getEvaluations().get(1).getDecision());
            assertTrue(response.getEvaluations().get(2).getDecision());
            assertFalse(response.getEvaluations().get(3).getDecision());

            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> ExternalPdpSupport.expandBatch(pdp, batch(null, "permit1", "fail"), executor));
            assertEquals(ex.getCode(), ExternalPdpException.Code.UNAVAILABLE);

            ex = expectThrows(ExternalPdpException.class,
                    () -> ExternalPdpSupport.expandBatch(pdp, batch(null, "boom"), executor));
            assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void testParallelRejected() {
        ExecutorService executor = Executors.newFixedThreadPool(1);
        executor.shutdown();
        ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                () -> ExternalPdpSupport.expandBatch(new RecordingPdp(), batch(null, "permit1"), executor));
        assertEquals(ex.getCode(), ExternalPdpException.Code.UNAVAILABLE);
    }

    @Test
    public void testParallelBatchLargerThanExecutorCapacity() throws ExternalPdpException {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(1));
        ExternalPolicyDecisionPoint slowPdp = new ExternalPolicyDecisionPoint() {
            @Override
            public void initialize(ExternalPdpContext context) {
            }

            @Override
            public EvaluationResponse evaluate(EvaluationRequest request) throws ExternalPdpException {
                try {
                    Thread.sleep(20);
                } catch (InterruptedException ex) {
                    throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "interrupted");
                }
                return new EvaluationResponse(request.getResource().getId().startsWith("permit"), null);
            }
        };
        try {
            EvaluationsResponse response = ExternalPdpSupport.expandBatch(slowPdp,
                    batch(null, "permit1", "deny1", "permit2", "deny2", "permit3", "deny3"), executor);
            assertEquals(response.getEvaluations().size(), 6);
            for (int i = 0; i < 6; i++) {
                assertEquals(response.getEvaluations().get(i).getDecision(), i % 2 == 0);
            }
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void testParallelSaturatedByOtherTasks() {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(1));
        CountDownLatch release = new CountDownLatch(1);
        Runnable blocker = () -> {
            try {
                release.await();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        };
        executor.execute(blocker);
        executor.execute(blocker);
        try {
            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> ExternalPdpSupport.expandBatch(new RecordingPdp(), batch(null, "permit1"), executor));
            assertEquals(ex.getCode(), ExternalPdpException.Code.UNAVAILABLE);
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    public void testParallelInterrupted() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(1);
        CountDownLatch release = new CountDownLatch(1);
        ExternalPolicyDecisionPoint slowPdp = new ExternalPolicyDecisionPoint() {
            @Override
            public void initialize(ExternalPdpContext context) {
            }

            @Override
            public EvaluationResponse evaluate(EvaluationRequest request) throws ExternalPdpException {
                try {
                    release.await();
                } catch (InterruptedException ex) {
                    throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "interrupted");
                }
                return new EvaluationResponse(true, null);
            }
        };
        ExecutorService caller = Executors.newSingleThreadExecutor();
        try {
            Future<ExternalPdpException.Code> result = caller.submit(() -> {
                try {
                    ExternalPdpSupport.expandBatch(slowPdp, batch(null, "permit1"), executor);
                    return null;
                } catch (ExternalPdpException ex) {
                    return Thread.currentThread().isInterrupted() ? ex.getCode() : null;
                }
            });
            Thread.sleep(200);
            caller.shutdownNow();
            assertEquals(result.get(5, TimeUnit.SECONDS), ExternalPdpException.Code.TIMEOUT);
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    public void testRequireMtlsOrLoopback() throws Exception {
        for (String endpoint : new String[] { "https://localhost:8443", "https://LOCALHOST/pdp", "https://127.0.0.1:8443",
                "https://127.1.2.3", "https://[::1]:8443", "https://[::ffff:127.0.0.1]", "grpc://localhost:9000" }) {
            ExternalPdpSupport.requireMtlsOrLoopback(new URI(endpoint), null);
        }
        for (String endpoint : new String[] { "https://pdp.example.com", "https://10.0.0.1:8443", "https://[2001:db8::1]",
                "https://localhost.example.com", "https://127.example.com", "grpc://pdp.example.com:9000",
                "https:///no-host" }) {
            ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                    () -> ExternalPdpSupport.requireMtlsOrLoopback(new URI(endpoint), null));
            assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);
        }
        ExternalPdpSupport.requireMtlsOrLoopback(new URI("https://pdp.example.com"), SSLContext.getDefault());
        ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                () -> ExternalPdpSupport.requireMtlsOrLoopback(new URI("https:///no-host"), SSLContext.getDefault()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);

        assertFalse(ExternalPdpSupport.isLoopbackHost("[zz::1]"));
        assertFalse(ExternalPdpSupport.isLoopbackHost("127.0.0.256"));
    }

    @Test
    public void testIsShortCircuit() {
        assertFalse(ExternalPdpSupport.isShortCircuit(null, false));
        assertFalse(ExternalPdpSupport.isShortCircuit(EvaluationsOptions.EXECUTE_ALL, true));
        assertTrue(ExternalPdpSupport.isShortCircuit(EvaluationsOptions.DENY_ON_FIRST_DENY, false));
        assertFalse(ExternalPdpSupport.isShortCircuit(EvaluationsOptions.DENY_ON_FIRST_DENY, true));
        assertTrue(ExternalPdpSupport.isShortCircuit(EvaluationsOptions.PERMIT_ON_FIRST_PERMIT, true));
        assertFalse(ExternalPdpSupport.isShortCircuit(EvaluationsOptions.PERMIT_ON_FIRST_PERMIT, false));
    }
}
