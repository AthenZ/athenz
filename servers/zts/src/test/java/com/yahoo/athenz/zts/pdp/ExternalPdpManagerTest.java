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

package com.yahoo.athenz.zts.pdp;

import com.yahoo.athenz.common.server.pdp.ExternalPdpContext;
import com.yahoo.athenz.common.server.pdp.ExternalPdpException;
import com.yahoo.athenz.common.server.pdp.ExternalPolicyDecisionPoint;
import com.yahoo.athenz.common.server.pdp.authzen.*;
import com.yahoo.athenz.common.server.pdp.impl.AuthZenHttpPdp;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.*;

public class ExternalPdpManagerTest {

    public static class SingleEvaluationPdp implements ExternalPolicyDecisionPoint {
        ExternalPdpContext context;

        @Override
        public void initialize(ExternalPdpContext context) {
            this.context = context;
        }

        @Override
        public EvaluationResponse evaluate(EvaluationRequest request) {
            return new EvaluationResponse(true, null);
        }
    }

    public static class BatchPdp implements ExternalPolicyDecisionPoint {
        @Override
        public void initialize(ExternalPdpContext context) {
        }

        @Override
        public EvaluationsResponse evaluations(EvaluationsRequest request) {
            return new EvaluationsResponse(List.of());
        }
    }

    public static class NoDecisionPdp implements ExternalPolicyDecisionPoint {
        @Override
        public void initialize(ExternalPdpContext context) {
        }
    }

    public static class NotAPdp {
    }

    static final class ScriptedPdp implements ExternalPolicyDecisionPoint {
        final AtomicReference<Object> result = new AtomicReference<>();
        volatile long delayMs;
        volatile boolean closed;
        CountDownLatch release;

        @Override
        public void initialize(ExternalPdpContext context) {
        }

        @Override
        public EvaluationsResponse evaluations(EvaluationsRequest request) throws ExternalPdpException {
            if (release != null) {
                try {
                    release.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
            if (delayMs > 0) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException ex) {
                    throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "interrupted");
                }
            }
            Object value = result.get();
            if (value instanceof ExternalPdpException) {
                throw (ExternalPdpException) value;
            }
            if (value instanceof RuntimeException) {
                throw (RuntimeException) value;
            }
            return (EvaluationsResponse) value;
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    @AfterMethod
    public void cleanup() {
        ExternalPdpConfigTest.clearProperties();
    }

    private static ExternalPdpConfig config(String timeoutMs, String concurrency) {
        System.setProperty(ExternalPdpConfig.PROP_MODE, "FILTER");
        System.setProperty(ExternalPdpConfig.PROP_ENDPOINT, "class://test");
        System.setProperty(ExternalPdpConfig.PROP_TIMEOUT_MS, timeoutMs);
        System.setProperty(ExternalPdpConfig.PROP_MAX_CONCURRENCY, concurrency);
        System.setProperty(ExternalPdpConfig.PROP_AUDIT_QUEUE_SIZE, "1");
        return ExternalPdpConfig.fromSystemProperties();
    }

    private static EvaluationsRequest request(int items) {
        List<EvaluationRequest> evaluations = new ArrayList<>();
        for (int i = 0; i < items; i++) {
            evaluations.add(new EvaluationRequest(null, null, new Resource("athenz_role", "d:role.r" + i, null), null));
        }
        return new EvaluationsRequest(new Subject("user", "user.joe", null), null, null, null, evaluations, null);
    }

    private static EvaluationsResponse response(int items) {
        List<EvaluationResponse> results = new ArrayList<>();
        for (int i = 0; i < items; i++) {
            results.add(new EvaluationResponse(true, null));
        }
        return new EvaluationsResponse(results);
    }

    @Test
    public void testLoadPdp() {
        assertTrue(ExternalPdpManager.loadPdp("https://pdp.athenz.io") instanceof AuthZenHttpPdp);
        assertTrue(ExternalPdpManager.loadPdp("HTTPS://pdp.athenz.io") instanceof AuthZenHttpPdp);
        assertTrue(ExternalPdpManager.loadPdp("class://" + SingleEvaluationPdp.class.getName())
                instanceof SingleEvaluationPdp);
        assertTrue(ExternalPdpManager.loadPdp("class://" + BatchPdp.class.getName()) instanceof BatchPdp);
        assertThrows(IllegalArgumentException.class, () -> ExternalPdpManager.loadPdp("http://pdp.athenz.io"));
        assertThrows(IllegalArgumentException.class, () -> ExternalPdpManager.loadPdp("class://com.unknown.Pdp"));
        assertThrows(IllegalArgumentException.class,
                () -> ExternalPdpManager.loadPdp("class://" + NotAPdp.class.getName()));
        assertThrows(IllegalArgumentException.class,
                () -> ExternalPdpManager.loadPdp("class://" + NoDecisionPdp.class.getName()));
        assertFalse(ExternalPdpManager.declaresDecisionMethod(Object.class));
    }

    @Test
    public void testInitializeContext() throws ExternalPdpException {
        SingleEvaluationPdp pdp = new SingleEvaluationPdp();
        ExternalPdpManager manager = new ExternalPdpManager(config("300", "4"), pdp, new ExternalPdpContext.Builder());
        assertEquals(pdp.context.getEndpoint(), "class://test");
        assertNotNull(pdp.context.getExecutor());
        assertEquals(pdp.context.getConnectTimeoutMs(), 300);
        assertEquals(pdp.context.getReadTimeoutMs(), 300);
        assertEquals(pdp.context.getMaxConnections(), 4);
        assertSame(manager.getPdp(), pdp);

        // the default batch implementation expands to single evaluations
        EvaluationsResponse response = manager.evaluations(request(2), manager.newDeadline());
        assertEquals(response.getEvaluations().size(), 2);
        manager.close();
    }

    @Test
    public void testInitializeFailure() {
        ExternalPolicyDecisionPoint failing = new ExternalPolicyDecisionPoint() {
            @Override
            public void initialize(ExternalPdpContext context) throws ExternalPdpException {
                throw new ExternalPdpException(ExternalPdpException.Code.INTERNAL, "bad config");
            }

            @Override
            public EvaluationsResponse evaluations(EvaluationsRequest request) {
                return null;
            }
        };
        assertThrows(ExternalPdpException.class,
                () -> new ExternalPdpManager(config("300", "4"), failing, new ExternalPdpContext.Builder()));
    }

    @Test
    public void testEvaluations() throws ExternalPdpException {
        ScriptedPdp pdp = new ScriptedPdp();
        ExternalPdpManager manager = new ExternalPdpManager(config("1000", "2"), pdp, new ExternalPdpContext.Builder());

        pdp.result.set(response(2));
        assertEquals(manager.evaluations(request(2), manager.newDeadline()).getEvaluations().size(), 2);

        pdp.result.set(response(1));
        ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                () -> manager.evaluations(request(2), manager.newDeadline()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);

        pdp.result.set(new EvaluationsResponse(java.util.Arrays.asList(
                new com.yahoo.athenz.common.server.pdp.authzen.EvaluationResponse(true, null), null)));
        ex = expectThrows(ExternalPdpException.class, () -> manager.evaluations(request(2), manager.newDeadline()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);

        pdp.result.set(new EvaluationsResponse(null));
        ex = expectThrows(ExternalPdpException.class, () -> manager.evaluations(request(2), manager.newDeadline()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);

        pdp.result.set(null);
        ex = expectThrows(ExternalPdpException.class, () -> manager.evaluations(request(2), manager.newDeadline()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);

        pdp.result.set(new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE, "down"));
        ex = expectThrows(ExternalPdpException.class, () -> manager.evaluations(request(2), manager.newDeadline()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.UNAVAILABLE);

        pdp.result.set(new IllegalStateException("bug"));
        ex = expectThrows(ExternalPdpException.class, () -> manager.evaluations(request(2), manager.newDeadline()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);

        ex = expectThrows(ExternalPdpException.class, () -> manager.evaluations(request(2), System.nanoTime() - 1));
        assertEquals(ex.getCode(), ExternalPdpException.Code.TIMEOUT);

        manager.close();
        assertTrue(pdp.closed);
    }

    @Test
    public void testDeadline() throws ExternalPdpException {
        ScriptedPdp pdp = new ScriptedPdp();
        pdp.delayMs = 2000;
        pdp.result.set(response(1));
        ExternalPdpManager manager = new ExternalPdpManager(config("100", "2"), pdp, new ExternalPdpContext.Builder());
        long start = System.nanoTime();
        ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                () -> manager.evaluations(request(1), manager.newDeadline()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.TIMEOUT);
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1500);
        manager.close();
    }

    @Test
    public void testInterrupted() throws Exception {
        ScriptedPdp pdp = new ScriptedPdp();
        pdp.delayMs = 2000;
        pdp.result.set(response(1));
        ExternalPdpManager manager = new ExternalPdpManager(config("5000", "2"), pdp, new ExternalPdpContext.Builder());
        AtomicReference<ExternalPdpException.Code> code = new AtomicReference<>();
        Thread caller = new Thread(() -> {
            try {
                manager.evaluations(request(1), manager.newDeadline());
            } catch (ExternalPdpException ex) {
                code.set(ex.getCode());
            }
        });
        caller.start();
        Thread.sleep(200);
        caller.interrupt();
        caller.join(5000);
        assertEquals(code.get(), ExternalPdpException.Code.TIMEOUT);
        manager.close();
    }

    @Test
    public void testBulkheadAndAuditQueue() throws Exception {
        ScriptedPdp pdp = new ScriptedPdp();
        pdp.release = new CountDownLatch(1);
        pdp.result.set(response(1));
        ExternalPdpManager manager = new ExternalPdpManager(config("5000", "1"), pdp, new ExternalPdpContext.Builder());

        Thread first = new Thread(() -> {
            try {
                manager.evaluations(request(1), manager.newDeadline());
            } catch (ExternalPdpException ignored) {
                // released at the end of the test
            }
        });
        first.start();
        Thread.sleep(200);
        ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                () -> manager.evaluations(request(1), manager.newDeadline()));
        assertEquals(ex.getCode(), ExternalPdpException.Code.UNAVAILABLE);

        CountDownLatch auditBlock = new CountDownLatch(1);
        assertTrue(manager.submitAudit(() -> {
            try {
                auditBlock.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }));
        Thread.sleep(100);
        assertTrue(manager.submitAudit(() -> { }));
        assertFalse(manager.submitAudit(() -> { }));

        auditBlock.countDown();
        pdp.release.countDown();
        first.join(5000);
        manager.close();
    }
}
