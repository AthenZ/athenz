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
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationRequest;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsRequest;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsResponse;
import com.yahoo.athenz.common.server.pdp.impl.AuthZenHttpPdp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Loads the configured PDP and executes calls to it under a per-request
 * deadline and a concurrency bulkhead, so that a slow or blocked PDP
 * cannot exhaust server request threads.
 */
public class ExternalPdpManager implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExternalPdpManager.class);

    static final String SCHEME_CLASS = "class://";
    static final String SCHEME_HTTPS = "https://";

    private final ExternalPolicyDecisionPoint pdp;
    private final ThreadPoolExecutor callExecutor;
    private final ThreadPoolExecutor fanoutExecutor;
    private final ThreadPoolExecutor auditExecutor;
    private final long timeoutNanos;

    /**
     * @param config external pdp configuration
     * @param pdp decision point implementation (not yet initialized)
     * @param contextBuilder context builder with server facilities; the executor is set by the manager
     * @throws ExternalPdpException if the decision point fails to initialize
     */
    public ExternalPdpManager(final ExternalPdpConfig config, final ExternalPolicyDecisionPoint pdp,
            final ExternalPdpContext.Builder contextBuilder) throws ExternalPdpException {

        this.pdp = pdp;
        this.timeoutNanos = TimeUnit.MILLISECONDS.toNanos(config.getTimeoutMs());

        final int concurrency = config.getMaxConcurrency();
        callExecutor = new ThreadPoolExecutor(concurrency, concurrency, 60, TimeUnit.SECONDS,
                new SynchronousQueue<>(), threadFactory("zts-ext-pdp-call"), new ThreadPoolExecutor.AbortPolicy());
        fanoutExecutor = new ThreadPoolExecutor(concurrency, concurrency, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(concurrency * 4), threadFactory("zts-ext-pdp-fanout"),
                new ThreadPoolExecutor.AbortPolicy());
        auditExecutor = new ThreadPoolExecutor(1, 1, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(config.getAuditQueueSize()), threadFactory("zts-ext-pdp-audit"),
                new ThreadPoolExecutor.AbortPolicy());
        callExecutor.allowCoreThreadTimeOut(true);
        fanoutExecutor.allowCoreThreadTimeOut(true);

        try {
            pdp.initialize(contextBuilder.endpoint(config.getEndpoint()).executor(fanoutExecutor)
                    .connectTimeoutMs(config.getTimeoutMs()).readTimeoutMs(config.getTimeoutMs())
                    .maxConnections(concurrency).build());
        } catch (ExternalPdpException | RuntimeException ex) {
            shutdownExecutors();
            throw ex;
        }
        LOGGER.info("External PDP {} initialized for endpoint {}", pdp.getClass().getName(), config.getEndpoint());
    }

    static ThreadFactory threadFactory(final String prefix) {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, prefix + "-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    /**
     * Create the decision point object for the given endpoint.
     * @param endpoint class://fully.qualified.ClassName or https:// url
     * @return uninitialized decision point
     * @throws IllegalArgumentException if the endpoint is invalid or the class cannot be used
     */
    public static ExternalPolicyDecisionPoint loadPdp(final String endpoint) {
        if (endpoint.toLowerCase(Locale.ROOT).startsWith(SCHEME_HTTPS)) {
            return new AuthZenHttpPdp();
        }
        if (!endpoint.startsWith(SCHEME_CLASS)) {
            throw new IllegalArgumentException("Unsupported external pdp endpoint scheme: " + endpoint);
        }
        final String className = endpoint.substring(SCHEME_CLASS.length());
        Object instance;
        try {
            instance = Class.forName(className).getConstructor().newInstance();
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to create external pdp class: " + className, ex);
        }
        if (!(instance instanceof ExternalPolicyDecisionPoint)) {
            throw new IllegalArgumentException(className + " does not implement ExternalPolicyDecisionPoint");
        }
        ExternalPolicyDecisionPoint pdp = (ExternalPolicyDecisionPoint) instance;
        if (!declaresDecisionMethod(pdp.getClass())) {
            throw new IllegalArgumentException(className + " must override evaluate or evaluations");
        }
        return pdp;
    }

    static boolean declaresDecisionMethod(final Class<?> pdpClass) {
        try {
            return pdpClass.getMethod("evaluate", EvaluationRequest.class).getDeclaringClass()
                        != ExternalPolicyDecisionPoint.class
                    || pdpClass.getMethod("evaluations", EvaluationsRequest.class).getDeclaringClass()
                        != ExternalPolicyDecisionPoint.class;
        } catch (NoSuchMethodException ex) {
            return false;
        }
    }

    /**
     * @return deadline (System.nanoTime based) for a new token request
     */
    public long newDeadline() {
        return System.nanoTime() + timeoutNanos;
    }

    /**
     * Execute a batch evaluation and verify the result count.
     * @param request batch request
     * @param deadline request deadline from {@link #newDeadline()}
     * @return validated batch response
     * @throws ExternalPdpException on failure, timeout, saturation or invalid response
     */
    public EvaluationsResponse evaluations(final EvaluationsRequest request, long deadline)
            throws ExternalPdpException {
        EvaluationsResponse response = call(() -> pdp.evaluations(request), deadline);
        if (response.getEvaluations() == null
                || response.getEvaluations().size() != request.getEvaluations().size()) {
            throw new ExternalPdpException(ExternalPdpException.Code.INVALID_RESPONSE,
                    "pdp returned an unexpected number of evaluation results");
        }
        return response;
    }

    <T> T call(final Callable<T> callable, long deadline) throws ExternalPdpException {
        final long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "pdp deadline exceeded");
        }
        Future<T> future;
        try {
            future = callExecutor.submit(callable);
        } catch (RejectedExecutionException ex) {
            throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE, "pdp concurrency limit reached", ex);
        }
        T result;
        try {
            result = future.get(remaining, TimeUnit.NANOSECONDS);
        } catch (TimeoutException ex) {
            future.cancel(true);
            throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "pdp deadline exceeded", ex);
        } catch (InterruptedException ex) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "pdp call interrupted", ex);
        } catch (ExecutionException ex) {
            if (ex.getCause() instanceof ExternalPdpException) {
                throw (ExternalPdpException) ex.getCause();
            }
            throw new ExternalPdpException(ExternalPdpException.Code.INTERNAL, "pdp call failed", ex.getCause());
        }
        if (result == null) {
            throw new ExternalPdpException(ExternalPdpException.Code.INVALID_RESPONSE, "pdp returned no response");
        }
        return result;
    }

    /**
     * Queue a shadow (audit) evaluation. Never blocks the caller.
     * @param task audit task
     * @return false if the audit queue is full and the task was dropped
     */
    public boolean submitAudit(final Runnable task) {
        try {
            auditExecutor.execute(task);
            return true;
        } catch (RejectedExecutionException ex) {
            return false;
        }
    }

    ExternalPolicyDecisionPoint getPdp() {
        return pdp;
    }

    void shutdownExecutors() {
        callExecutor.shutdownNow();
        fanoutExecutor.shutdownNow();
        auditExecutor.shutdownNow();
    }

    @Override
    public void close() {
        shutdownExecutors();
        pdp.close();
    }
}
