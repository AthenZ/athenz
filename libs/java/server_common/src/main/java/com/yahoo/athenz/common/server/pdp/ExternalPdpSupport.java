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

import com.yahoo.athenz.common.server.pdp.authzen.EvaluationRequest;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationResponse;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsOptions;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsRequest;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;

/**
 * Helpers for {@link ExternalPolicyDecisionPoint} implementations.
 */
public final class ExternalPdpSupport {

    private ExternalPdpSupport() {
    }

    /**
     * Apply the AuthZEN default-value inheritance: any member not set on the
     * evaluation item is taken from the batch request.
     * @param request batch request with the default values
     * @param item evaluation item
     * @return a single evaluation request with all defaults applied
     */
    public static EvaluationRequest applyDefaults(final EvaluationsRequest request, final EvaluationRequest item) {
        return new EvaluationRequest(
                item.getSubject() != null ? item.getSubject() : request.getSubject(),
                item.getAction() != null ? item.getAction() : request.getAction(),
                item.getResource() != null ? item.getResource() : request.getResource(),
                item.getContext() != null ? item.getContext() : request.getContext());
    }

    /**
     * Expand a batch request into single {@link ExternalPolicyDecisionPoint#evaluate}
     * calls. With the execute_all semantic (the default) and a non-null executor,
     * the calls are executed in parallel; otherwise they are executed sequentially
     * and the short-circuit semantics are honored.
     * @param pdp decision point that implements single evaluation
     * @param request batch request
     * @param executor optional executor for parallel execution
     * @return batch response with results in request order
     * @throws ExternalPdpException if any single evaluation fails
     */
    public static EvaluationsResponse expandBatch(final ExternalPolicyDecisionPoint pdp,
            final EvaluationsRequest request, final ExecutorService executor) throws ExternalPdpException {

        final List<EvaluationRequest> items = request.getEvaluations() == null
                ? Collections.emptyList() : request.getEvaluations();
        final String semantic = request.getOptions() == null ? null : request.getOptions().getEvaluationsSemantic();

        if (executor != null && (semantic == null || EvaluationsOptions.EXECUTE_ALL.equals(semantic))) {
            return new EvaluationsResponse(evaluateParallel(pdp, request, items, executor));
        }

        List<EvaluationResponse> results = new ArrayList<>(items.size());
        for (EvaluationRequest item : items) {
            EvaluationResponse result = pdp.evaluate(applyDefaults(request, item));
            results.add(result);
            if (isShortCircuit(semantic, result.getDecision())) {
                break;
            }
        }
        return new EvaluationsResponse(results);
    }

    static boolean isShortCircuit(final String semantic, boolean decision) {
        if (EvaluationsOptions.DENY_ON_FIRST_DENY.equals(semantic)) {
            return !decision;
        }
        return EvaluationsOptions.PERMIT_ON_FIRST_PERMIT.equals(semantic) && decision;
    }

    // submissions are incremental: when the shared executor is full, the
    // caller waits for its own oldest task instead of failing the batch, so a
    // batch larger than the executor capacity is still evaluated

    static List<EvaluationResponse> evaluateParallel(final ExternalPolicyDecisionPoint pdp,
            final EvaluationsRequest request, final List<EvaluationRequest> items,
            final ExecutorService executor) throws ExternalPdpException {

        List<Future<EvaluationResponse>> futures = new ArrayList<>(items.size());
        List<EvaluationResponse> results = new ArrayList<>(items.size());
        try {
            for (EvaluationRequest item : items) {
                final EvaluationRequest single = applyDefaults(request, item);
                while (!submit(executor, futures, () -> pdp.evaluate(single))) {
                    if (results.size() == futures.size()) {
                        cancelAll(futures);
                        throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE,
                                "evaluation executor saturated");
                    }
                    results.add(futures.get(results.size()).get());
                }
            }
            while (results.size() < futures.size()) {
                results.add(futures.get(results.size()).get());
            }
            return results;
        } catch (InterruptedException ex) {
            cancelAll(futures);
            Thread.currentThread().interrupt();
            throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "evaluation interrupted", ex);
        } catch (ExecutionException ex) {
            cancelAll(futures);
            if (ex.getCause() instanceof ExternalPdpException) {
                throw (ExternalPdpException) ex.getCause();
            }
            throw new ExternalPdpException(ExternalPdpException.Code.INTERNAL, "evaluation failed", ex.getCause());
        }
    }

    static boolean submit(final ExecutorService executor, final List<Future<EvaluationResponse>> futures,
            final Callable<EvaluationResponse> task) {
        try {
            futures.add(executor.submit(task));
            return true;
        } catch (RejectedExecutionException ex) {
            return false;
        }
    }

    static void cancelAll(final List<Future<EvaluationResponse>> futures) {
        for (Future<EvaluationResponse> future : futures) {
            future.cancel(true);
        }
    }
}
