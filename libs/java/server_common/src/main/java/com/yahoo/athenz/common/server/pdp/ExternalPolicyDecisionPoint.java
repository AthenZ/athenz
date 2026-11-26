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
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsRequest;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsResponse;

/**
 * External Policy Decision Point consulted by ZTS during OAuth2 access
 * token issuance. Requests and responses use the AuthZEN-aligned model;
 * implementations are free to use any wire protocol. Implementations must
 * be thread-safe and must override at least one of {@link #evaluate} or
 * {@link #evaluations}.
 */
public interface ExternalPolicyDecisionPoint {

    /**
     * Called once at server startup.
     * @param context server facilities available to the implementation
     * @throws ExternalPdpException if the implementation cannot be initialized
     */
    void initialize(ExternalPdpContext context) throws ExternalPdpException;

    /**
     * Single decision (AuthZEN Access Evaluation).
     * @param request evaluation request
     * @return evaluation response
     * @throws ExternalPdpException in case of any failure
     */
    default EvaluationResponse evaluate(EvaluationRequest request) throws ExternalPdpException {
        throw new ExternalPdpException(ExternalPdpException.Code.UNSUPPORTED, "single evaluation not supported");
    }

    /**
     * Batch decision (AuthZEN Access Evaluations). ZTS always calls this
     * method. The default implementation expands the batch into sequential
     * {@link #evaluate} calls. Results must be returned in request order.
     * @param request batch evaluation request
     * @return batch evaluation response
     * @throws ExternalPdpException in case of any failure
     */
    default EvaluationsResponse evaluations(EvaluationsRequest request) throws ExternalPdpException {
        return ExternalPdpSupport.expandBatch(this, request, null);
    }

    /**
     * Called once at server shutdown.
     */
    default void close() {
    }
}
