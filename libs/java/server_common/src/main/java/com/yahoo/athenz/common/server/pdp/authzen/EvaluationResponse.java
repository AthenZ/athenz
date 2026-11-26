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

package com.yahoo.athenz.common.server.pdp.authzen;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * AuthZEN Access Evaluation response. Only a JSON boolean true is
 * treated as a permit; a missing or non-boolean decision is a deny.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class EvaluationResponse extends AuthZenObject {

    private final boolean decision;
    private final Map<String, Object> context;

    /**
     * @param decision true if the request is permitted
     * @param context optional response context
     */
    public EvaluationResponse(final boolean decision, final Map<String, Object> context) {
        this.decision = decision;
        this.context = copyOf(context);
    }

    @JsonCreator
    static EvaluationResponse fromJson(@JsonProperty("decision") final Object decision,
            @JsonProperty("context") final Map<String, Object> context) {
        return new EvaluationResponse(Boolean.TRUE.equals(decision), context);
    }

    @JsonProperty("decision")
    public boolean getDecision() {
        return decision;
    }

    public Map<String, Object> getContext() {
        return context;
    }
}
