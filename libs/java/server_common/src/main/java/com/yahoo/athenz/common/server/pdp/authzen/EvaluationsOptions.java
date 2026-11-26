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

/**
 * AuthZEN Access Evaluations options.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class EvaluationsOptions extends AuthZenObject {

    public static final String EXECUTE_ALL = "execute_all";
    public static final String DENY_ON_FIRST_DENY = "deny_on_first_deny";
    public static final String PERMIT_ON_FIRST_PERMIT = "permit_on_first_permit";

    private final String evaluationsSemantic;

    /**
     * @param evaluationsSemantic one of execute_all, deny_on_first_deny or permit_on_first_permit
     */
    @JsonCreator
    public EvaluationsOptions(@JsonProperty("evaluations_semantic") final String evaluationsSemantic) {
        this.evaluationsSemantic = evaluationsSemantic;
    }

    @JsonProperty("evaluations_semantic")
    public String getEvaluationsSemantic() {
        return evaluationsSemantic;
    }
}
