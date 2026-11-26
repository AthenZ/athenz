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
 * AuthZEN Access Evaluation request. When used as an item of an
 * {@link EvaluationsRequest}, any null member inherits the batch default.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class EvaluationRequest extends AuthZenObject {

    private final Subject subject;
    private final Action action;
    private final Resource resource;
    private final Map<String, Object> context;

    /**
     * @param subject subject of the decision
     * @param action requested action
     * @param resource target resource
     * @param context optional request context
     */
    @JsonCreator
    public EvaluationRequest(@JsonProperty("subject") final Subject subject,
            @JsonProperty("action") final Action action,
            @JsonProperty("resource") final Resource resource,
            @JsonProperty("context") final Map<String, Object> context) {
        this.subject = subject;
        this.action = action;
        this.resource = resource;
        this.context = copyOf(context);
    }

    public Subject getSubject() {
        return subject;
    }

    public Action getAction() {
        return action;
    }

    public Resource getResource() {
        return resource;
    }

    public Map<String, Object> getContext() {
        return context;
    }
}
