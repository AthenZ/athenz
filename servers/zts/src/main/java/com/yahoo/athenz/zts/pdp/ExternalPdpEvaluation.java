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

import com.yahoo.athenz.common.server.pdp.ExternalPdpException;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationRequest;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationResponse;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsOptions;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsRequest;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsResponse;
import com.yahoo.athenz.common.server.pdp.authzen.Resource;
import com.yahoo.athenz.common.server.pdp.authzen.Subject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Collects the evaluations for a single token request: the token gate
 * (always the first item), candidate roles and, in AUTHORITATIVE mode,
 * flow-specific permission checks. Role and permission items are grouped
 * by a caller-defined key (e.g. token subject vs. client principal).
 */
public final class ExternalPdpEvaluation {

    enum Kind {
        GATE,
        ROLE,
        PERMISSION
    }

    static final class Entry {
        final Kind kind;
        final String key;
        final String domain;
        final String role;

        Entry(final Kind kind, final String key, final String domain, final String role) {
            this.kind = kind;
            this.key = key;
            this.domain = domain;
            this.role = role;
        }
    }

    private final Subject subject;
    private final Map<String, Object> context;
    private final List<EvaluationRequest> items = new ArrayList<>();
    private final List<Entry> entries = new ArrayList<>();
    private final Map<String, Map<String, Set<String>>> candidates = new TreeMap<>();

    /**
     * @param subject default subject for all evaluations (the token subject)
     * @param context request context shared by all evaluations
     * @param tokenResource token gate resource
     */
    public ExternalPdpEvaluation(final Subject subject, final Map<String, Object> context,
            final Resource tokenResource) {
        this.subject = subject;
        this.context = context;
        items.add(new EvaluationRequest(null, AuthZenRequestBuilder.action(AuthZenRequestBuilder.ACTION_ISSUE_TOKEN),
                tokenResource, null));
        entries.add(new Entry(Kind.GATE, null, null, null));
    }

    /**
     * Add a candidate role evaluation.
     * @param key group key for the role decision
     * @param domain role domain
     * @param role role name
     * @param defined whether the role is defined in Athenz
     * @param rbacGranted whether RBAC granted the role, null if RBAC was not consulted
     * @param subjectOverride subject for this evaluation, null to use the default subject
     */
    public void addRole(final String key, final String domain, final String role, boolean defined,
            final Boolean rbacGranted, final Subject subjectOverride) {
        items.add(new EvaluationRequest(subjectOverride, null,
                AuthZenRequestBuilder.roleResource(domain, role, defined, rbacGranted), null));
        entries.add(new Entry(Kind.ROLE, key, domain, role));
        candidates.computeIfAbsent(key, k -> new TreeMap<>()).computeIfAbsent(domain, d -> new TreeSet<>()).add(role);
    }

    /**
     * Add a permission evaluation. All permissions sharing a key must be
     * permitted for the key to be granted.
     * @param key group key for the permission decision
     * @param action action name
     * @param resource Athenz resource string
     * @param subjectOverride subject for this evaluation, null to use the default subject
     */
    public void addPermission(final String key, final String action, final String resource,
            final Subject subjectOverride) {
        items.add(new EvaluationRequest(subjectOverride, AuthZenRequestBuilder.action(action),
                AuthZenRequestBuilder.athenzResource(resource), null));
        entries.add(new Entry(Kind.PERMISSION, key, null, null));
    }

    /**
     * @return the AuthZEN batch request for all collected evaluations
     */
    public EvaluationsRequest toRequest() {
        return new EvaluationsRequest(subject, AuthZenRequestBuilder.action(AuthZenRequestBuilder.ACTION_ASSUME_ROLE),
                null, context, items, new EvaluationsOptions(EvaluationsOptions.EXECUTE_ALL));
    }

    /**
     * @return candidate roles by key and domain
     */
    public Map<String, Map<String, Set<String>>> getCandidates() {
        return Collections.unmodifiableMap(candidates);
    }

    /**
     * Interpret the PDP response for this evaluation.
     * @param response batch response
     * @return decision
     * @throws ExternalPdpException if the response does not match the request
     */
    public ExternalPdpDecision decide(final EvaluationsResponse response) throws ExternalPdpException {
        final List<EvaluationResponse> results = response.getEvaluations();
        if (results == null || results.size() != items.size()) {
            throw new ExternalPdpException(ExternalPdpException.Code.INVALID_RESPONSE,
                    "pdp returned an unexpected number of evaluation results");
        }
        ExternalPdpDecision.Builder builder = new ExternalPdpDecision.Builder();
        for (int i = 0; i < results.size(); i++) {
            final Entry entry = entries.get(i);
            final EvaluationResponse result = results.get(i);
            builder.reason(i, result.getContext());
            switch (entry.kind) {
                case GATE:
                    builder.gate(result.getDecision(), result.getContext());
                    break;
                case ROLE:
                    builder.role(entry.key, entry.domain, entry.role, result.getDecision());
                    break;
                default:
                    builder.permission(entry.key, result.getDecision());
                    break;
            }
        }
        return builder.build();
    }

    /**
     * Decision used when the PDP failed and the configuration allows
     * failing open: every candidate is permitted, no claims are added.
     * @param maxExpiresIn maximum token lifetime in seconds
     * @return fail-open decision
     */
    public ExternalPdpDecision failOpen(int maxExpiresIn) {
        ExternalPdpDecision.Builder builder = new ExternalPdpDecision.Builder().failOpen(maxExpiresIn);
        for (Entry entry : entries) {
            if (entry.kind == Kind.ROLE) {
                builder.role(entry.key, entry.domain, entry.role, true);
            } else if (entry.kind == Kind.PERMISSION) {
                builder.permission(entry.key, true);
            }
        }
        return builder.build();
    }
}
