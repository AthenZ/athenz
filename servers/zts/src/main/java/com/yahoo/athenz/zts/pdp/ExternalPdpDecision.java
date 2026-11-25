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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Interpreted PDP decision for a single token request.
 */
public final class ExternalPdpDecision {

    static final String CTX_CLAIMS = "claims";
    static final String CTX_MAX_EXPIRES_IN = "max_expires_in";
    static final String CTX_REASON_ADMIN = "reason_admin";

    private final boolean gatePermitted;
    private final Map<String, Map<String, Set<String>>> permittedRoles;
    private final Map<String, Boolean> permissions;
    private final Map<String, Object> claims;
    private final boolean claimsMalformed;
    private final Integer maxExpiresIn;
    private final List<Object> reasons;
    private final boolean failOpen;

    private ExternalPdpDecision(final Builder builder) {
        gatePermitted = builder.gatePermitted;
        permittedRoles = builder.permittedRoles;
        permissions = builder.permissions;
        claims = builder.claims;
        claimsMalformed = builder.claimsMalformed;
        maxExpiresIn = builder.maxExpiresIn;
        reasons = Collections.unmodifiableList(builder.reasons);
        failOpen = builder.failOpen;
    }

    public boolean isGatePermitted() {
        return gatePermitted;
    }

    /**
     * @param key role group key
     * @param domain role domain
     * @return the permitted roles for the key and domain (never null)
     */
    public Set<String> getPermittedRoles(final String key, final String domain) {
        Set<String> roles = permittedRoles.getOrDefault(key, Collections.emptyMap()).get(domain);
        return roles == null ? new TreeSet<>() : new TreeSet<>(roles);
    }

    /**
     * @return all permitted roles by key and domain
     */
    public Map<String, Map<String, Set<String>>> getPermittedRoles() {
        return Collections.unmodifiableMap(permittedRoles);
    }

    /**
     * @param key permission group key
     * @return true if all permissions with the given key were permitted (or none were requested)
     */
    public boolean isPermissionGranted(final String key) {
        return permissions.getOrDefault(key, Boolean.TRUE);
    }

    /**
     * @return claims returned by the token gate, or null if none
     */
    public Map<String, Object> getClaims() {
        return claims;
    }

    /**
     * @return true if the token gate returned a claims value that is not a JSON object
     */
    public boolean isClaimsMalformed() {
        return claimsMalformed;
    }

    /**
     * @return maximum token lifetime in seconds requested by the PDP, or null
     */
    public Integer getMaxExpiresIn() {
        return maxExpiresIn;
    }

    /**
     * @return reason_admin values returned by the PDP, for the decision log only
     */
    public List<Object> getReasons() {
        return reasons;
    }

    /**
     * @return true if this decision was synthesized because the PDP failed and fail-open is enabled
     */
    public boolean isFailOpen() {
        return failOpen;
    }

    static final class Builder {

        private boolean gatePermitted = true;
        private final Map<String, Map<String, Set<String>>> permittedRoles = new TreeMap<>();
        private final Map<String, Boolean> permissions = new HashMap<>();
        private Map<String, Object> claims;
        private boolean claimsMalformed;
        private Integer maxExpiresIn;
        private final List<Object> reasons = new ArrayList<>();
        private boolean failOpen;

        @SuppressWarnings("unchecked")
        Builder gate(boolean decision, final Map<String, Object> context) {
            gatePermitted = decision;
            if (context == null) {
                return this;
            }
            Object claimsValue = context.get(CTX_CLAIMS);
            if (claimsValue instanceof Map) {
                claims = (Map<String, Object>) claimsValue;
            } else if (claimsValue != null) {
                claimsMalformed = true;
            }
            Object expiry = context.get(CTX_MAX_EXPIRES_IN);
            if ((expiry instanceof Integer || expiry instanceof Long) && ((Number) expiry).longValue() > 0) {
                maxExpiresIn = (int) Math.min(((Number) expiry).longValue(), Integer.MAX_VALUE);
            }
            return this;
        }

        Builder role(final String key, final String domain, final String role, boolean decision) {
            Set<String> roles = permittedRoles.computeIfAbsent(key, k -> new TreeMap<>())
                    .computeIfAbsent(domain, d -> new TreeSet<>());
            if (decision) {
                roles.add(role);
            }
            return this;
        }

        Builder permission(final String key, boolean decision) {
            permissions.merge(key, decision, Boolean::logicalAnd);
            return this;
        }

        Builder reason(int index, final Map<String, Object> context) {
            if (context != null && context.get(CTX_REASON_ADMIN) != null) {
                Map<String, Object> reason = new TreeMap<>();
                reason.put("index", index);
                reason.put(CTX_REASON_ADMIN, context.get(CTX_REASON_ADMIN));
                reasons.add(reason);
            }
            return this;
        }

        Builder failOpen(int failOpenMaxExpiresIn) {
            failOpen = true;
            maxExpiresIn = failOpenMaxExpiresIn;
            return this;
        }

        ExternalPdpDecision build() {
            return new ExternalPdpDecision(this);
        }
    }
}
