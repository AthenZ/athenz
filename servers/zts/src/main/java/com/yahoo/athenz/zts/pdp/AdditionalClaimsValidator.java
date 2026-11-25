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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validates additional claims returned by the PDP before they are added
 * to an access token. Claims can never override standard or Athenz claims.
 */
public final class AdditionalClaimsValidator {

    static final Set<String> RESERVED_CLAIMS = Set.of("iss", "sub", "aud", "exp", "nbf", "iat", "jti",
            "scope", "scp", "client_id", "uid", "ver", "auth_time", "cnf", "act", "may_act", "proxy",
            "authorization_details", "principal_issuer", "spiffe", "azp", "nonce", "groups", "resource", "typ");

    static final Pattern CLAIM_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9_.:-]{0,63}");
    static final int MAX_DEPTH = 3;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Set<String> reserved;
    private final List<String> allowed;
    private final int maxBytes;
    private final boolean strict;

    /**
     * @param config external pdp configuration
     */
    public AdditionalClaimsValidator(final ExternalPdpConfig config) {
        reserved = new HashSet<>(RESERVED_CLAIMS);
        reserved.addAll(config.getClaimsReservedExtra());
        allowed = config.getClaimsAllowed();
        maxBytes = config.getClaimsMaxBytes();
        strict = config.isClaimsStrict();
    }

    /**
     * Result of a claims validation.
     */
    public static final class Result {

        private final Map<String, Object> accepted;
        private final List<String> rejected;
        private final boolean failed;

        Result(final Map<String, Object> accepted, final List<String> rejected, boolean failed) {
            this.accepted = Collections.unmodifiableMap(accepted);
            this.rejected = Collections.unmodifiableList(rejected);
            this.failed = failed;
        }

        /**
         * @return claims to add to the token
         */
        public Map<String, Object> getAccepted() {
            return accepted;
        }

        /**
         * @return names of the rejected claims
         */
        public List<String> getRejected() {
            return rejected;
        }

        /**
         * @return true if the request must be denied (strict mode violation)
         */
        public boolean isFailed() {
            return failed;
        }
    }

    /**
     * @param claims claims returned by the PDP
     * @return validation result
     */
    public Result validate(final Map<String, Object> claims) {
        Map<String, Object> accepted = new LinkedHashMap<>();
        List<String> rejected = new ArrayList<>();
        for (Map.Entry<String, Object> claim : claims.entrySet()) {
            if (isValidName(claim.getKey()) && isValidValue(claim.getValue(), 0)) {
                accepted.put(claim.getKey(), claim.getValue());
            } else {
                rejected.add(claim.getKey());
            }
        }
        if (!rejected.isEmpty() && strict) {
            return new Result(Collections.emptyMap(), rejected, true);
        }
        if (serializedSize(accepted) > maxBytes) {
            rejected.addAll(accepted.keySet());
            return new Result(Collections.emptyMap(), rejected, strict);
        }
        return new Result(accepted, rejected, false);
    }

    boolean isValidName(final String name) {
        if (name == null || !CLAIM_NAME.matcher(name).matches() || reserved.contains(name)) {
            return false;
        }
        if (allowed.isEmpty()) {
            return true;
        }
        for (String pattern : allowed) {
            if (pattern.endsWith("*") ? name.startsWith(pattern.substring(0, pattern.length() - 1))
                    : name.equals(pattern)) {
                return true;
            }
        }
        return false;
    }

    static boolean isValidValue(final Object value, int depth) {
        if (value instanceof String || value instanceof Number || value instanceof Boolean) {
            return true;
        }
        if (depth >= MAX_DEPTH) {
            return false;
        }
        if (value instanceof List) {
            for (Object item : (List<?>) value) {
                if (!isValidValue(item, depth + 1)) {
                    return false;
                }
            }
            return true;
        }
        if (value instanceof Map) {
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!(entry.getKey() instanceof String) || !isValidValue(entry.getValue(), depth + 1)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    static int serializedSize(final Map<String, Object> claims) {
        try {
            return MAPPER.writeValueAsBytes(claims).length;
        } catch (JsonProcessingException ex) {
            return Integer.MAX_VALUE;
        }
    }
}
