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
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Immutable external PDP configuration read from system properties.
 */
public final class ExternalPdpConfig {

    public static final String PROP_PREFIX = "athenz.zts.external_pdp.";
    public static final String PROP_MODE = PROP_PREFIX + "mode";
    public static final String PROP_AUDIT_TARGET = PROP_PREFIX + "audit_target";
    public static final String PROP_ENDPOINT = PROP_PREFIX + "endpoint";
    public static final String PROP_FLOWS = PROP_PREFIX + "flows";
    public static final String PROP_TIMEOUT_MS = PROP_PREFIX + "timeout_ms";
    public static final String PROP_MAX_CONCURRENCY = PROP_PREFIX + "max_concurrency";
    public static final String PROP_AUDIT_QUEUE_SIZE = PROP_PREFIX + "audit_queue_size";
    public static final String PROP_FAIL_OPEN = PROP_PREFIX + "fail_open";
    public static final String PROP_FAIL_OPEN_MAX_EXPIRES_IN = PROP_PREFIX + "fail_open_max_expires_in";
    public static final String PROP_REQUIRE_DEFINED_ROLES = PROP_PREFIX + "require_defined_roles";
    public static final String PROP_MAX_CANDIDATE_ROLES = PROP_PREFIX + "max_candidate_roles";
    public static final String PROP_CLAIMS_ENABLED = PROP_PREFIX + "claims_enabled";
    public static final String PROP_CLAIMS_ALLOWED = PROP_PREFIX + "claims_allowed";
    public static final String PROP_CLAIMS_RESERVED_EXTRA = PROP_PREFIX + "claims_reserved_extra";
    public static final String PROP_CLAIMS_MAX_BYTES = PROP_PREFIX + "claims_max_bytes";
    public static final String PROP_CLAIMS_STRICT = PROP_PREFIX + "claims_strict";

    private final ExternalPdpMode mode;
    private final ExternalPdpMode auditTarget;
    private final String endpoint;
    private final Set<ExternalPdpFlow> flows;
    private final int timeoutMs;
    private final int maxConcurrency;
    private final int auditQueueSize;
    private final boolean failOpen;
    private final int failOpenMaxExpiresIn;
    private final boolean requireDefinedRoles;
    private final int maxCandidateRoles;
    private final boolean claimsEnabled;
    private final List<String> claimsAllowed;
    private final Set<String> claimsReservedExtra;
    private final int claimsMaxBytes;
    private final boolean claimsStrict;

    private ExternalPdpConfig() {
        mode = modeFromSystemProperties();
        auditTarget = parseMode(PROP_AUDIT_TARGET, "FILTER");
        if (auditTarget != ExternalPdpMode.FILTER && auditTarget != ExternalPdpMode.AUTHORITATIVE) {
            throw new IllegalArgumentException("Invalid " + PROP_AUDIT_TARGET + ": " + auditTarget);
        }
        endpoint = System.getProperty(PROP_ENDPOINT, "");
        if (mode != ExternalPdpMode.DISABLED && endpoint.isEmpty()) {
            throw new IllegalArgumentException(PROP_ENDPOINT + " is required when " + PROP_MODE + " is " + mode);
        }
        flows = parseFlows(System.getProperty(PROP_FLOWS, "access_token,token_exchange,jag"));
        timeoutMs = parsePositiveInt(PROP_TIMEOUT_MS, 500);
        maxConcurrency = parsePositiveInt(PROP_MAX_CONCURRENCY, 64);
        auditQueueSize = parsePositiveInt(PROP_AUDIT_QUEUE_SIZE, 1000);
        failOpen = Boolean.parseBoolean(System.getProperty(PROP_FAIL_OPEN, "false"));
        failOpenMaxExpiresIn = parsePositiveInt(PROP_FAIL_OPEN_MAX_EXPIRES_IN, 300);
        requireDefinedRoles = Boolean.parseBoolean(System.getProperty(PROP_REQUIRE_DEFINED_ROLES, "true"));
        maxCandidateRoles = parsePositiveInt(PROP_MAX_CANDIDATE_ROLES, 64);
        claimsEnabled = Boolean.parseBoolean(System.getProperty(PROP_CLAIMS_ENABLED, "false"));
        claimsAllowed = Collections.unmodifiableList(parseList(System.getProperty(PROP_CLAIMS_ALLOWED, "")));
        claimsReservedExtra = Collections.unmodifiableSet(new HashSet<>(
                parseList(System.getProperty(PROP_CLAIMS_RESERVED_EXTRA, ""))));
        claimsMaxBytes = parsePositiveInt(PROP_CLAIMS_MAX_BYTES, 2048);
        claimsStrict = Boolean.parseBoolean(System.getProperty(PROP_CLAIMS_STRICT, "true"));
    }

    /**
     * @return configuration based on the current system properties
     * @throws IllegalArgumentException if any property value is invalid
     */
    public static ExternalPdpConfig fromSystemProperties() {
        return new ExternalPdpConfig();
    }

    /**
     * Reads only the mode so a disabled deployment never parses the remaining properties.
     * @return configured mode, DISABLED by default
     * @throws IllegalArgumentException if the mode value is invalid
     */
    public static ExternalPdpMode modeFromSystemProperties() {
        return parseMode(PROP_MODE, "DISABLED");
    }

    static ExternalPdpMode parseMode(final String property, final String defaultValue) {
        final String value = System.getProperty(property, defaultValue).trim().toUpperCase(Locale.ROOT);
        try {
            return ExternalPdpMode.valueOf(value);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid " + property + ": " + value, ex);
        }
    }

    static Set<ExternalPdpFlow> parseFlows(final String value) {
        Set<ExternalPdpFlow> result = EnumSet.noneOf(ExternalPdpFlow.class);
        for (String name : parseList(value)) {
            ExternalPdpFlow flow = ExternalPdpFlow.fromConfigName(name);
            if (flow == null) {
                throw new IllegalArgumentException("Invalid " + PROP_FLOWS + " entry: " + name);
            }
            result.add(flow);
        }
        return Collections.unmodifiableSet(result);
    }

    static int parsePositiveInt(final String property, int defaultValue) {
        final String value = System.getProperty(property);
        if (value == null) {
            return defaultValue;
        }
        int result;
        try {
            result = Integer.parseInt(value.trim());
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Invalid " + property + ": " + value, ex);
        }
        if (result <= 0) {
            throw new IllegalArgumentException("Invalid " + property + ": " + value);
        }
        return result;
    }

    static List<String> parseList(final String value) {
        List<String> result = new ArrayList<>();
        for (String item : value.split(",")) {
            final String trimmed = item.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }

    public ExternalPdpMode getMode() {
        return mode;
    }

    public ExternalPdpMode getAuditTarget() {
        return auditTarget;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public Set<ExternalPdpFlow> getFlows() {
        return flows;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public int getMaxConcurrency() {
        return maxConcurrency;
    }

    public int getAuditQueueSize() {
        return auditQueueSize;
    }

    public boolean isFailOpen() {
        return failOpen;
    }

    public int getFailOpenMaxExpiresIn() {
        return failOpenMaxExpiresIn;
    }

    public boolean isRequireDefinedRoles() {
        return requireDefinedRoles;
    }

    public int getMaxCandidateRoles() {
        return maxCandidateRoles;
    }

    public boolean isClaimsEnabled() {
        return claimsEnabled;
    }

    public List<String> getClaimsAllowed() {
        return claimsAllowed;
    }

    public Set<String> getClaimsReservedExtra() {
        return claimsReservedExtra;
    }

    public int getClaimsMaxBytes() {
        return claimsMaxBytes;
    }

    public boolean isClaimsStrict() {
        return claimsStrict;
    }
}
