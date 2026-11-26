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

import com.yahoo.athenz.zts.token.AccessTokenRequest.RequestType;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.testng.Assert.*;

public class ExternalPdpConfigTest {

    static final String[] PROPS = {
        ExternalPdpConfig.PROP_MODE, ExternalPdpConfig.PROP_AUDIT_TARGET, ExternalPdpConfig.PROP_ENDPOINT,
        ExternalPdpConfig.PROP_FLOWS, ExternalPdpConfig.PROP_TIMEOUT_MS, ExternalPdpConfig.PROP_MAX_CONCURRENCY,
        ExternalPdpConfig.PROP_AUDIT_QUEUE_SIZE, ExternalPdpConfig.PROP_FAIL_OPEN,
        ExternalPdpConfig.PROP_FAIL_OPEN_MAX_EXPIRES_IN, ExternalPdpConfig.PROP_REQUIRE_DEFINED_ROLES,
        ExternalPdpConfig.PROP_MAX_CANDIDATE_ROLES, ExternalPdpConfig.PROP_CLAIMS_ENABLED,
        ExternalPdpConfig.PROP_CLAIMS_ALLOWED, ExternalPdpConfig.PROP_CLAIMS_RESERVED_EXTRA,
        ExternalPdpConfig.PROP_CLAIMS_MAX_BYTES, ExternalPdpConfig.PROP_CLAIMS_STRICT
    };

    static void clearProperties() {
        for (String prop : PROPS) {
            System.clearProperty(prop);
        }
    }

    @AfterMethod
    public void cleanup() {
        clearProperties();
    }

    @Test
    public void testDefaults() {
        ExternalPdpConfig config = ExternalPdpConfig.fromSystemProperties();
        assertEquals(config.getMode(), ExternalPdpMode.DISABLED);
        assertEquals(config.getAuditTarget(), ExternalPdpMode.FILTER);
        assertEquals(config.getEndpoint(), "");
        assertEquals(config.getFlows(), EnumSet.allOf(ExternalPdpFlow.class));
        assertEquals(config.getTimeoutMs(), 500);
        assertEquals(config.getMaxConcurrency(), 64);
        assertEquals(config.getAuditQueueSize(), 1000);
        assertFalse(config.isFailOpen());
        assertEquals(config.getFailOpenMaxExpiresIn(), 300);
        assertTrue(config.isRequireDefinedRoles());
        assertEquals(config.getMaxCandidateRoles(), 64);
        assertFalse(config.isClaimsEnabled());
        assertTrue(config.getClaimsAllowed().isEmpty());
        assertTrue(config.getClaimsReservedExtra().isEmpty());
        assertEquals(config.getClaimsMaxBytes(), 2048);
        assertTrue(config.isClaimsStrict());
    }

    @Test
    public void testCustomValues() {
        System.setProperty(ExternalPdpConfig.PROP_MODE, " filter ");
        System.setProperty(ExternalPdpConfig.PROP_AUDIT_TARGET, "authoritative");
        System.setProperty(ExternalPdpConfig.PROP_ENDPOINT, "https://pdp.athenz.io");
        System.setProperty(ExternalPdpConfig.PROP_FLOWS, "access_token, jag,");
        System.setProperty(ExternalPdpConfig.PROP_TIMEOUT_MS, "250");
        System.setProperty(ExternalPdpConfig.PROP_MAX_CONCURRENCY, "8");
        System.setProperty(ExternalPdpConfig.PROP_AUDIT_QUEUE_SIZE, "10");
        System.setProperty(ExternalPdpConfig.PROP_FAIL_OPEN, "true");
        System.setProperty(ExternalPdpConfig.PROP_FAIL_OPEN_MAX_EXPIRES_IN, "60");
        System.setProperty(ExternalPdpConfig.PROP_REQUIRE_DEFINED_ROLES, "false");
        System.setProperty(ExternalPdpConfig.PROP_MAX_CANDIDATE_ROLES, "5");
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_ENABLED, "true");
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_ALLOWED, "pdp_*,tier");
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_RESERVED_EXTRA, "org");
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_MAX_BYTES, "100");
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_STRICT, "false");

        ExternalPdpConfig config = ExternalPdpConfig.fromSystemProperties();
        assertEquals(config.getMode(), ExternalPdpMode.FILTER);
        assertEquals(config.getAuditTarget(), ExternalPdpMode.AUTHORITATIVE);
        assertEquals(config.getEndpoint(), "https://pdp.athenz.io");
        assertEquals(config.getFlows(), EnumSet.of(ExternalPdpFlow.ACCESS_TOKEN, ExternalPdpFlow.JAG));
        assertEquals(config.getTimeoutMs(), 250);
        assertEquals(config.getMaxConcurrency(), 8);
        assertEquals(config.getAuditQueueSize(), 10);
        assertTrue(config.isFailOpen());
        assertEquals(config.getFailOpenMaxExpiresIn(), 60);
        assertFalse(config.isRequireDefinedRoles());
        assertEquals(config.getMaxCandidateRoles(), 5);
        assertTrue(config.isClaimsEnabled());
        assertEquals(config.getClaimsAllowed(), List.of("pdp_*", "tier"));
        assertEquals(config.getClaimsReservedExtra(), Set.of("org"));
        assertEquals(config.getClaimsMaxBytes(), 100);
        assertFalse(config.isClaimsStrict());
    }

    @Test
    public void testModeFromSystemProperties() {
        assertEquals(ExternalPdpConfig.modeFromSystemProperties(), ExternalPdpMode.DISABLED);
        System.setProperty(ExternalPdpConfig.PROP_MODE, " authoritative ");
        assertEquals(ExternalPdpConfig.modeFromSystemProperties(), ExternalPdpMode.AUTHORITATIVE);
        System.setProperty(ExternalPdpConfig.PROP_MODE, "augment");
        assertThrows(IllegalArgumentException.class, ExternalPdpConfig::modeFromSystemProperties);
    }

    @Test
    public void testInvalidValues() {
        System.setProperty(ExternalPdpConfig.PROP_MODE, "augment");
        assertThrows(IllegalArgumentException.class, ExternalPdpConfig::fromSystemProperties);

        System.setProperty(ExternalPdpConfig.PROP_MODE, "AUDIT");
        assertThrows(IllegalArgumentException.class, ExternalPdpConfig::fromSystemProperties);

        System.setProperty(ExternalPdpConfig.PROP_ENDPOINT, "https://pdp.athenz.io");
        System.setProperty(ExternalPdpConfig.PROP_AUDIT_TARGET, "AUDIT");
        assertThrows(IllegalArgumentException.class, ExternalPdpConfig::fromSystemProperties);
        System.setProperty(ExternalPdpConfig.PROP_AUDIT_TARGET, "DISABLED");
        assertThrows(IllegalArgumentException.class, ExternalPdpConfig::fromSystemProperties);
        System.clearProperty(ExternalPdpConfig.PROP_AUDIT_TARGET);

        System.setProperty(ExternalPdpConfig.PROP_FLOWS, "access_token,id_token");
        assertThrows(IllegalArgumentException.class, ExternalPdpConfig::fromSystemProperties);
        System.clearProperty(ExternalPdpConfig.PROP_FLOWS);

        System.setProperty(ExternalPdpConfig.PROP_TIMEOUT_MS, "abc");
        assertThrows(IllegalArgumentException.class, ExternalPdpConfig::fromSystemProperties);
        System.setProperty(ExternalPdpConfig.PROP_TIMEOUT_MS, "0");
        assertThrows(IllegalArgumentException.class, ExternalPdpConfig::fromSystemProperties);
    }

    @Test
    public void testFlow() {
        assertEquals(ExternalPdpFlow.fromConfigName("token_exchange"), ExternalPdpFlow.TOKEN_EXCHANGE);
        assertNull(ExternalPdpFlow.fromConfigName("unknown"));
        assertEquals(ExternalPdpFlow.JAG.getConfigName(), "jag");
        assertEquals(ExternalPdpFlow.fromRequestType(RequestType.ACCESS_TOKEN), ExternalPdpFlow.ACCESS_TOKEN);
        assertEquals(ExternalPdpFlow.fromRequestType(RequestType.ACCESS_TOKEN_EXCHANGE), ExternalPdpFlow.TOKEN_EXCHANGE);
        assertEquals(ExternalPdpFlow.fromRequestType(RequestType.JAG_TOKEN_EXCHANGE), ExternalPdpFlow.JAG);
        assertEquals(ExternalPdpFlow.fromRequestType(RequestType.JAG_JWT_BEARER), ExternalPdpFlow.JAG);
        assertNull(ExternalPdpFlow.fromRequestType(RequestType.ID_TOKEN_EXCHANGE));
    }
}
