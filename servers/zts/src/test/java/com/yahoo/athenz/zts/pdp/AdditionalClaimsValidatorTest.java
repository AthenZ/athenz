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

import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;

public class AdditionalClaimsValidatorTest {

    @AfterMethod
    public void cleanup() {
        ExternalPdpConfigTest.clearProperties();
    }

    private static AdditionalClaimsValidator validator() {
        return new AdditionalClaimsValidator(ExternalPdpConfig.fromSystemProperties());
    }

    @Test
    public void testAcceptedClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("tier", "gold");
        claims.put("risk", 3);
        claims.put("mfa", true);
        claims.put("entitlements", List.of("a", Map.of("k", List.of(1))));
        AdditionalClaimsValidator.Result result = validator().validate(claims);
        assertFalse(result.isFailed());
        assertTrue(result.getRejected().isEmpty());
        assertEquals(result.getAccepted(), claims);
    }

    @Test
    public void testStrictRejection() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("tier", "gold");
        claims.put("sub", "user.evil");
        AdditionalClaimsValidator.Result result = validator().validate(claims);
        assertTrue(result.isFailed());
        assertTrue(result.getAccepted().isEmpty());
        assertEquals(result.getRejected(), List.of("sub"));
    }

    @Test
    public void testLenientRejection() {
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_STRICT, "false");
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_RESERVED_EXTRA, "org");
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("tier", "gold");
        claims.put("org", "x");
        claims.put("1bad", "x");
        claims.put("deep", List.of(List.of(List.of(List.of("too deep")))));
        claims.put("nullvalue", null);
        claims.put("object", new Object());
        claims.put("badkey", Map.of(1, "x"));
        AdditionalClaimsValidator.Result result = validator().validate(claims);
        assertFalse(result.isFailed());
        assertEquals(result.getAccepted(), Map.of("tier", "gold"));
        assertEquals(result.getRejected(), List.of("org", "1bad", "deep", "nullvalue", "object", "badkey"));
    }

    @Test
    public void testAllowList() {
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_ALLOWED, "pdp_*,tier");
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_STRICT, "false");
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("pdp_risk", 1);
        claims.put("tier", "gold");
        claims.put("other", "x");
        AdditionalClaimsValidator.Result result = validator().validate(claims);
        assertEquals(result.getAccepted().keySet(), List.of("pdp_risk", "tier").stream().collect(
                java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new)));
        assertEquals(result.getRejected(), List.of("other"));
    }

    @Test
    public void testSizeLimit() {
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_MAX_BYTES, "20");
        Map<String, Object> claims = Map.of("tier", "a-very-long-claim-value");
        AdditionalClaimsValidator.Result result = validator().validate(claims);
        assertTrue(result.isFailed());
        assertTrue(result.getAccepted().isEmpty());
        assertEquals(result.getRejected(), List.of("tier"));

        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_STRICT, "false");
        result = validator().validate(claims);
        assertFalse(result.isFailed());
        assertTrue(result.getAccepted().isEmpty());
    }

    @Test
    public void testHelpers() {
        assertFalse(validator().isValidName(null));
        assertEquals(AdditionalClaimsValidator.serializedSize(Map.of("a", new Object())), Integer.MAX_VALUE);
        assertTrue(AdditionalClaimsValidator.isValidValue(1.5, 0));
        assertFalse(AdditionalClaimsValidator.isValidValue(List.of(1), AdditionalClaimsValidator.MAX_DEPTH));
    }
}
