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
import com.yahoo.athenz.common.server.pdp.authzen.Subject;
import org.testng.annotations.Test;

import java.util.*;

import static org.testng.Assert.*;

public class ExternalPdpEvaluationTest {

    private static ExternalPdpEvaluation evaluation() {
        ExternalPdpEvaluation evaluation = new ExternalPdpEvaluation(new Subject("service", "sports.api", null),
                Map.of("request_id", "r1"), AuthZenRequestBuilder.tokenResource("sports", List.of("sports")));
        evaluation.addRole("subject", "sports", "readers", true, Boolean.TRUE, null);
        evaluation.addRole("subject", "sports", "writers", true, Boolean.TRUE, null);
        evaluation.addRole("client", "sports", "readers", false, null, new Subject("service", "client.svc", null));
        evaluation.addPermission("target", "zts.jag_exchange", "sports:role.readers", null);
        evaluation.addPermission("target", "zts.jag_exchange", "sports:role.writers", null);
        return evaluation;
    }

    private static EvaluationsResponse response(Map<String, Object> gateContext, boolean... decisions) {
        List<EvaluationResponse> results = new ArrayList<>();
        for (int i = 0; i < decisions.length; i++) {
            results.add(new EvaluationResponse(decisions[i], i == 0 ? gateContext : null));
        }
        return new EvaluationsResponse(results);
    }

    @Test
    public void testToRequest() {
        EvaluationsRequest request = evaluation().toRequest();
        assertEquals(request.getSubject().getId(), "sports.api");
        assertEquals(request.getAction().getName(), AuthZenRequestBuilder.ACTION_ASSUME_ROLE);
        assertEquals(request.getContext().get("request_id"), "r1");
        assertEquals(request.getOptions().getEvaluationsSemantic(), EvaluationsOptions.EXECUTE_ALL);
        List<EvaluationRequest> items = request.getEvaluations();
        assertEquals(items.size(), 6);
        assertEquals(items.get(0).getAction().getName(), AuthZenRequestBuilder.ACTION_ISSUE_TOKEN);
        assertEquals(items.get(0).getResource().getType(), AuthZenRequestBuilder.RESOURCE_TOKEN);
        assertNull(items.get(1).getAction());
        assertEquals(items.get(1).getResource().getId(), "sports:role.readers");
        assertEquals(items.get(1).getResource().getProperties().get("rbac_granted"), Boolean.TRUE);
        assertEquals(items.get(3).getSubject().getId(), "client.svc");
        assertFalse(items.get(3).getResource().getProperties().containsKey("rbac_granted"));
        assertEquals(items.get(4).getAction().getName(), "zts.jag_exchange");
        assertEquals(items.get(4).getResource().getType(), AuthZenRequestBuilder.RESOURCE_ATHENZ);

        assertEquals(evaluation().getCandidates().get("subject").get("sports"), Set.of("readers", "writers"));
    }

    @Test
    public void testDecide() throws ExternalPdpException {
        Map<String, Object> gateContext = new HashMap<>();
        gateContext.put("claims", Map.of("tier", "gold"));
        gateContext.put("max_expires_in", 900);
        gateContext.put("reason_admin", "ok");
        ExternalPdpDecision decision = evaluation().decide(response(gateContext, true, true, false, true, true, true));
        assertTrue(decision.isGatePermitted());
        assertEquals(decision.getPermittedRoles("subject", "sports"), Set.of("readers"));
        assertEquals(decision.getPermittedRoles("client", "sports"), Set.of("readers"));
        assertTrue(decision.getPermittedRoles("client", "weather").isEmpty());
        assertTrue(decision.getPermittedRoles("unknown", "sports").isEmpty());
        assertEquals(decision.getPermittedRoles().size(), 2);
        assertTrue(decision.isPermissionGranted("target"));
        assertTrue(decision.isPermissionGranted("none"));
        assertEquals(decision.getClaims(), Map.of("tier", "gold"));
        assertFalse(decision.isClaimsMalformed());
        assertEquals(decision.getMaxExpiresIn(), Integer.valueOf(900));
        assertEquals(decision.getReasons().size(), 1);
        assertFalse(decision.isFailOpen());

        decision = evaluation().decide(response(null, false, false, false, false, true, false));
        assertFalse(decision.isGatePermitted());
        assertTrue(decision.getPermittedRoles("subject", "sports").isEmpty());
        assertFalse(decision.isPermissionGranted("target"));
        assertNull(decision.getClaims());
        assertNull(decision.getMaxExpiresIn());
        assertTrue(decision.getReasons().isEmpty());

        // user reasons are kept on their own and together with admin reasons
        Map<String, Object> userOnly = Map.of("reason_user", "mfa required");
        decision = evaluation().decide(response(userOnly, true, true, false, true, true, true));
        assertEquals(decision.getReasons(), List.of(Map.of("index", 0, "reason_user", "mfa required")));
        Map<String, Object> both = Map.of("reason_admin", "policy-7", "reason_user", "mfa required");
        decision = evaluation().decide(response(both, true, true, false, true, true, true));
        assertEquals(decision.getReasons(),
                List.of(Map.of("index", 0, "reason_admin", "policy-7", "reason_user", "mfa required")));
    }

    @Test
    public void testDecideGateContextValidation() throws ExternalPdpException {
        Map<String, Object> gateContext = new HashMap<>();
        gateContext.put("claims", "not-an-object");
        gateContext.put("max_expires_in", "900");
        ExternalPdpDecision decision = evaluation().decide(response(gateContext, true, true, true, true, true, true));
        assertTrue(decision.isClaimsMalformed());
        assertNull(decision.getClaims());
        assertNull(decision.getMaxExpiresIn());

        gateContext.put("max_expires_in", -5);
        assertNull(evaluation().decide(response(gateContext, true, true, true, true, true, true)).getMaxExpiresIn());
        gateContext.put("max_expires_in", 1.5);
        assertNull(evaluation().decide(response(gateContext, true, true, true, true, true, true)).getMaxExpiresIn());
        gateContext.put("max_expires_in", 10_000_000_000L);
        assertEquals(evaluation().decide(response(gateContext, true, true, true, true, true, true)).getMaxExpiresIn(),
                Integer.valueOf(Integer.MAX_VALUE));
    }

    @Test
    public void testDecideSizeMismatch() {
        ExternalPdpException ex = expectThrows(ExternalPdpException.class,
                () -> evaluation().decide(response(null, true, true)));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
        ex = expectThrows(ExternalPdpException.class, () -> evaluation().decide(new EvaluationsResponse(null)));
        assertEquals(ex.getCode(), ExternalPdpException.Code.INVALID_RESPONSE);
    }

    @Test
    public void testFailOpen() {
        ExternalPdpDecision decision = evaluation().failOpen(120);
        assertTrue(decision.isFailOpen());
        assertTrue(decision.isGatePermitted());
        assertEquals(decision.getPermittedRoles("subject", "sports"), Set.of("readers", "writers"));
        assertTrue(decision.isPermissionGranted("target"));
        assertEquals(decision.getMaxExpiresIn(), Integer.valueOf(120));
        assertNull(decision.getClaims());
    }
}
