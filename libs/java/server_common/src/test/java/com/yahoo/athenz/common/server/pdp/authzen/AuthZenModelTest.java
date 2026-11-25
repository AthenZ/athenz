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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;

public class AuthZenModelTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void testEvaluationsRequestSerialization() throws Exception {
        Map<String, Object> props = new HashMap<>();
        props.put("domain", "sports");
        EvaluationsRequest request = new EvaluationsRequest(
                new Subject("service", "sports.api", props),
                new Action("assume_role", null),
                null,
                Collections.singletonMap("request_id", "id-1"),
                List.of(new EvaluationRequest(null, null, new Resource("athenz_role", "sports:role.readers", null), null)),
                new EvaluationsOptions(EvaluationsOptions.EXECUTE_ALL));

        final String json = MAPPER.writeValueAsString(request);
        assertEquals(json, "{\"subject\":{\"type\":\"service\",\"id\":\"sports.api\",\"properties\":{\"domain\":\"sports\"}},"
                + "\"action\":{\"name\":\"assume_role\"},\"context\":{\"request_id\":\"id-1\"},"
                + "\"evaluations\":[{\"resource\":{\"type\":\"athenz_role\",\"id\":\"sports:role.readers\"}}],"
                + "\"options\":{\"evaluations_semantic\":\"execute_all\"}}");

        EvaluationsRequest parsed = MAPPER.readValue(json, EvaluationsRequest.class);
        assertEquals(parsed.getSubject().getType(), "service");
        assertEquals(parsed.getSubject().getId(), "sports.api");
        assertEquals(parsed.getSubject().getProperties().get("domain"), "sports");
        assertEquals(parsed.getAction().getName(), "assume_role");
        assertNull(parsed.getAction().getProperties());
        assertNull(parsed.getResource());
        assertEquals(parsed.getContext().get("request_id"), "id-1");
        assertEquals(parsed.getEvaluations().get(0).getResource().getId(), "sports:role.readers");
        assertNull(parsed.getEvaluations().get(0).getSubject());
        assertNull(parsed.getEvaluations().get(0).getAction());
        assertNull(parsed.getEvaluations().get(0).getContext());
        assertNull(parsed.getEvaluations().get(0).getResource().getProperties());
        assertEquals(parsed.getOptions().getEvaluationsSemantic(), EvaluationsOptions.EXECUTE_ALL);
    }

    @Test
    public void testDefensiveCopies() {
        Map<String, Object> props = new HashMap<>();
        props.put("a", "b");
        Subject subject = new Subject("user", "user.joe", props);
        props.put("c", "d");
        assertEquals(subject.getProperties().size(), 1);
        assertThrows(UnsupportedOperationException.class, () -> subject.getProperties().put("x", "y"));

        List<EvaluationResponse> results = new java.util.ArrayList<>();
        results.add(new EvaluationResponse(true, null));
        EvaluationsResponse response = new EvaluationsResponse(results);
        results.add(new EvaluationResponse(false, null));
        assertEquals(response.getEvaluations().size(), 1);
        assertThrows(UnsupportedOperationException.class, () -> response.getEvaluations().clear());

        assertNull(new EvaluationsResponse(null).getEvaluations());
        assertNull(new Subject("user", "user.joe", null).getProperties());
    }

    @Test
    public void testEvaluationResponseDecision() throws Exception {
        EvaluationsResponse response = MAPPER.readValue("{\"evaluations\":[{\"decision\":true,"
                + "\"context\":{\"max_expires_in\":900}},{\"decision\":false},{},{\"decision\":\"true\"},"
                + "{\"decision\":1}]}", EvaluationsResponse.class);
        List<EvaluationResponse> results = response.getEvaluations();
        assertTrue(results.get(0).getDecision());
        assertEquals(results.get(0).getContext().get("max_expires_in"), 900);
        assertFalse(results.get(1).getDecision());
        assertNull(results.get(1).getContext());
        assertFalse(results.get(2).getDecision());
        assertFalse(results.get(3).getDecision());
        assertFalse(results.get(4).getDecision());

        assertEquals(MAPPER.writeValueAsString(new EvaluationResponse(false, null)), "{\"decision\":false}");
    }

    @Test
    public void testExtensionsPreserved() throws Exception {
        EvaluationResponse response = MAPPER.readValue("{\"decision\":true,\"vendor_trace\":\"abc\"}",
                EvaluationResponse.class);
        assertEquals(response.getExtensions().get("vendor_trace"), "abc");
        assertThrows(UnsupportedOperationException.class, () -> response.getExtensions().put("x", "y"));
        assertEquals(MAPPER.writeValueAsString(response), "{\"decision\":true,\"vendor_trace\":\"abc\"}");

        Subject subject = MAPPER.readValue("{\"type\":\"user\",\"id\":\"user.joe\",\"extra\":{\"k\":1}}", Subject.class);
        assertEquals(((Map<?, ?>) subject.getExtensions().get("extra")).get("k"), 1);
    }

    @Test
    public void testSingleEvaluationRequest() throws Exception {
        EvaluationRequest request = new EvaluationRequest(new Subject("user", "user.joe", null),
                new Action("issue_token", Collections.singletonMap("k", "v")),
                new Resource("athenz_token", "sports", Collections.singletonMap("token_type", "access_token")),
                Collections.singletonMap("mode", "FILTER"));
        EvaluationRequest parsed = MAPPER.readValue(MAPPER.writeValueAsString(request), EvaluationRequest.class);
        assertEquals(parsed.getSubject().getId(), "user.joe");
        assertEquals(parsed.getAction().getProperties().get("k"), "v");
        assertEquals(parsed.getResource().getType(), "athenz_token");
        assertEquals(parsed.getResource().getProperties().get("token_type"), "access_token");
        assertEquals(parsed.getContext().get("mode"), "FILTER");
    }
}
