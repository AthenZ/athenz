/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yahoo.athenz.zts.external.gcp;

import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class GcpAccessTokenRequestTest {

    @Test
    public void testGcpAccessTokenRequest() {

        GcpAccessTokenRequest request = new GcpAccessTokenRequest();
        request.setLifetime("300s");
        request.setScope(Collections.singletonList("scope"));

        assertEquals(request.getScope(), Collections.singletonList("scope"));
        assertEquals(request.getLifetime(), "300s");

        request.setLifetimeSeconds(1800);
        assertEquals(request.getLifetime(), "1800s");

        request.setScopeList("scope1 scope2   scope3");
        List<String> scopes = request.getScope();
        assertEquals(3, scopes.size());
        assertTrue(scopes.contains("scope1"));
        assertTrue(scopes.contains("scope2"));
        assertTrue(scopes.contains("scope3"));
    }
}
