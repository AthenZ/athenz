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
package com.yahoo.athenz.msd;
import org.testng.annotations.Test;

import java.util.Map;

import static org.testng.Assert.*;

public class KubernetesNetworkPolicyRequestTest {

    @Test
    public void testMethods() {
        KubernetesNetworkPolicyRequest req1 = new KubernetesNetworkPolicyRequest();
        req1.setAthenzDomainLabel("athenz");
        req1.setAthenzServiceLabel("api");
        req1.setNetworkPolicyType("kubernetes");
        req1.setNetworkPolicyNamespace("myns");
        req1.setDomainLabelAsNamespaceSelector(true);
        req1.setDomainInServiceLabel(true);
        req1.setRequestedApiVersion("v1");

        KubernetesNetworkPolicyRequest req2 = new KubernetesNetworkPolicyRequest();
        req2.setAthenzDomainLabel("athenz");
        req2.setAthenzServiceLabel("api");
        req2.setNetworkPolicyType("kubernetes");
        req2.setNetworkPolicyNamespace("myns");
        req2.setDomainLabelAsNamespaceSelector(true);
        req2.setDomainInServiceLabel(true);
        req2.setRequestedApiVersion("v1");

        assertEquals(req1, req2);
        assertFalse(req1.equals("abc"));

        assertEquals(req1.getAthenzDomainLabel(), "athenz");
        assertEquals(req1.getAthenzServiceLabel(), "api");
        assertEquals(req1.getNetworkPolicyType(), "kubernetes");
        assertEquals(req1.getNetworkPolicyNamespace(), "myns");
        assertTrue(req1.getDomainInServiceLabel());
        assertTrue(req1.getDomainLabelAsNamespaceSelector());
        assertEquals(req1.getRequestedApiVersion(), "v1");

        req2.setAthenzDomainLabel("athenz2");
        assertNotEquals(req1, req2);

        req2.setAthenzDomainLabel("athenz");
        req2.setAthenzServiceLabel("api2");
        assertNotEquals(req1, req2);

        req2.setAthenzServiceLabel("api");
        req2.setNetworkPolicyType("cilium");
        assertNotEquals(req1, req2);

        req2.setNetworkPolicyType("kubernetes");
        req2.setNetworkPolicyNamespace("myns2");
        assertNotEquals(req1, req2);

        req2.setNetworkPolicyNamespace("myns");
        req2.setDomainInServiceLabel(false);
        assertNotEquals(req1, req2);

        req2.setDomainInServiceLabel(true);
        req2.setRequestedApiVersion("v2");
        assertNotEquals(req1, req2);

        req2.setRequestedApiVersion("v1");
        req2.setDomainLabelAsNamespaceSelector(false);
        assertNotEquals(req1, req2);
    }
}