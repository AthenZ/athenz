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

import java.util.ArrayList;

import static org.testng.Assert.*;

public class KubernetesNetworkPolicyIngressRuleTest {

    @Test
    public void testMethods() {
        KubernetesNetworkPolicyIngressRule ingressRule1 = new KubernetesNetworkPolicyIngressRule();
        ingressRule1.setFrom(null);
        ingressRule1.setPorts(null);
        assertNull(ingressRule1.getFrom());
        assertNull(ingressRule1.getPorts());

        KubernetesNetworkPolicyIngressRule ingressRule2 = new KubernetesNetworkPolicyIngressRule();
        ingressRule2.setFrom(null);
        ingressRule2.setPorts(null);

        assertEquals(ingressRule1, ingressRule2);
        assertFalse(ingressRule1.equals("abc"));

        ingressRule2.setFrom(new ArrayList<>());
        assertNotEquals(ingressRule1, ingressRule2);

        ingressRule2.setFrom(null);
        ingressRule2.setPorts(new ArrayList<>());
        assertNotEquals(ingressRule1, ingressRule2);
    }
}