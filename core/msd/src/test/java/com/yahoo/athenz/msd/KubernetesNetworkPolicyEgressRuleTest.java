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

public class KubernetesNetworkPolicyEgressRuleTest {

    @Test
    public void testMethods() {

        KubernetesNetworkPolicyEgressRule egressRule1 = new KubernetesNetworkPolicyEgressRule();
        egressRule1.setTo(null);
        egressRule1.setPorts(null);
        assertNull(egressRule1.getTo());
        assertNull(egressRule1.getPorts());

        KubernetesNetworkPolicyEgressRule egressRule2 = new KubernetesNetworkPolicyEgressRule();
        egressRule2.setTo(null);
        egressRule2.setPorts(null);

        assertEquals(egressRule1, egressRule2);
        assertFalse(egressRule1.equals("abc"));

        egressRule2.setTo(new ArrayList<>());
        assertNotEquals(egressRule1, egressRule2);

        egressRule2.setTo(null);
        egressRule2.setPorts(new ArrayList<>());
        assertNotEquals(egressRule1, egressRule2);
    }
}