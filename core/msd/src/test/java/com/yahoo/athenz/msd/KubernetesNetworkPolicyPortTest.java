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

import static org.testng.Assert.*;

public class KubernetesNetworkPolicyPortTest {

    @Test
    public void testMethods() {
        KubernetesNetworkPolicyPort policyPort1 = new KubernetesNetworkPolicyPort();
        policyPort1.setPort(8080);
        policyPort1.setEndPort(8081);
        policyPort1.setProtocol(TransportPolicyProtocol.TCP);
        assertEquals(policyPort1.getPort(), 8080);
        assertEquals(policyPort1.getEndPort(), 8081);
        assertEquals(policyPort1.getProtocol(), TransportPolicyProtocol.TCP);

        KubernetesNetworkPolicyPort policyPort2 = new KubernetesNetworkPolicyPort();
        policyPort2.setPort(8080);
        policyPort2.setEndPort(8081);
        policyPort2.setProtocol(TransportPolicyProtocol.TCP);

        assertEquals(policyPort1, policyPort2);
        assertFalse(policyPort1.equals("abc"));

        policyPort2.setPort(8081);
        assertNotEquals(policyPort1, policyPort2);

        policyPort2.setPort(8080);
        policyPort2.setEndPort(8082);
        assertNotEquals(policyPort1, policyPort2);

        policyPort2.setEndPort(8081);
        policyPort2.setProtocol(TransportPolicyProtocol.UDP);
        assertNotEquals(policyPort1, policyPort2);
    }
}