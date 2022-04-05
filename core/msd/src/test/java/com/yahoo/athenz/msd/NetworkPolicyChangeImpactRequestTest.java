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

package com.yahoo.athenz.msd;

import org.testng.annotations.Test;

import java.util.Collections;

import static org.testng.Assert.*;

public class NetworkPolicyChangeImpactRequestTest {

    @Test
    public void testFields() {

        NetworkPolicyPort pd = new NetworkPolicyPort()
                .setPort(443).setEndPort(443)
                .setProtocol(TransportPolicyProtocol.TCP);

        NetworkPolicyPort ps = new NetworkPolicyPort()
                .setPort(1024).setEndPort(65535)
                .setProtocol(TransportPolicyProtocol.TCP);

        IPBlock ipbt = new IPBlock().setCidr("10.0.0.1/16");
        IPBlock ipbf = new IPBlock().setCidr("10.1.0.1/16");

        NetworkPolicyPorts ports = new NetworkPolicyPorts().setDestinationPorts(Collections.singletonList(pd))
                .setSourcePorts(Collections.singletonList(ps));

        NetworkPolicyChangeImpactRequest o1 = new NetworkPolicyChangeImpactRequest()
                .setTo(Collections.singletonList(ipbt))
                .setFrom(Collections.singletonList(ipbf))
                .setPorts(Collections.singletonList(ports));

        NetworkPolicyChangeImpactRequest o2 = new NetworkPolicyChangeImpactRequest()
                .setTo(Collections.singletonList(ipbt))
                .setFrom(Collections.singletonList(ipbf))
                .setPorts(Collections.singletonList(ports));

        assertEquals(o1, o2);
        assertEquals(o1, o1);
        assertFalse(o1.equals("abc"));

        assertEquals(o1.getPorts(), Collections.singletonList(ports));
        assertEquals(o1.getFrom(), Collections.singletonList(ipbf));
        assertEquals(o1.getTo(), Collections.singletonList(ipbt));

        o2.setPorts(null);
        assertNotEquals(o1, o2);

        o2.setPorts(Collections.singletonList(ports));
        o2.setFrom(null);
        assertNotEquals(o1, o2);

        o2.setFrom(Collections.singletonList(ipbf));
        o2.setTo(null);
        assertNotEquals(o1, o2);
    }

}