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

public class NetworkPolicyPortsTest {

    @Test
    public void testFields() {

        NetworkPolicyPort pd = new NetworkPolicyPort()
                .setPort(443).setEndPort(443)
                .setProtocol(TransportPolicyProtocol.TCP);

        NetworkPolicyPort ps = new NetworkPolicyPort()
                .setPort(1024).setEndPort(65535)
                .setProtocol(TransportPolicyProtocol.TCP);

        NetworkPolicyPorts ports1 = new NetworkPolicyPorts().setDestinationPorts(Collections.singletonList(pd))
                .setSourcePorts(Collections.singletonList(ps));

        NetworkPolicyPorts ports2 = new NetworkPolicyPorts().setDestinationPorts(Collections.singletonList(pd))
                .setSourcePorts(Collections.singletonList(ps));

        assertEquals(ports1, ports2);
        assertEquals(ports1, ports1);
        assertFalse(ports1.equals("abc"));

        assertEquals(ports1.getSourcePorts(), Collections.singletonList(ps));
        assertEquals(ports1.getDestinationPorts(), Collections.singletonList(pd));

        ports2.setSourcePorts(null);
        assertNotEquals(ports1, ports2);

        ports2.setSourcePorts(Collections.singletonList(ps));
        ports2.setDestinationPorts(null);
        assertNotEquals(ports1, ports2);
    }

}