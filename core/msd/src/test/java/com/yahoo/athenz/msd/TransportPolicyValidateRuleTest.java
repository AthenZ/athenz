/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.msd;

import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;
import static org.testng.Assert.assertFalse;

public class TransportPolicyValidateRuleTest {

    @Test
    public void testTransportPolicyValidateRule() {
        TransportPolicySubject tps1 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
        List<TransportPolicySubject> tpsList1 = Collections.singletonList(tps1);

        TransportPolicyPort tpp1 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
        List<TransportPolicyPort> tppList1 = Collections.singletonList(tpp1);

        TransportPolicyPeer tppeer1 = new TransportPolicyPeer().setAthenzServices(tpsList1).setPorts(tppList1);

        List<String> instances = new ArrayList<String>();
        instances.add("instance1");
        instances.add("instances2");

        TransportPolicySubject tps2 = new TransportPolicySubject().setDomainName("dom2").setServiceName("svc2");
        List<TransportPolicySubject> tpsList2 = Collections.singletonList(tps2);

        TransportPolicyPort tpp2 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
        List<TransportPolicyPort> tppList2 = Collections.singletonList(tpp2);

        TransportPolicyPeer tppeer2 = new TransportPolicyPeer().setAthenzServices(tpsList2).setPorts(tppList2);

        TransportPolicyValidateRule tpvr1 = new TransportPolicyValidateRule().setDestination(Collections.singletonList(tppeer1)).setInstances(instances).setSource(Collections.singletonList(tppeer2)).setTrafficDirection(TransportPolicyTrafficDirection.EGRESS);
        assertEquals(tpvr1.getDestination(), Collections.singletonList(tppeer1));
        assertEquals(tpvr1.getInstances(), instances);
        assertEquals(tpvr1.getSource(), Collections.singletonList(tppeer2));
        assertEquals(tpvr1.getTrafficDirection(), TransportPolicyTrafficDirection.EGRESS);

        TransportPolicyValidateRule tpvr2 = new TransportPolicyValidateRule().setDestination(Collections.singletonList(tppeer1)).setInstances(instances).setSource(Collections.singletonList(tppeer2)).setTrafficDirection(TransportPolicyTrafficDirection.EGRESS);
        assertTrue(tpvr2.equals(tpvr1));

        tpvr2.setTrafficDirection(TransportPolicyTrafficDirection.INGRESS);
        assertFalse(tpvr2.equals(tpvr1));
        tpvr2.setTrafficDirection(TransportPolicyTrafficDirection.EGRESS);

        tpvr2.setInstances(null);
        assertFalse(tpvr2.equals(tpvr1));
        tpvr2.setInstances(instances);

        tpvr2.setDestination(Collections.singletonList(tppeer2));
        assertFalse(tpvr2.equals(tpvr1));
        tpvr2.setDestination(Collections.singletonList(tppeer1));

        tpvr2.setSource(Collections.singletonList(tppeer1));
        assertFalse(tpvr2.equals(tpvr1));
        tpvr2.setSource(Collections.singletonList(tppeer2));

        assertFalse(tpvr1.equals("abc"));
        assertTrue(tpvr1.equals(tpvr1));
    }

}
