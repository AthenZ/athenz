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

public class TransportPolicyValidationRequestTest {

    @Test
    public void testTransportPolicyValidationRequest() {
        TransportPolicySubject tps1 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
        List<TransportPolicySubject> tpsList1 = Collections.singletonList(tps1);

        TransportPolicyPort tpp1 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
        List<TransportPolicyPort> tppList1 = Collections.singletonList(tpp1);

        TransportPolicyPeer tppeer1 = new TransportPolicyPeer().setAthenzServices(tpsList1).setPorts(tppList1);

        TransportPolicyCondition tpc1 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE);
        tpc1.setInstances(Collections.singletonList("host1"));
        List<TransportPolicyCondition> tpcList1 = Collections.singletonList(tpc1);
        TransportPolicyMatch tpm1 = new TransportPolicyMatch().setAthenzService(tps1).setConditions(tpcList1);

        TransportPolicyEntitySelector tpes1 = new TransportPolicyEntitySelector().setPorts(Collections.singletonList(tpp1)).setMatch(tpm1);

        TransportPolicySubject tps2 = new TransportPolicySubject().setDomainName("dom2").setServiceName("svc2");
        List<TransportPolicySubject> tpsList2 = Collections.singletonList(tps2);

        TransportPolicyPort tpp2 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
        List<TransportPolicyPort> tppList2 = Collections.singletonList(tpp2);

        TransportPolicyPeer tppeer2 = new TransportPolicyPeer().setAthenzServices(tpsList2).setPorts(tppList2);
        TransportPolicyCondition tpc2 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE);
        tpc1.setInstances(Collections.singletonList("host2"));
        List<TransportPolicyCondition> tpcList2 = Collections.singletonList(tpc2);
        TransportPolicyMatch tpm2 = new TransportPolicyMatch().setAthenzService(tps1).setConditions(tpcList2);
        TransportPolicyEntitySelector tpes2 = new TransportPolicyEntitySelector().setPorts(Collections.singletonList(tpp2)).setMatch(tpm2);
        long id1 = 1;
        long id2 = 2;

        TransportPolicyValidationRequest tpvr1 = new TransportPolicyValidationRequest().setTrafficDirection(TransportPolicyTrafficDirection.EGRESS).setPeer(tppeer1).setEntitySelector(tpes1).setId(id1);
        assertEquals(tpvr1.getEntitySelector(), tpes1);
        assertEquals(tpvr1.getPeer(), tppeer1);
        assertEquals(tpvr1.getTrafficDirection(), TransportPolicyTrafficDirection.EGRESS);
        assertEquals((long)tpvr1.getId(), id1);

        TransportPolicyValidationRequest tpvr2 = new TransportPolicyValidationRequest().setTrafficDirection(TransportPolicyTrafficDirection.EGRESS).setPeer(tppeer1).setEntitySelector(tpes1).setId(id1);
        assertTrue(tpvr2.equals(tpvr1));

        tpvr2.setTrafficDirection(TransportPolicyTrafficDirection.INGRESS);
        assertFalse(tpvr2.equals(tpvr1));
        tpvr2.setTrafficDirection(TransportPolicyTrafficDirection.EGRESS);

        tpvr2.setId(id2);
        assertFalse(tpvr2.equals(tpvr1));
        tpvr2.setId(id1);

        tpvr2.setPeer(null);
        assertFalse(tpvr2.equals(tpvr1));
        tpvr2.setPeer(tppeer1);

        tpvr2.setEntitySelector(tpes2);
        assertFalse(tpvr2.equals(tpvr1));
        tpvr2.setEntitySelector(tpes1);

        assertFalse(tpvr1.equals("abc"));
        assertTrue(tpvr1.equals(tpvr1));
    }

}
