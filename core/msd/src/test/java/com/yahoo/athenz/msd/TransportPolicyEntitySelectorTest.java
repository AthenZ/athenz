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

import static org.testng.Assert.*;

import java.util.Collections;
import java.util.List;
import org.testng.annotations.Test;

public class TransportPolicyEntitySelectorTest {

  @Test
  public void testTransportPolicyEntitySelectorFields() {

    TransportPolicyPort tpp1 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
    List<TransportPolicyPort> tppList1 = Collections.singletonList(tpp1);
    TransportPolicySubject tps1 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
    TransportPolicyCondition tpc1 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE);
    tpc1.setInstances(Collections.singletonList("host1"));
    List<TransportPolicyCondition> tpcList1 = Collections.singletonList(tpc1);
    TransportPolicyMatch tpm1 = new TransportPolicyMatch().setAthenzService(tps1).setConditions(tpcList1);

    TransportPolicyEntitySelector tpes1 = new TransportPolicyEntitySelector().setPorts(tppList1).setMatch(tpm1);

    assertEquals(tpes1.getMatch(), tpm1);
    assertEquals(tpes1.getPorts(), tppList1);

    TransportPolicyPort tpp2 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
    List<TransportPolicyPort> tppList2 = Collections.singletonList(tpp2);
    TransportPolicySubject tps2 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
    TransportPolicyCondition tpc2 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE);
    tpc2.setInstances(Collections.singletonList("host1"));
    List<TransportPolicyCondition> tpcList2 = Collections.singletonList(tpc2);
    TransportPolicyMatch tpm2 = new TransportPolicyMatch().setAthenzService(tps2).setConditions(tpcList2);

    TransportPolicyEntitySelector tpes2 = new TransportPolicyEntitySelector().setPorts(tppList2).setMatch(tpm2);

    assertEquals(tpes1, tpes2);

    tpes2.setMatch(null);
    assertNotEquals(tpes1, tpes2);

    tpes2.setMatch(tpm2);
    tpes2.setPorts(null);
    assertNotEquals(tpes1, tpes2);

    assertFalse(tpes1.equals("xyz"));
  }
}