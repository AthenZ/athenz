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

import com.yahoo.rdl.Timestamp;
import java.util.Collections;
import java.util.List;
import org.testng.annotations.Test;

public class TransportPolicyIngressRuleTest {

  @Test
  public void testTransportPolicyIngressRuleFields() {

    TransportPolicyPort tpp1 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
    List<TransportPolicyPort> tppList1 = Collections.singletonList(tpp1);
    TransportPolicySubject tps1 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
    TransportPolicyCondition tpc1 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE);
    tpc1.setInstances(Collections.singletonList("host1"));
    List<TransportPolicyCondition> tpcList1 = Collections.singletonList(tpc1);
    TransportPolicyMatch tpm1 = new TransportPolicyMatch().setAthenzService(tps1).setConditions(tpcList1);

    TransportPolicyEntitySelector tpes1 = new TransportPolicyEntitySelector().setPorts(tppList1).setMatch(tpm1);

    List<TransportPolicySubject> tpsList1 = Collections.singletonList(tps1);
    TransportPolicyPeer tppeer1 = new TransportPolicyPeer().setAthenzServices(tpsList1).setPorts(tppList1);

    TransportPolicyIngressRule tpir1 = new TransportPolicyIngressRule().setEntitySelector(tpes1).setFrom(tppeer1).setId(12345678L).setLastModified(
        Timestamp.fromMillis(123456789123L));

    assertEquals(tpir1.getEntitySelector(), tpes1);
    assertEquals(tpir1.getFrom(), tppeer1);
    assertEquals(tpir1.getId(), 12345678L);
    assertEquals(tpir1.getLastModified(), Timestamp.fromMillis(123456789123L));


    TransportPolicyPort tpp2 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
    List<TransportPolicyPort> tppList2 = Collections.singletonList(tpp2);
    TransportPolicySubject tps2 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
    TransportPolicyCondition tpc2 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE);
    tpc2.setInstances(Collections.singletonList("host1"));
    List<TransportPolicyCondition> tpcList2 = Collections.singletonList(tpc2);
    TransportPolicyMatch tpm2 = new TransportPolicyMatch().setAthenzService(tps2).setConditions(tpcList2);

    TransportPolicyEntitySelector tpes2 = new TransportPolicyEntitySelector().setPorts(tppList2).setMatch(tpm2);

    List<TransportPolicySubject> tpsList2 = Collections.singletonList(tps2);
    TransportPolicyPeer tppeer2 = new TransportPolicyPeer().setAthenzServices(tpsList2).setPorts(tppList2);

    TransportPolicyIngressRule tpir2 = new TransportPolicyIngressRule().setEntitySelector(tpes2).setFrom(tppeer2).setId(12345678L).setLastModified(
        Timestamp.fromMillis(123456789123L));

    assertEquals(tpir1, tpir1);
    assertEquals(tpir1, tpir2);

    tpir2.setFrom(null);
    assertNotEquals(tpir1, tpir2);

    tpir2.setFrom(tppeer2);
    tpir2.setEntitySelector(null);
    assertNotEquals(tpir1, tpir2);

    tpir2.setEntitySelector(tpes2);
    tpir2.setId(234567L);
    assertNotEquals(tpir1, tpir2);

    tpir2.setId(12345678L);
    tpir2.setLastModified(null);
    assertNotEquals(tpir1, tpir2);


    assertFalse(tpir1.equals("xyz"));
  }
}