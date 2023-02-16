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

public class TransportPolicyMatchTest {

  @Test
  public void testTransportPolicyMatchFields() {
    TransportPolicySubject tps1 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
    TransportPolicyCondition tpc1 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE).setScope(Collections.singletonList(TransportPolicyScope.ONPREM));
    tpc1.setInstances(Collections.singletonList("host1"));
    List<TransportPolicyCondition> tpcList1 = Collections.singletonList(tpc1);
    TransportPolicyMatch tpm1 = new TransportPolicyMatch().setAthenzService(tps1).setConditions(tpcList1);
    TransportPolicySubject tps2 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
    TransportPolicyCondition tpc2 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE).setScope(Collections.singletonList(TransportPolicyScope.ONPREM));
    tpc2.setInstances(Collections.singletonList("host1"));
    TransportPolicyMatch tpm2 = new TransportPolicyMatch().setAthenzService(tps2).setConditions(Collections.singletonList(tpc2));

    assertEquals(tpm1.getAthenzService(), tps1);
    assertEquals(tpm1.getConditions(), tpcList1);

    assertEquals(tpm1, tpm2);

    tpm2.setAthenzService(null);
    assertNotEquals(tpm1, tpm2);

    tpm2.setAthenzService(tps2);
    tpm2.setConditions(null);
    assertNotEquals(tpm1, tpm2);

    tpm2.setConditions(Collections.singletonList(tpc2));
    assertEquals(tpm1, tpm2);
    tpc2.setScope(Collections.singletonList(TransportPolicyScope.AWS));
    assertNotEquals(tpm1, tpm2);
    tpc2.setScope(null);
    assertNotEquals(tpm1, tpm2);
    tpc2.setScope(Collections.singletonList(TransportPolicyScope.ONPREM));
    assertEquals(tpm1, tpm2);
    tpc2.setScope(List.of(TransportPolicyScope.ONPREM, TransportPolicyScope.AWS));
    assertNotEquals(tpm1, tpm2);
    tpc1.setScope(List.of(TransportPolicyScope.ONPREM, TransportPolicyScope.AWS));
    assertEquals(tpm1, tpm2);

    assertNotEquals(tpm1.getConditions().get(0).getScope(), null);

    assertFalse(tpm1.equals("xyz"));
  }
}