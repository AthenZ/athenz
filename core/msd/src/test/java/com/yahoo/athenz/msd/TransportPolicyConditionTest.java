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

public class TransportPolicyConditionTest {

  @Test
  public void testTransportPolicyConditionFields() {
    TransportPolicyCondition tpc1 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE);
    List<String> tpci1 = Collections.singletonList("host1");
    tpc1.setInstances(tpci1);
    List<TransportPolicySubjectSelectorRequirement> additionalConditions =
            Collections.singletonList(new TransportPolicySubjectSelectorRequirement()
                    .setKey("key1").setOperator("EQ").setValue("value1"));
    tpc1.setAdditionalConditions(additionalConditions);
    assertEquals(tpc1, tpc1);
    assertFalse(tpc1.equals("xyz"));
    assertEquals(tpc1.getEnforcementState(), TransportPolicyEnforcementState.ENFORCE);
    assertEquals(tpc1.getInstances(), tpci1);
    assertEquals(tpc1.getAdditionalConditions(), additionalConditions);

    TransportPolicyCondition tpc2 = new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE);
    List<String> tpci2 = Collections.singletonList("host1");
    tpc2.setInstances(tpci2);
    List<TransportPolicySubjectSelectorRequirement> additionalConditions2 =
            Collections.singletonList(new TransportPolicySubjectSelectorRequirement()
                    .setKey("key1").setOperator("EQ").setValue("value1"));
    tpc2.setAdditionalConditions(additionalConditions2);

    assertEquals(tpc1, tpc2);

    tpc2.setEnforcementState(null);
    assertNotEquals(tpc1, tpc2);

    tpc2.setEnforcementState(TransportPolicyEnforcementState.ENFORCE);
    tpc2.setInstances(null);
    assertNotEquals(tpc1, tpc2);

    tpc2.setInstances(tpci2);
    tpc2.setAdditionalConditions(null);
    assertNotEquals(tpc1, tpc2);

  }
}