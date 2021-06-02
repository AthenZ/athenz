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

import org.testng.annotations.Test;

public class TransportPolicyEnforcementStateTest {

  @Test
  public void transportPolicyEnforcementStateTest() {
    TransportPolicyEnforcementState td1 = TransportPolicyEnforcementState.ENFORCE;
    assertTrue(td1 == td1);
    assertFalse(td1.equals("abc"));

    TransportPolicyEnforcementState td2 = TransportPolicyEnforcementState.REPORT;
    assertFalse(td1 == td2);

    td2 = TransportPolicyEnforcementState.ENFORCE;
    assertEquals(td1, td2);

    assertEquals(TransportPolicyEnforcementState.fromString("REPORT"), TransportPolicyEnforcementState.REPORT);

    try {
      TransportPolicyEnforcementState.fromString("XYZ");
    } catch (Exception ignored) {
    }
  }
}