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

public class TransportPolicyPortTest {

  @Test
  public void testTransportPolicyPortFields() {
    TransportPolicyPort tpp1 = new TransportPolicyPort().setPort(1024).setEndPort(65535).setProtocol(TransportPolicyProtocol.TCP);
    assertEquals(tpp1.getPort(), 1024);
    assertEquals(tpp1.getEndPort(), 65535);
    assertEquals(tpp1.getProtocol(), TransportPolicyProtocol.TCP);

    TransportPolicyPort tpp2 = new TransportPolicyPort().setPort(1024).setEndPort(65535).setProtocol(TransportPolicyProtocol.TCP);
    assertEquals(tpp1, tpp2);

    assertEquals(tpp1, tpp1);

    tpp2.setPort(1030);
    assertFalse(tpp1.equals(tpp2));

    tpp2.setPort(1024);
    tpp2.setEndPort(10000);
    assertFalse(tpp1.equals(tpp2));

    tpp2.setEndPort(65535);
    tpp2.setProtocol(null);
    assertNotEquals(tpp1, tpp2);

    tpp2.setProtocol(TransportPolicyProtocol.UDP);
    assertNotEquals(tpp1, tpp2);

    tpp2.setProtocol(TransportPolicyProtocol.TCP);
    assertEquals(tpp1, tpp2);


    assertFalse(tpp1.equals("xyz"));
  }
}