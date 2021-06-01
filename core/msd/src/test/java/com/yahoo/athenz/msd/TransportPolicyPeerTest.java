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

public class TransportPolicyPeerTest {

  @Test
  public void testTransportPolicyPeerFields() {

    TransportPolicySubject tps1 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
    List<TransportPolicySubject> tpsList1 = Collections.singletonList(tps1);

    TransportPolicyPort tpp1 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
    List<TransportPolicyPort> tppList1 = Collections.singletonList(tpp1);

    TransportPolicyPeer tppeer1 = new TransportPolicyPeer().setAthenzServices(tpsList1).setPorts(tppList1);

    assertEquals(tppeer1.getAthenzServices(), tpsList1);
    assertEquals(tppeer1.getPorts(), tppList1);

    TransportPolicySubject tps2 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1");
    List<TransportPolicySubject> tpsList2 = Collections.singletonList(tps2);

    TransportPolicyPort tpp2 = new TransportPolicyPort().setProtocol(TransportPolicyProtocol.TCP).setPort(1).setEndPort(1024);
    List<TransportPolicyPort> tppList2 = Collections.singletonList(tpp2);

    TransportPolicyPeer tppeer2 = new TransportPolicyPeer().setAthenzServices(tpsList2).setPorts(tppList2);

    assertEquals(tppeer1, tppeer2);

    tppeer2.setPorts(null);
    assertNotEquals(tppeer1, tppeer2);

    tppeer2.setPorts(tppList2);
    tppeer2.setAthenzServices(null);
    assertNotEquals(tppeer1, tppeer2);

    assertFalse(tppeer1.equals("xyz"));
  }
}