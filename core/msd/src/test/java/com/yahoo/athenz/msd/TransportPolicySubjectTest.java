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

public class TransportPolicySubjectTest {

  @Test
  public void testTransportPolicySubjectFields() {

    TransportPolicySubject tps1 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1").setExternalPeer("ext1");
    assertFalse(tps1.equals("xyz"));
    assertEquals(tps1, tps1);

    TransportPolicySubject tps2 = new TransportPolicySubject().setDomainName("dom1").setServiceName("svc1").setExternalPeer("ext1");
    assertEquals(tps1,tps2);

    tps2.setServiceName(null);
    assertNotEquals(tps1, tps2);

    tps2.setServiceName("svc1");
    tps2.setDomainName(null);
    assertNotEquals(tps1, tps2);

    tps2.setDomainName("dom1");
    tps2.setExternalPeer(null);
    assertNotEquals(tps1, tps2);

    assertEquals(tps1.getDomainName(), "dom1");
    assertEquals(tps1.getServiceName(), "svc1");
    assertEquals(tps1.getExternalPeer(), "ext1");

  }
}