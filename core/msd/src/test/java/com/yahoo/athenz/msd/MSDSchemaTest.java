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

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

public class MSDSchemaTest {

  @Test
  public void testMSDSchema() {
    MSDSchema msdSchema = new MSDSchema();
    assertNotNull(msdSchema);
    Schema schema = MSDSchema.instance();
    assertNotNull(schema);
    Validator validator = new Validator(schema);

    TransportPolicySubject tps = new TransportPolicySubject();
    tps.setDomainName("dom1").setServiceName("svc1");
    Result result = validator.validate(tps, "TransportPolicySubject");
    assertTrue(result.valid);

    tps.setDomainName("*").setServiceName("*");
    result = validator.validate(tps, "TransportPolicySubject");
    assertTrue(result.valid);
  }

  @Test
  public void testEgressPeerOptional() {
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

    TransportPolicyEgressRule tper1 = new TransportPolicyEgressRule().setEntitySelector(tpes1).setTo(tppeer1).setId(12345678L).setLastModified(
            Timestamp.fromMillis(123456789123L));


    Schema schema = MSDSchema.instance();
    Validator validator = new Validator(schema);

    Result result = validator.validate(tper1, "TransportPolicyEgressRule");
    assertTrue(result.valid);

    tper1.setTo(null);
    result = validator.validate(tper1, "TransportPolicyEgressRule");
    assertTrue(result.valid);

    tper1.setLastModified(null);
    result = validator.validate(tper1, "TransportPolicyEgressRule");
    assertFalse(result.valid);
  }

  @Test
  public void testIngressPeerOptional() {
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

    Schema schema = MSDSchema.instance();
    Validator validator = new Validator(schema);

    Result result = validator.validate(tpir1, "TransportPolicyIngressRule");
    assertTrue(result.valid);

    tpir1.setFrom(null);
    result = validator.validate(tpir1, "TransportPolicyIngressRule");
    assertTrue(result.valid);

    tpir1.setLastModified(null);
    result = validator.validate(tpir1, "TransportPolicyIngressRule");
    assertFalse(result.valid);
  }
}