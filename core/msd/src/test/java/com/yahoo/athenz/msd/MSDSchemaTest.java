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
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;
import org.testng.annotations.Test;

public class MSDSchemaTest {

  @Test
  public void testMSDSchema() {
    MSDSchema msdSchema = new MSDSchema();
    assertNotNull(msdSchema);
    Schema schema = MSDSchema.instance();
    assertNotNull(schema);
    Validator validator = new Validator(schema);

    TransportPolicySubject tps1 = new TransportPolicySubject();
    tps1.setDomainName("dom1").setServiceName("svc1");
    Result result = validator.validate(tps1, "TransportPolicySubject");
    assertTrue(result.valid);
  }
}