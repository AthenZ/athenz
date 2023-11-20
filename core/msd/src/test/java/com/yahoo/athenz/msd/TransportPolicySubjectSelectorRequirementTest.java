/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.msd;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class TransportPolicySubjectSelectorRequirementTest {

    @Test
    public void testMethods() {
        TransportPolicySubjectSelectorRequirement tps1 = new TransportPolicySubjectSelectorRequirement();
        tps1.setKey("key");
        tps1.setOperator("operator");
        tps1.setValue("value");

        TransportPolicySubjectSelectorRequirement tps2 = new TransportPolicySubjectSelectorRequirement();
        tps2.setKey("key");
        tps2.setOperator("operator");
        tps2.setValue("value");

        assertEquals(tps1.getKey(), "key");
        assertEquals(tps1.getOperator(), "operator");
        assertEquals(tps1.getValue(), "value");

        assertEquals(tps1, tps2);
        assertFalse(tps1.equals("abc"));

        tps2.setKey("key2");
        assertNotEquals(tps1, tps2);

        tps2.setKey("key");
        tps2.setOperator("operator2");
        assertNotEquals(tps1, tps2);

        tps2.setOperator("operator");
        tps2.setValue("value2");
        assertNotEquals(tps1, tps2);
    }
}