/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zms;

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Validator;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class AssertionConditionsTest {

    @Test
    public void testAssertionConditionsFields() {

        Map<String, AssertionConditionData> m1 = new HashMap<>();
        AssertionConditionData cd1 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1");
        m1.put("instances", cd1);

        Map<String, AssertionConditionData> m2 = new HashMap<>();
        AssertionConditionData cd2 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1");
        m2.put("instances", cd2);
        AssertionCondition c1 = new AssertionCondition().setId(1).setConditionsMap(m1);
        AssertionCondition c2 = new AssertionCondition().setId(1).setConditionsMap(m2);

        AssertionConditions ac1 = new AssertionConditions().setConditionsList(Collections.singletonList(c1));
        AssertionConditions ac2 = new AssertionConditions().setConditionsList(Collections.singletonList(c2));

        assertEquals(ac1, ac1);
        assertEquals(ac1, ac2);
        assertFalse(ac1.equals("xyz"));

        assertEquals(1, ac1.getConditionsList().size());

        ac2.setConditionsList(null);
        assertNotEquals(ac2, ac1);
        assertNotEquals(ac1, null);
        assertNotEquals(ac1, "xyz");

        ac2.setConditionsList(null);
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Validator.Result resultC1 = validator.validate(ac2, "AssertionConditions");
        assertFalse(resultC1.valid);
    }
}