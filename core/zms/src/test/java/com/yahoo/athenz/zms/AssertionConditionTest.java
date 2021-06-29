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

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class AssertionConditionTest {

    @Test
    public void testAssertionConditionFields() {
        Map<String, AssertionConditionData> m1 = new HashMap<>();
        AssertionConditionData cd1 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1");
        m1.put("instances", cd1);

        Map<String, AssertionConditionData> m2 = new HashMap<>();
        AssertionConditionData cd2 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1");
        m2.put("instances", cd2);
        AssertionCondition c1 = new AssertionCondition().setId(1).setConditionsMap(m1);
        AssertionCondition c2 = new AssertionCondition().setId(1).setConditionsMap(m2);

        assertEquals(c1, c2);
        assertEquals(c1, c1);
        assertFalse(c1.equals("xyz"));

        c2.setConditionsMap(null);
        assertNotEquals(c1, c2);

        c2.setConditionsMap(m2);
        c2.setId(null);
        assertNotEquals(c1, c2);

        assertEquals(m1, c1.getConditionsMap());
        assertEquals((Integer)1, c1.getId());

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Validator.Result resultC1 = validator.validate(c1, "AssertionCondition");
        assertTrue(resultC1.valid);

        c1.getConditionsMap().put("e#@!", cd2);
        resultC1 = validator.validate(c1, "AssertionCondition");
        assertFalse(resultC1.valid);

        c1.getConditionsMap().put("09abcd", cd2);
        resultC1 = validator.validate(c1, "AssertionCondition");
        assertFalse(resultC1.valid);

        c1.setConditionsMap(new HashMap<>());
        resultC1 = validator.validate(c1, "AssertionCondition");
        assertTrue(resultC1.valid);

        c1.getConditionsMap().put("abc", new AssertionConditionData());
        resultC1 = validator.validate(c1, "AssertionCondition");
        assertFalse(resultC1.valid);

        c1.setConditionsMap(null);
        resultC1 = validator.validate(c1, "AssertionCondition");
        assertFalse(resultC1.valid);
    }
}