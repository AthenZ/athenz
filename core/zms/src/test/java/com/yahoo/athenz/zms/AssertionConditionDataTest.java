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

import static org.testng.Assert.*;

public class AssertionConditionDataTest {
    @Test
    public void testAssertionConditionDataFields() {
        AssertionConditionData cd1 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1");
        AssertionConditionData cd2 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1");

        assertEquals(cd1, cd2);
        assertEquals(cd1, cd1);
        assertFalse(cd1.equals("xyz"));

        cd2.setOperator(null);
        assertNotEquals(cd1, cd2);

        cd2.setOperator(AssertionConditionOperator.EQUALS);
        cd2.setValue(null);
        assertNotEquals(cd1, cd2);

        assertEquals(cd1.getOperator().name(), "EQUALS");
        assertEquals(cd1.getValue(), "value1");

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Validator.Result resultC1 = validator.validate(cd1, "AssertionConditionData");
        assertTrue(resultC1.valid);

        cd1.setValue("abc!~,fws##");
        resultC1 = validator.validate(cd1, "AssertionConditionData");
        assertFalse(resultC1.valid);

        cd1.setValue("*.avd");
        resultC1 = validator.validate(cd1, "AssertionConditionData");
        assertTrue(resultC1.valid);

        cd1.setValue("*");
        resultC1 = validator.validate(cd1, "AssertionConditionData");
        assertTrue(resultC1.valid);

        cd1.setValue("+qaq");
        resultC1 = validator.validate(cd1, "AssertionConditionData");
        assertFalse(resultC1.valid);

        cd1.setValue("abc.athenz.io");
        resultC1 = validator.validate(cd1, "AssertionConditionData");
        assertTrue(resultC1.valid);

        AssertionConditionData cd3 = new AssertionConditionData();
        resultC1 = validator.validate(cd3, "AssertionConditionData");
        assertFalse(resultC1.valid);
    }
}
