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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AssertionConditionOperatorTest {

    @Test
    public void testAssertionConditionOperatorFields() {
        AssertionConditionOperator op1 = AssertionConditionOperator.EQUALS;
        AssertionConditionOperator op2 = AssertionConditionOperator.EQUALS;
        assertEquals(op1, op2);
        assertEquals(op1, op1);
        assertFalse(op1.equals("xyz"));
        AssertionConditionOperator op3 = AssertionConditionOperator.fromString("EQUALS");
        assertEquals(op1, op3);
        try {
            AssertionConditionOperator.fromString("NOT EQUALS");
            fail();
        }catch (IllegalArgumentException ignored){

        }
    }
}