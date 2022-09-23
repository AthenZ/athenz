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

package com.yahoo.athenz.zts;

import org.testng.annotations.*;

import java.util.*;

import static org.testng.Assert.*;

@SuppressWarnings({"EqualsWithItself", "EqualsBetweenInconvertibleTypes"})
public class StatusTest {

    @Test
    public void testStatus() {

        Status data1 = new Status();
        data1.setMessage("message1");

        Status data2 = new Status();
        data2.setMessage("message1");

        assertEquals(data1, data1);
        assertEquals(data1, data2);

        data2.setCode(401);

        // verify getters
        assertEquals("message1", data2.getMessage());
        assertEquals(401, data2.getCode());

        assertNotEquals(data2, data1);

        data1.setCode(401);
        assertEquals(data2, data1);

        data1.setMessage("message2");
        assertNotEquals(data2, data1);

        data1.setMessage(null);
        assertNotEquals(data2, data1);

        assertNotEquals(data1, null);
        assertNotEquals("data", data2);
    }
}
