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

package com.yahoo.athenz.msd;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class AthenzDependencyResponseTest {

    @Test
    public void testAthenzDependencyRequestFields() {
        AthenzDependencyResponse resp1 = new AthenzDependencyResponse();
        resp1.setStatus(AthenzDependencyResponseStatus.allow);
        resp1.setMessage("msg1");

        assertNotNull(resp1);
        assertFalse(resp1.equals(new Object()));
        assertEquals(resp1.getStatus(), AthenzDependencyResponseStatus.allow);
        assertEquals(resp1.getMessage(), "msg1");
        assertFalse(resp1.equals(null));
        assertFalse(resp1.equals(new Object()));
    }

    @Test(dataProvider = "dataForTestAthenzDependencyResponseEquality")
    public void testAthenzDependencyResponseEquality(AthenzDependencyResponse resp1, AthenzDependencyResponse resp2,
                                                    boolean expected) {
        assertEquals(resp1.equals(resp2), expected);
    }

    @DataProvider
    private Object[][] dataForTestAthenzDependencyResponseEquality() {
        AthenzDependencyResponse resp1 = new AthenzDependencyResponse();
        resp1.setStatus(AthenzDependencyResponseStatus.allow);
        resp1.setMessage("msg1");

        AthenzDependencyResponse resp2 = new AthenzDependencyResponse();
        resp2.setStatus(AthenzDependencyResponseStatus.allow);
        resp2.setMessage("msg1");

        AthenzDependencyResponse resp3 = new AthenzDependencyResponse();
        resp3.setStatus(AthenzDependencyResponseStatus.deny);
        resp3.setMessage("msg1");

        AthenzDependencyResponse resp4 = new AthenzDependencyResponse();
        resp4.setStatus(AthenzDependencyResponseStatus.allow);
        resp4.setMessage("msg2");

        return new Object[][]{
            {resp1, resp1, true},
            {resp1, resp2, true},
            {resp1, resp3, false},
            {resp1, resp4, false},
            {new AthenzDependencyResponse(), new AthenzDependencyResponse(), true}
            };
    }
}