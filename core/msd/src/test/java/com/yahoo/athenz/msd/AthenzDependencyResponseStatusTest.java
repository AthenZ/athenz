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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class AthenzDependencyResponseStatusTest {

    @Test(dataProvider = "dataForTestFromString")
    public void testFromString(String input, AthenzDependencyResponseStatus expected, String expectedError) {
        AthenzDependencyResponseStatus actual = null;
        String actualErr = null;
        try {
            actual = AthenzDependencyResponseStatus.fromString(input);
        } catch (Exception ex) {
            actualErr = ex.getMessage();
        }
        assertEquals(actualErr, expectedError, "exception");
        assertEquals(actual, expected);
    }

    @DataProvider
    private Object[][] dataForTestFromString() {
        return new Object[][]{
            {null, null, "Invalid string representation for AthenzDependencyResponseStatus: null"},
            {"something", null, "Invalid string representation for AthenzDependencyResponseStatus: something"},
            {"allow", AthenzDependencyResponseStatus.allow, null},
            {"deny", AthenzDependencyResponseStatus.deny, null}
            };
    }
}