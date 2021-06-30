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

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class WorkloadOptionsTest {
    @Test
    public void testWorkloadOptionsFields() {
        WorkloadOptions wlo1 = new WorkloadOptions();
        wlo1.setIpChanged(true);

        assertNotNull(wlo1);
        assertEquals(wlo1.getIpChanged(), true);
        assertEquals(wlo1, wlo1);

        WorkloadOptions wlo2 = new WorkloadOptions();
        wlo2.setIpChanged(true);

        assertEquals(wlo1, wlo2);

        // Modify issue time and verify equality
        wlo2.setIpChanged(false);
        assertNotEquals(wlo1, wlo2);
        wlo2.setIpChanged(true);

        assertNotEquals(wlo1, null);

        // for code coverage
        assertFalse(wlo1.equals("mystring"));
        assertNotEquals(wlo1, "mystring");
    }
}