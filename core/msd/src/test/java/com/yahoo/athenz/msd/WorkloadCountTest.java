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

public class WorkloadCountTest {

    @Test
    public void testFields() {
        WorkloadCount wc1 = new WorkloadCount().setStoreCount(10).setCacheCount(20);
        assertEquals(wc1.getStoreCount(), 10);
        assertEquals(wc1.getCacheCount(), 20);

        WorkloadCount wc2 = new WorkloadCount().setStoreCount(10).setCacheCount(20);
        assertEquals(wc1, wc2);

        assertEquals(wc1, wc1);

        wc2.setStoreCount(15);
        assertNotEquals(wc2, wc1);

        wc2.setStoreCount(10);
        wc2.setCacheCount(25);
        assertNotEquals(wc2, wc1);

        assertFalse(wc1.equals("xyz"));
    }
}
