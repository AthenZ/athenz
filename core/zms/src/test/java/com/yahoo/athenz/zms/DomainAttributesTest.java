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

package com.yahoo.athenz.zms;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class DomainAttributesTest {

    @Test
    public void testDomainAttributes() {

        DomainAttributes attrs1 = new DomainAttributes();
        attrs1.setFetchTime(1001);

        DomainAttributes attrs2 = new DomainAttributes();
        attrs2.setFetchTime(1001);

        assertEquals(attrs1, attrs1);
        assertEquals(attrs1, attrs2);
        assertNotEquals("data", attrs2);

        // verify getters
        assertEquals(attrs1.getFetchTime(), 1001);

        attrs1.setFetchTime(1002);
        assertNotEquals(attrs1, attrs2);
        attrs1.setFetchTime(1001);
        assertEquals(attrs1, attrs2);
    }
}
