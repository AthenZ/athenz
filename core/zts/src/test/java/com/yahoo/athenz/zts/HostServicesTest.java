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

import static org.testng.Assert.*;

import java.util.Collections;

import org.testng.annotations.Test;

@SuppressWarnings({"EqualsWithItself", "EqualsBetweenInconvertibleTypes"})
public class HostServicesTest {

    @Test
    public void testHostService() {
        HostServices hs1 = new HostServices();
        HostServices hs2 = new HostServices();

        hs1.setNames(Collections.singletonList("host1"));
        hs1.setHost("hostA");

        hs2.setNames(Collections.singletonList("host1"));
        hs2.setHost("hostA");

        assertEquals(Collections.singletonList("host1"), hs1.getNames());
        assertEquals("hostA", hs1.getHost());

        assertEquals(hs1, hs2);
        assertEquals(hs1, hs1);

        hs1.setNames(Collections.singletonList("host2"));
        assertNotEquals(hs2, hs1);
        hs1.setNames(null);
        assertNotEquals(hs2, hs1);
        hs1.setNames(Collections.singletonList("host1"));
        assertEquals(hs2, hs1);

        hs1.setHost("hostB");
        assertNotEquals(hs2, hs1);
        hs1.setHost(null);
        assertNotEquals(hs2, hs1);
        hs1.setHost("hostA");
        assertEquals(hs2, hs1);

        assertNotEquals(hs2, null);
        assertNotEquals("hs2", hs1);
    }
}
