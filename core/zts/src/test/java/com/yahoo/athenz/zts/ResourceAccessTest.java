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

import static org.testng.Assert.*;

@SuppressWarnings("EqualsWithItself")
public class ResourceAccessTest {

    @Test
    public void testSetGranted() {
        ResourceAccess a = new ResourceAccess();
        assertTrue(a.setGranted(true).granted);
    }

    @Test
    public void testGetGranted() {
        ResourceAccess a = new ResourceAccess();
        a.setGranted(true);
        assertTrue(a.getGranted());
    }

    @Test
    public void testEqualsSameObj() {
        ResourceAccess a = new ResourceAccess().setGranted(true);
        ResourceAccess b = new ResourceAccess().setGranted(false);
        assertEquals(a, a);
        assertNotEquals(a, b);
        b.setGranted(true);
        assertEquals(a, b);
    }

    @SuppressWarnings("EqualsBetweenInconvertibleTypes")
    @Test
    public void testEqualsDifObj() {
        ResourceAccess a = new ResourceAccess();
        assertNotEquals("", a);
    }
}
