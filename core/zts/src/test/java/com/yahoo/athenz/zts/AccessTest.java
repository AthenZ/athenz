/*
 * Copyright 2016 Yahoo Inc.
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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

@SuppressWarnings("EqualsWithItself")
public class AccessTest {

    @Test
    public void testSetGranted() {
        Access a = new Access();
        assertTrue(a.setGranted(true).granted);
    }

    @Test
    public void testGetGranted() {
        Access a = new Access();
        a.setGranted(true);
        assertTrue(a.getGranted());
    }

    @Test
    public void testEqualsSameObj() {
        Access a = new Access().setGranted(true);
        Access b = new Access().setGranted(false);
        assertEquals(a, a);
        assertNotEquals(a, b);
    }

    @SuppressWarnings("EqualsBetweenInconvertibleTypes")
    @Test
    public void testEqualsDifObj() {
        Access a = new Access();
        assertNotEquals("", a);
    }
}
