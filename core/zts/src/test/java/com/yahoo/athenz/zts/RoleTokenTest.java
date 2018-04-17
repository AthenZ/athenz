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
public class RoleTokenTest {

    @Test
    public void testRoleToken() {
        RoleToken rt = new RoleToken();
        RoleToken rt2 = new RoleToken();

        // set
        rt.setToken("sample_token").setExpiryTime(30L);
        rt2.setToken("sample_token").setExpiryTime(40L);

        // getter assertion
        assertEquals(rt.getToken(), "sample_token");
        assertEquals(rt.getExpiryTime(), 30L);
        assertEquals(rt, rt);
        assertNotEquals(rt, rt2);
        rt2.setToken(null);
        assertNotEquals(rt2, rt);
        //noinspection EqualsBetweenInconvertibleTypes
        assertNotEquals("", rt);

    }

}
