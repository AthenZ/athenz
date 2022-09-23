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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class RoleTokenTest {

    @Test
    public void testRoleToken() {
        RoleToken rt1 = new RoleToken();
        RoleToken rt2 = new RoleToken();

        // set
        rt1.setToken("sample_token").setExpiryTime(30L);
        rt2.setToken("sample_token").setExpiryTime(30L);

        // getter assertion
        assertEquals(rt1.getToken(), "sample_token");
        assertEquals(rt1.getExpiryTime(), 30L);

        assertEquals(rt1, rt1);
        assertEquals(rt1, rt2);

        rt1.setToken(null);
        assertNotEquals(rt2, rt1);
        rt1.setToken("token2");
        assertNotEquals(rt2, rt1);
        rt1.setToken("sample_token");
        assertEquals(rt2, rt1);

        rt2.setExpiryTime(40L);
        assertNotEquals(rt2, rt1);
        rt2.setExpiryTime(30L);
        assertEquals(rt2, rt1);

        assertNotEquals(rt2, null);
        assertNotEquals("", rt1);
    }
}
