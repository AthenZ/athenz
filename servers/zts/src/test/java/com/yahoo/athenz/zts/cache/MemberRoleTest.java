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
package com.yahoo.athenz.zts.cache;


import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class MemberRoleTest {

    @Test
    public void testMemberRole() {

        MemberRole mr = new MemberRole("role", 100);
        assertEquals("role", mr.getRole());
        assertEquals(100, mr.getExpiration());
        assertEquals(3510355, mr.hashCode());

        mr = new MemberRole(null, 200);
        assertNull(mr.getRole());
        assertEquals(200, mr.getExpiration());
        assertEquals(7161, mr.hashCode());
    }

    @Test
    public void testMemberRoleEquals() {

        MemberRole mr1 = new MemberRole("role", 100);
        MemberRole mr2 = new MemberRole("role", 100);
        MemberRole mr3 = new MemberRole("role", 200);
        MemberRole mr4 = new MemberRole(null, 100);
        MemberRole mr5 = new MemberRole(null, 100);
        MemberRole mr6 = new MemberRole("role2", 100);

        assertTrue(mr1.equals(mr1));
        assertFalse(mr1.equals(null));
        assertFalse(mr1.equals("string"));
        assertTrue(mr1.equals(mr2));
        assertFalse(mr1.equals(mr3));
        assertFalse(mr4.equals(mr1));
        assertTrue(mr4.equals(mr5));
        assertFalse(mr1.equals(mr6));
    }
}
