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

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class MemberRoleTest {

    @Test
    public void testMemberRole() {

        MemberRole mbr1 = new MemberRole();
        mbr1.setRoleName("role1");
        mbr1.setExpiration(Timestamp.fromMillis(100));
        mbr1.setActive(false);
        mbr1.setAuditRef("audit-ref");
        mbr1.setDomainName("athenz");
        mbr1.setMemberName("mbr");
        mbr1.setRequestTime(Timestamp.fromMillis(100));
        mbr1.setRequestPrincipal("user.admin");
        mbr1.setSystemDisabled(1);
        mbr1.setReviewReminder(Timestamp.fromMillis(100));
        mbr1.setPendingState("ADD");
        mbr1.setTrustRoleName("domain:role.trust");

        assertEquals("role1", mbr1.getRoleName());
        assertEquals(Timestamp.fromMillis(100), mbr1.getExpiration());
        assertEquals(Timestamp.fromMillis(100), mbr1.getRequestTime());
        assertFalse(mbr1.getActive());
        assertEquals(mbr1.getAuditRef(), "audit-ref");
        assertEquals(mbr1.getDomainName(), "athenz");
        assertEquals(mbr1.getMemberName(), "mbr");
        assertEquals(mbr1.getRequestPrincipal(), "user.admin");
        assertEquals(mbr1.getSystemDisabled(), Integer.valueOf(1));
        assertEquals(Timestamp.fromMillis(100), mbr1.getReviewReminder());
        assertEquals(mbr1.getPendingState(), "ADD");
        assertEquals(mbr1.getTrustRoleName(), "domain:role.trust");

        assertEquals(mbr1, mbr1);
        assertNotEquals(null, mbr1);
        assertNotEquals("data", mbr1);

        MemberRole mbr2 = new MemberRole()
                .setRoleName("role1")
                .setExpiration(Timestamp.fromMillis(100))
                .setActive(false)
                .setAuditRef("audit-ref")
                .setDomainName("athenz")
                .setMemberName("mbr")
                .setRequestTime(Timestamp.fromMillis(100))
                .setRequestPrincipal("user.admin")
                .setSystemDisabled(1)
                .setReviewReminder(Timestamp.fromMillis(100))
                .setPendingState("ADD")
                .setTrustRoleName("domain:role.trust");

        assertEquals(mbr1, mbr2);

        mbr2.setMemberName("mbr2");
        assertNotEquals(mbr1, mbr2);
        mbr2.setMemberName(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setMemberName("mbr");
        assertEquals(mbr1, mbr2);

        mbr2.setRoleName("role2");
        assertNotEquals(mbr1, mbr2);
        mbr2.setRoleName(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setRoleName("role1");
        assertEquals(mbr1, mbr2);

        mbr2.setAuditRef("audit-ref2");
        assertNotEquals(mbr1, mbr2);
        mbr2.setAuditRef(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setAuditRef("audit-ref");
        assertEquals(mbr1, mbr2);

        mbr2.setDomainName("athenz2");
        assertNotEquals(mbr1, mbr2);
        mbr2.setDomainName(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setDomainName("athenz");
        assertEquals(mbr1, mbr2);

        mbr2.setExpiration(Timestamp.fromMillis(101));
        assertNotEquals(mbr1, mbr2);
        mbr2.setExpiration(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setExpiration(Timestamp.fromMillis(100));
        assertEquals(mbr1, mbr2);

        mbr2.setRequestTime(Timestamp.fromMillis(101));
        assertNotEquals(mbr1, mbr2);
        mbr2.setRequestTime(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setRequestTime(Timestamp.fromMillis(100));
        assertEquals(mbr1, mbr2);

        mbr2.setReviewReminder(Timestamp.fromMillis(101));
        assertNotEquals(mbr1, mbr2);
        mbr2.setReviewReminder(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setReviewReminder(Timestamp.fromMillis(100));
        assertEquals(mbr1, mbr2);

        mbr2.setRequestPrincipal("athenz2");
        assertNotEquals(mbr1, mbr2);
        mbr2.setRequestPrincipal(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setRequestPrincipal("user.admin");
        assertEquals(mbr1, mbr2);

        mbr2.setSystemDisabled(2);
        assertNotEquals(mbr1, mbr2);
        mbr2.setSystemDisabled(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setSystemDisabled(1);
        assertEquals(mbr1, mbr2);

        mbr2.setActive(true);
        assertNotEquals(mbr1, mbr2);
        mbr2.setActive(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setActive(false);
        assertEquals(mbr1, mbr2);

        mbr2.setPendingState("DELETE");
        assertNotEquals(mbr1, mbr2);
        mbr2.setPendingState(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setPendingState("ADD");
        assertEquals(mbr1, mbr2);

        mbr2.setTrustRoleName("domain:role.trust2");
        assertNotEquals(mbr1, mbr2);
        mbr2.setTrustRoleName(null);
        assertNotEquals(mbr1, mbr2);
        mbr2.setTrustRoleName("domain:role.trust");
        assertEquals(mbr1, mbr2);
    }

}
