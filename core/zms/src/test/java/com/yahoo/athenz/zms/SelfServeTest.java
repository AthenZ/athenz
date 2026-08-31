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

import java.util.Collections;

import static org.testng.Assert.*;

public class SelfServeTest {

    @Test
    public void testSelfServeObject() {

        SelfServeObject object1 = new SelfServeObject()
                .setDomainName("domain1").setName("name1").setDescription("desc1")
                .setSelfRenew(true).setSelfRenewMins(30).setReviewEnabled(true)
                .setAuditEnabled(false).setDeleteProtection(true).setMaxMembers(10)
                .setMemberExpiryDays(90).setMemberCount(5)
                .setCreated(Timestamp.fromMillis(123456789))
                .setMemberStatus("member").setExpiration(Timestamp.fromMillis(223456789))
                .setInheritedFrom("home.domain:group.devs");

        SelfServeObject object2 = new SelfServeObject()
                .setDomainName("domain1").setName("name1").setDescription("desc1")
                .setSelfRenew(true).setSelfRenewMins(30).setReviewEnabled(true)
                .setAuditEnabled(false).setDeleteProtection(true).setMaxMembers(10)
                .setMemberExpiryDays(90).setMemberCount(5)
                .setCreated(Timestamp.fromMillis(123456789))
                .setMemberStatus("member").setExpiration(Timestamp.fromMillis(223456789))
                .setInheritedFrom("home.domain:group.devs");

        assertEquals(object1, object1);
        assertEquals(object1, object2);
        assertNotEquals("data", object2);

        // verify getters

        assertEquals("domain1", object1.getDomainName());
        assertEquals("name1", object1.getName());
        assertEquals("desc1", object1.getDescription());
        assertEquals(Boolean.TRUE, object1.getSelfRenew());
        assertEquals(Integer.valueOf(30), object1.getSelfRenewMins());
        assertEquals(Boolean.TRUE, object1.getReviewEnabled());
        assertEquals(Boolean.FALSE, object1.getAuditEnabled());
        assertEquals(Boolean.TRUE, object1.getDeleteProtection());
        assertEquals(Integer.valueOf(10), object1.getMaxMembers());
        assertEquals(Integer.valueOf(90), object1.getMemberExpiryDays());
        assertEquals(Integer.valueOf(5), object1.getMemberCount());
        assertEquals(Timestamp.fromMillis(123456789), object1.getCreated());
        assertEquals("member", object1.getMemberStatus());
        assertEquals(Timestamp.fromMillis(223456789), object1.getExpiration());
        assertEquals("home.domain:group.devs", object1.getInheritedFrom());

        object1.setDomainName("domain2");
        assertNotEquals(object1, object2);
        object1.setDomainName(null);
        assertNotEquals(object1, object2);
        object1.setDomainName("domain1");
        assertEquals(object1, object2);

        object1.setName("name2");
        assertNotEquals(object1, object2);
        object1.setName(null);
        assertNotEquals(object1, object2);
        object1.setName("name1");
        assertEquals(object1, object2);

        object1.setDescription("desc2");
        assertNotEquals(object1, object2);
        object1.setDescription(null);
        assertNotEquals(object1, object2);
        object1.setDescription("desc1");
        assertEquals(object1, object2);

        object1.setSelfRenew(false);
        assertNotEquals(object1, object2);
        object1.setSelfRenew(null);
        assertNotEquals(object1, object2);
        object1.setSelfRenew(true);
        assertEquals(object1, object2);

        object1.setSelfRenewMins(31);
        assertNotEquals(object1, object2);
        object1.setSelfRenewMins(null);
        assertNotEquals(object1, object2);
        object1.setSelfRenewMins(30);
        assertEquals(object1, object2);

        object1.setReviewEnabled(false);
        assertNotEquals(object1, object2);
        object1.setReviewEnabled(null);
        assertNotEquals(object1, object2);
        object1.setReviewEnabled(true);
        assertEquals(object1, object2);

        object1.setAuditEnabled(true);
        assertNotEquals(object1, object2);
        object1.setAuditEnabled(null);
        assertNotEquals(object1, object2);
        object1.setAuditEnabled(false);
        assertEquals(object1, object2);

        object1.setDeleteProtection(false);
        assertNotEquals(object1, object2);
        object1.setDeleteProtection(null);
        assertNotEquals(object1, object2);
        object1.setDeleteProtection(true);
        assertEquals(object1, object2);

        object1.setMaxMembers(11);
        assertNotEquals(object1, object2);
        object1.setMaxMembers(null);
        assertNotEquals(object1, object2);
        object1.setMaxMembers(10);
        assertEquals(object1, object2);

        object1.setMemberExpiryDays(91);
        assertNotEquals(object1, object2);
        object1.setMemberExpiryDays(null);
        assertNotEquals(object1, object2);
        object1.setMemberExpiryDays(90);
        assertEquals(object1, object2);

        object1.setMemberCount(6);
        assertNotEquals(object1, object2);
        object1.setMemberCount(null);
        assertNotEquals(object1, object2);
        object1.setMemberCount(5);
        assertEquals(object1, object2);

        object1.setCreated(Timestamp.fromMillis(123456780));
        assertNotEquals(object1, object2);
        object1.setCreated(null);
        assertNotEquals(object1, object2);
        object1.setCreated(Timestamp.fromMillis(123456789));
        assertEquals(object1, object2);

        object1.setMemberStatus("pending");
        assertNotEquals(object1, object2);
        object1.setMemberStatus(null);
        assertNotEquals(object1, object2);
        object1.setMemberStatus("member");
        assertEquals(object1, object2);

        object1.setExpiration(Timestamp.fromMillis(223456780));
        assertNotEquals(object1, object2);
        object1.setExpiration(null);
        assertNotEquals(object1, object2);
        object1.setExpiration(Timestamp.fromMillis(223456789));
        assertEquals(object1, object2);

        object1.setInheritedFrom("home.domain:group.other");
        assertNotEquals(object1, object2);
        object1.setInheritedFrom(null);
        assertNotEquals(object1, object2);
        object1.setInheritedFrom("home.domain:group.devs");
        assertEquals(object1, object2);
    }

    @Test
    public void testSelfServeObjects() {

        SelfServeObjects objects1 = new SelfServeObjects();
        SelfServeObjects objects2 = new SelfServeObjects();

        assertEquals(objects1, objects1);
        assertEquals(objects1, objects2);
        assertNotEquals("data", objects2);

        // verify getters

        assertNull(objects1.getList());

        SelfServeObject object1 = new SelfServeObject()
                .setDomainName("domain1").setName("name1");
        objects1.setList(Collections.singletonList(object1));
        assertEquals(objects1.getList().size(), 1);
        assertNotEquals(objects1, objects2);

        objects2.setList(Collections.singletonList(object1));
        assertEquals(objects1, objects2);
    }
}
