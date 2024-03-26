/**
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

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;

import static org.testng.Assert.*;
import org.testng.annotations.Test;

import java.util.*;

public class GroupTest {

    @Test
    public void testGroupsMethod() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        GroupAuditLog ral = new GroupAuditLog().setMember("user.test").setAdmin("user.admin")
                .setCreated(Timestamp.fromMillis(123456789123L)).setAction("add").setAuditRef("zmstest");

        List<GroupAuditLog> rall = Collections.singletonList(ral);

        // Group test
        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("member1"));

        Group r = new Group()
                .setName("sys.auth:group.admin")
                .setGroupMembers(groupMembers)
                .setAuditEnabled(true)
                .setModified(Timestamp.fromMillis(123456789123L))
                .setAuditLog(rall)
                .setSelfServe(false)
                .setReviewEnabled(false)
                .setNotifyRoles("role1,domain:role.role2")
                .setLastReviewedDate(Timestamp.fromMillis(123456789123L))
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3")
                .setMemberExpiryDays(10)
                .setServiceExpiryDays(20)
                .setDeleteProtection(false)
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setSelfRenew(true)
                .setSelfRenewMins(180)
                .setMaxMembers(5)
                .setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF"));

        Group r2 = new Group()
                .setName("sys.auth:group.admin")
                .setGroupMembers(groupMembers)
                .setAuditEnabled(true)
                .setModified(Timestamp.fromMillis(123456789123L))
                .setAuditLog(rall)
                .setSelfServe(false)
                .setReviewEnabled(false)
                .setNotifyRoles("role1,domain:role.role2")
                .setLastReviewedDate(Timestamp.fromMillis(123456789123L))
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3")
                .setMemberExpiryDays(10)
                .setServiceExpiryDays(20)
                .setDeleteProtection(false)
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setSelfRenew(true)
                .setSelfRenewMins(180)
                .setMaxMembers(5)
                .setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF"));

        assertEquals(r, r2);
        assertEquals(r, r);

        assertEquals(r.getName(), "sys.auth:group.admin");
        assertEquals(r.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(r.getAuditLog(), rall);
        assertEquals(r.getGroupMembers(), groupMembers);
        assertTrue(r.getAuditEnabled());
        assertFalse(r.getSelfServe());
        assertFalse(r.getReviewEnabled());
        assertEquals(r.getLastReviewedDate(), Timestamp.fromMillis(123456789123L));
        assertEquals(r.getNotifyRoles(), "role1,domain:role.role2");
        assertEquals(r.getUserAuthorityExpiration(), "attr1");
        assertEquals(r.getUserAuthorityFilter(), "attr2,attr3");
        assertEquals(r.getMemberExpiryDays().intValue(), 10);
        assertEquals(r.getServiceExpiryDays().intValue(), 20);
        assertFalse(r.getDeleteProtection());
        assertEquals(r.getTags().get("tagKey").getList().get(0), "tagValue");
        assertEquals(r.getSelfRenewMins(), 180);
        assertEquals(r.getSelfRenew(), Boolean.TRUE);
        assertEquals(r.getMaxMembers(), 5);
        assertEquals(r.getResourceOwnership(), new ResourceGroupOwnership().setMetaOwner("TF"));

        r2.setLastReviewedDate(Timestamp.fromMillis(123456789124L));
        assertNotEquals(r, r2);
        r2.setLastReviewedDate(null);
        assertNotEquals(r, r2);
        r2.setLastReviewedDate(Timestamp.fromMillis(123456789123L));
        assertEquals(r, r2);

        r2.setMaxMembers(15);
        assertNotEquals(r, r2);
        r2.setMaxMembers(null);
        assertNotEquals(r, r2);
        r2.setMaxMembers(5);
        assertEquals(r, r2);

        r2.setNotifyRoles("group1");
        assertNotEquals(r, r2);
        r2.setNotifyRoles(null);
        assertNotEquals(r, r2);
        r2.setNotifyRoles("role1,domain:role.role2");
        assertEquals(r, r2);

        r2.setReviewEnabled(true);
        assertNotEquals(r, r2);
        r2.setReviewEnabled(null);
        assertNotEquals(r, r2);
        r2.setReviewEnabled(false);
        assertEquals(r, r2);

        r2.setSelfRenew(false);
        assertNotEquals(r, r2);
        r2.setSelfRenew(null);
        assertNotEquals(r, r2);
        r2.setSelfRenew(true);
        assertEquals(r, r2);

        r2.setSelfRenewMins(15);
        assertNotEquals(r, r2);
        r2.setSelfRenewMins(null);
        assertNotEquals(r, r2);
        r2.setSelfRenewMins(180);
        assertEquals(r, r2);

        r2.setAuditEnabled(false);
        assertNotEquals(r, r2);
        r2.setAuditEnabled(null);
        assertNotEquals(r, r2);
        r2.setAuditEnabled(true);
        assertEquals(r, r2);

        r2.setSelfServe(true);
        assertNotEquals(r, r2);
        r2.setSelfServe(null);
        assertNotEquals(r, r2);
        r2.setSelfServe(false);
        assertEquals(r, r2);

        r2.setDeleteProtection(true);
        assertNotEquals(r, r2);
        r2.setDeleteProtection(null);
        assertNotEquals(r, r2);
        r2.setDeleteProtection(false);
        assertEquals(r, r2);

        r2.setUserAuthorityExpiration("attr11");
        assertNotEquals(r, r2);
        r2.setUserAuthorityExpiration(null);
        assertNotEquals(r, r2);
        r2.setUserAuthorityExpiration("attr1");
        assertEquals(r, r2);

        r2.setUserAuthorityFilter("attr2");
        assertNotEquals(r, r2);
        r2.setUserAuthorityFilter(null);
        assertNotEquals(r, r2);
        r2.setUserAuthorityFilter("attr2,attr3");
        assertEquals(r, r2);

        r2.setMemberExpiryDays(15);
        assertNotEquals(r, r2);
        r2.setMemberExpiryDays(null);
        assertNotEquals(r, r2);
        r2.setMemberExpiryDays(10);
        assertEquals(r, r2);

        r2.setServiceExpiryDays(15);
        assertNotEquals(r, r2);
        r2.setServiceExpiryDays(null);
        assertNotEquals(r, r2);
        r2.setServiceExpiryDays(20);
        assertEquals(r, r2);

        r2.setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF2"));
        assertNotEquals(r, r2);
        r2.setResourceOwnership(null);
        assertNotEquals(r, r2);
        r2.setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF"));
        assertEquals(r, r2);

        r2.setAuditLog(null);
        assertNotEquals(r, r2);
        r2.setGroupMembers(null);
        assertNotEquals(r, r2);
        r2.setModified(null);
        assertNotEquals(r, r2);
        r2.setName(null);
        assertNotEquals(r, r2);
        assertNotEquals("group", r);

        r2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue1"))));
        assertNotEquals(r, r2);
        r2.setTags(null);
        assertNotEquals(r, r2);

        Result result = validator.validate(r, "Group");
        assertTrue(result.valid);

        List<Group> rl = List.of(r);

        // Groups test
        Groups rs1 = new Groups().setList(rl);
        assertEquals(rs1, rs1);

        result = validator.validate(rs1, "Groups");
        assertTrue(result.valid);

        assertEquals(rs1.getList(), rl);

        Groups rs2 = new Groups().setList(rl);
        assertEquals(rs1, rs2);

        rs2.setList(null);
        assertNotEquals(rs1, rs2);

        assertNotEquals(rs1, null);
        assertNotEquals("group", rs1);
    }

    @Test
    public void testGroupMember() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        GroupMember rm = new GroupMember()
                .setGroupName("group1")
                .setMemberName("user.test1")
                .setDomainName("domain1")
                .setExpiration(Timestamp.fromMillis(123456789123L))
                .setAuditRef("audit-ref")
                .setActive(false)
                .setApproved(true)
                .setRequestTime(Timestamp.fromMillis(123456789124L))
                .setLastNotifiedTime(Timestamp.fromMillis(123456789125L))
                .setRequestPrincipal("user.admin")
                .setReviewLastNotifiedTime(Timestamp.fromMillis(123456789127L))
                .setSystemDisabled(1)
                .setPrincipalType(1)
                .setPendingState("ADD");

        assertEquals(rm, rm);
        assertNotEquals("data", rm);
        assertNotEquals(null, rm);

        Result result = validator.validate(rm, "GroupMember");
        assertTrue(result.valid);

        assertEquals(rm.getGroupName(), "group1");
        assertEquals(rm.getMemberName(), "user.test1");
        assertEquals(rm.getDomainName(), "domain1");
        assertEquals(rm.getExpiration().millis(), 123456789123L);
        assertEquals(rm.getAuditRef(), "audit-ref");
        assertFalse(rm.getActive());
        assertTrue(rm.getApproved());
        assertEquals(rm.getRequestTime().millis(), 123456789124L);
        assertEquals(rm.getLastNotifiedTime().millis(), 123456789125L);
        assertEquals(rm.getRequestPrincipal(), "user.admin");
        assertEquals(rm.getReviewLastNotifiedTime().millis(), 123456789127L);
        assertEquals(rm.getSystemDisabled(), Integer.valueOf(1));
        assertEquals(rm.getPrincipalType(), Integer.valueOf(1));
        assertEquals(rm.getPendingState(), "ADD");

        GroupMember rm2 = new GroupMember()
                .setGroupName("group1")
                .setMemberName("user.test1")
                .setDomainName("domain1")
                .setExpiration(Timestamp.fromMillis(123456789123L))
                .setAuditRef("audit-ref")
                .setActive(false)
                .setApproved(true)
                .setRequestTime(Timestamp.fromMillis(123456789124L))
                .setLastNotifiedTime(Timestamp.fromMillis(123456789125L))
                .setRequestPrincipal("user.admin")
                .setReviewLastNotifiedTime(Timestamp.fromMillis(123456789127L))
                .setSystemDisabled(1)
                .setPrincipalType(1)
                .setPendingState("ADD");
        assertEquals(rm, rm2);

        rm2.setRequestPrincipal("user.test2");
        assertNotEquals(rm, rm2);
        rm2.setRequestPrincipal(null);
        assertNotEquals(rm, rm2);
        rm2.setRequestPrincipal("user.admin");
        assertEquals(rm, rm2);

        rm2.setDomainName("domain2");
        assertNotEquals(rm, rm2);
        rm2.setDomainName(null);
        assertNotEquals(rm, rm2);
        rm2.setDomainName("domain1");
        assertEquals(rm, rm2);

        rm2.setGroupName("group2");
        assertNotEquals(rm, rm2);
        rm2.setGroupName(null);
        assertNotEquals(rm, rm2);
        rm2.setGroupName("group1");
        assertEquals(rm, rm2);

        rm2.setMemberName("user.test2");
        assertNotEquals(rm, rm2);
        rm2.setMemberName(null);
        assertNotEquals(rm, rm2);
        rm2.setMemberName("user.test1");
        assertEquals(rm, rm2);

        rm2.setExpiration(Timestamp.fromMillis(123456789124L));
        assertNotEquals(rm, rm2);
        rm2.setExpiration(null);
        assertNotEquals(rm, rm2);
        rm2.setExpiration(Timestamp.fromMillis(123456789123L));
        assertEquals(rm, rm2);

        rm2.setRequestTime(Timestamp.fromMillis(123456789125L));
        assertNotEquals(rm, rm2);
        rm2.setRequestTime(null);
        assertNotEquals(rm, rm2);
        rm2.setRequestTime(Timestamp.fromMillis(123456789124L));
        assertEquals(rm, rm2);

        rm2.setLastNotifiedTime(Timestamp.fromMillis(123456789128L));
        assertNotEquals(rm, rm2);
        rm2.setLastNotifiedTime(null);
        assertNotEquals(rm, rm2);
        rm2.setLastNotifiedTime(Timestamp.fromMillis(123456789125L));
        assertEquals(rm, rm2);

        rm2.setAuditRef("audit2-ref");
        assertNotEquals(rm, rm2);
        rm2.setAuditRef(null);
        assertNotEquals(rm, rm2);
        rm2.setAuditRef("audit-ref");
        assertEquals(rm, rm2);

        rm2.setActive(true);
        assertNotEquals(rm, rm2);
        rm2.setActive(null);
        assertNotEquals(rm, rm2);
        rm2.setActive(false);
        assertEquals(rm, rm2);

        rm2.setApproved(false);
        assertNotEquals(rm, rm2);
        rm2.setApproved(null);
        assertNotEquals(rm, rm2);
        rm2.setApproved(true);
        assertEquals(rm, rm2);

        rm2.setReviewLastNotifiedTime(Timestamp.fromMillis(123456789124L));
        assertNotEquals(rm, rm2);
        rm2.setReviewLastNotifiedTime(null);
        assertNotEquals(rm, rm2);
        rm2.setReviewLastNotifiedTime(Timestamp.fromMillis(123456789127L));
        assertEquals(rm, rm2);

        rm2.setSystemDisabled(2);
        assertNotEquals(rm, rm2);
        rm2.setSystemDisabled(null);
        assertNotEquals(rm, rm2);
        rm2.setSystemDisabled(1);
        assertEquals(rm, rm2);

        rm2.setPendingState("DELETE");
        assertNotEquals(rm, rm2);
        rm2.setPendingState(null);
        assertNotEquals(rm, rm2);
        rm2.setPendingState("ADD");
        assertEquals(rm, rm2);

        rm2.setPrincipalType(2);
        assertNotEquals(rm, rm2);
        rm2.setPrincipalType(null);
        assertNotEquals(rm, rm2);
        rm2.setPrincipalType(1);
        assertEquals(rm, rm2);

        assertNotEquals(rm2, null);

        GroupMember rm3 = new GroupMember();
        rm3.init();
        assertTrue(rm3.getActive());
        assertTrue(rm3.getApproved());

        rm3.setActive(false);
        rm3.setApproved(false);
        rm3.init();
        assertFalse(rm3.getActive());
        assertFalse(rm3.getApproved());
    }

    @Test
    public void testDomainGroupMember() {

        List<GroupMember> list1 = new ArrayList<>();
        list1.add(new GroupMember().setGroupName("group1"));

        List<GroupMember> list2 = new ArrayList<>();

        DomainGroupMember mbr1 = new DomainGroupMember();
        mbr1.setMemberName("mbr1");
        mbr1.setMemberGroups(list1);

        assertEquals("mbr1", mbr1.getMemberName());
        assertEquals(list1, mbr1.getMemberGroups());

        assertEquals(mbr1, mbr1);
        assertNotEquals(null, mbr1);
        assertNotEquals("data", mbr1);

        DomainGroupMember mbr2 = new DomainGroupMember();
        assertNotEquals(mbr1, mbr2);

        mbr2.setMemberName("mbr2");
        assertNotEquals(mbr1, mbr2);

        mbr2.setMemberName("mbr1");
        assertNotEquals(mbr1, mbr2);

        mbr2.setMemberGroups(list2);
        assertNotEquals(mbr1, mbr2);

        list2.add(new GroupMember().setGroupName("group1"));
        assertEquals(mbr1, mbr2);

        GroupMember mbr3 = new GroupMember();
        mbr3.init();
        assertTrue(mbr3.getActive());

        mbr3.setActive(false);
        mbr3.init();
        assertFalse(mbr3.getActive());
    }

    @Test
    public void testDomainGroupMembers() {

        List<DomainGroupMember> list1 = new ArrayList<>();
        list1.add(new DomainGroupMember().setMemberName("mbr1"));

        List<DomainGroupMember> list2 = new ArrayList<>();

        DomainGroupMembers mbr1 = new DomainGroupMembers();
        mbr1.setDomainName("dom1");
        mbr1.setMembers(list1);

        assertEquals("dom1", mbr1.getDomainName());
        assertEquals(list1, mbr1.getMembers());

        assertEquals(mbr1, mbr1);
        assertNotEquals(null, mbr1);
        assertNotEquals("data", mbr1);

        DomainGroupMembers mbr2 = new DomainGroupMembers();
        assertNotEquals(mbr1, mbr2);

        mbr2.setDomainName("dom2");
        assertNotEquals(mbr1, mbr2);

        mbr2.setDomainName("dom1");
        assertNotEquals(mbr1, mbr2);

        mbr2.setMembers(list2);
        assertNotEquals(mbr1, mbr2);

        list2.add(new DomainGroupMember().setMemberName("mbr1"));
        assertEquals(mbr1, mbr2);
    }

    @Test
    public void testGroupSystemMetaMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        GroupSystemMeta rsm = new GroupSystemMeta();

        Result result = validator.validate(rsm, "GroupSystemMeta");
        assertTrue(result.valid);

        assertFalse(rsm.getAuditEnabled());

        GroupSystemMeta rsm2 = new GroupSystemMeta();
        assertNotEquals(rsm, rsm2);
        rsm2.setAuditEnabled(false);
        assertEquals(rsm, rsm2);
        assertEquals(rsm, rsm);

        rsm2.setAuditEnabled(null);
        assertNotEquals(rsm, rsm2);

        assertNotEquals(rsm2, null);
        assertNotEquals("group-meta", rsm);
    }

    @Test
    public void testGroupMetaMethod() {

        GroupMeta gm1 = new GroupMeta()
                .setSelfServe(false)
                .setNotifyRoles("role1,domain:role.role2")
                .setReviewEnabled(false)
                .setAuditEnabled(false)
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3")
                .setMemberExpiryDays(10)
                .setServiceExpiryDays(20)
                .setDeleteProtection(false)
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setLastReviewedDate(Timestamp.fromMillis(100))
                .setSelfRenew(true)
                .setSelfRenewMins(180)
                .setMaxMembers(5)
                .setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF"));

        assertFalse(gm1.getSelfServe());
        assertEquals(gm1.getNotifyRoles(), "role1,domain:role.role2");
        assertFalse(gm1.getReviewEnabled());
        assertFalse(gm1.getAuditEnabled());
        assertFalse(gm1.getDeleteProtection());
        assertEquals(gm1.getUserAuthorityExpiration(), "attr1");
        assertEquals(gm1.getUserAuthorityFilter(), "attr2,attr3");
        assertEquals(gm1.getMemberExpiryDays().intValue(), 10);
        assertEquals(gm1.getServiceExpiryDays().intValue(), 20);
        assertEquals(gm1.getTags().get("tagKey").getList().get(0), "tagValue");
        assertEquals(gm1.getLastReviewedDate(), Timestamp.fromMillis(100));
        assertEquals(gm1.getSelfRenewMins(), 180);
        assertEquals(gm1.getSelfRenew(), Boolean.TRUE);
        assertEquals(gm1.getMaxMembers(), 5);
        assertEquals(gm1.getResourceOwnership(), new ResourceGroupOwnership().setMetaOwner("TF"));

        GroupMeta gm2 = new GroupMeta()
                .setSelfServe(false)
                .setNotifyRoles("role1,domain:role.role2")
                .setReviewEnabled(false)
                .setAuditEnabled(false)
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3")
                .setMemberExpiryDays(10)
                .setServiceExpiryDays(20)
                .setDeleteProtection(false)
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setLastReviewedDate(Timestamp.fromMillis(100))
                .setSelfRenew(true)
                .setSelfRenewMins(180)
                .setMaxMembers(5)
                .setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF"));

        assertEquals(gm1, gm2);
        assertEquals(gm1, gm1);
        assertNotEquals(null, gm1);
        assertNotEquals("group-meta", gm1);

        gm2.setMaxMembers(15);
        assertNotEquals(gm1, gm2);
        gm2.setMaxMembers(null);
        assertNotEquals(gm1, gm2);
        gm2.setMaxMembers(5);
        assertEquals(gm1, gm2);

        gm2.setNotifyRoles("role1");
        assertNotEquals(gm2, gm1);
        gm2.setNotifyRoles(null);
        assertNotEquals(gm2, gm1);
        gm2.setNotifyRoles("role1,domain:role.role2");
        assertEquals(gm2, gm1);

        gm2.setReviewEnabled(true);
        assertNotEquals(gm2, gm1);
        gm2.setReviewEnabled(null);
        assertNotEquals(gm2, gm1);
        gm2.setReviewEnabled(false);
        assertEquals(gm2, gm1);

        gm2.setSelfRenew(false);
        assertNotEquals(gm1, gm2);
        gm2.setSelfRenew(null);
        assertNotEquals(gm1, gm2);
        gm2.setSelfRenew(true);
        assertEquals(gm1, gm2);

        gm2.setSelfRenewMins(15);
        assertNotEquals(gm1, gm2);
        gm2.setSelfRenewMins(null);
        assertNotEquals(gm1, gm2);
        gm2.setSelfRenewMins(180);
        assertEquals(gm1, gm2);

        gm2.setAuditEnabled(true);
        assertNotEquals(gm2, gm1);
        gm2.setAuditEnabled(null);
        assertNotEquals(gm2, gm1);
        gm2.setAuditEnabled(false);
        assertEquals(gm2, gm1);

        gm2.setSelfServe(true);
        assertNotEquals(gm2, gm1);
        gm2.setSelfServe(null);
        assertNotEquals(gm2, gm1);
        gm2.setSelfServe(false);
        assertEquals(gm2, gm1);

        gm2.setDeleteProtection(true);
        assertNotEquals(gm2, gm1);
        gm2.setDeleteProtection(null);
        assertNotEquals(gm2, gm1);
        gm2.setDeleteProtection(false);
        assertEquals(gm2, gm1);

        gm2.setUserAuthorityExpiration("attr11");
        assertNotEquals(gm2, gm1);
        gm2.setUserAuthorityExpiration(null);
        assertNotEquals(gm2, gm1);
        gm2.setUserAuthorityExpiration("attr1");
        assertEquals(gm2, gm1);

        gm2.setUserAuthorityFilter("attr2");
        assertNotEquals(gm2, gm1);
        gm2.setUserAuthorityFilter(null);
        assertNotEquals(gm2, gm1);
        gm2.setUserAuthorityFilter("attr2,attr3");
        assertEquals(gm2, gm1);

        gm2.setMemberExpiryDays(15);
        assertNotEquals(gm2, gm1);
        gm2.setMemberExpiryDays(null);
        assertNotEquals(gm2, gm1);
        gm2.setMemberExpiryDays(10);
        assertEquals(gm2, gm1);

        gm2.setServiceExpiryDays(15);
        assertNotEquals(gm2, gm1);
        gm2.setServiceExpiryDays(null);
        assertNotEquals(gm2, gm1);
        gm2.setServiceExpiryDays(20);
        assertEquals(gm2, gm1);

        gm2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue1"))));
        assertNotEquals(gm2, gm1);
        gm2.setTags(null);
        assertNotEquals(gm2, gm1);
        gm2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(gm2, gm1);

        gm2.setLastReviewedDate(Timestamp.fromMillis(200));
        assertNotEquals(gm2, gm1);
        gm2.setLastReviewedDate(null);
        assertNotEquals(gm2, gm1);
        gm2.setLastReviewedDate(Timestamp.fromMillis(100));
        assertEquals(gm2, gm1);

        gm2.setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF2"));
        assertNotEquals(gm2, gm1);
        gm2.setResourceOwnership(null);
        assertNotEquals(gm2, gm1);
        gm2.setResourceOwnership(new ResourceGroupOwnership().setMetaOwner("TF"));
        assertEquals(gm2, gm1);

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Result result = validator.validate(gm1, "GroupMeta");
        assertTrue(result.valid);
    }

    @Test
    public void testGroupMembershipMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        GroupMembership ms = new GroupMembership().init();
        assertTrue(ms.getIsMember());
        assertTrue(ms.getActive());
        assertTrue(ms.getApproved());

        ms.setMemberName("test.member").setIsMember(false).setGroupName("group1")
                .setExpiration(Timestamp.fromMillis(100)).setAuditRef("audit-ref")
                .setActive(true).setApproved(false).setRequestPrincipal("user.admin")
                .setSystemDisabled(1).setPendingState("ADD");

        // init second time does not change state
        ms.init();
        assertFalse(ms.getIsMember());
        assertTrue(ms.getActive());
        assertFalse(ms.getApproved());

        Result result = validator.validate(ms, "GroupMembership");
        assertTrue(result.valid);

        assertEquals(ms.getMemberName(), "test.member");
        assertFalse(ms.getIsMember());
        assertEquals(ms.getGroupName(), "group1");
        assertEquals(ms.getExpiration(), Timestamp.fromMillis(100));
        assertTrue(ms.getActive());
        assertFalse(ms.getApproved());
        assertEquals(ms.getAuditRef(), "audit-ref");
        assertEquals(ms.getRequestPrincipal(), "user.admin");
        assertEquals(ms.getSystemDisabled(), Integer.valueOf(1));
        assertEquals(ms.getPendingState(), "ADD");

        GroupMembership ms2 = new GroupMembership().setMemberName("test.member").setIsMember(false)
                .setExpiration(Timestamp.fromMillis(100)).setGroupName("group1")
                .setActive(true).setAuditRef("audit-ref").setApproved(false)
                .setRequestPrincipal("user.admin").setSystemDisabled(1).setPendingState("ADD");

        assertEquals(ms, ms2);
        assertEquals(ms, ms);

        ms2.setRequestPrincipal("user.test2");
        assertNotEquals(ms, ms2);
        ms2.setRequestPrincipal(null);
        assertNotEquals(ms, ms2);
        ms2.setRequestPrincipal("user.admin");
        assertEquals(ms, ms2);

        ms2.setExpiration(null);
        assertNotEquals(ms, ms2);
        ms2.setExpiration(Timestamp.fromMillis(100));
        assertEquals(ms, ms2);

        ms2.setGroupName(null);
        assertNotEquals(ms, ms2);
        ms2.setGroupName("group1");
        assertEquals(ms, ms2);

        ms2.setIsMember(null);
        assertNotEquals(ms, ms2);
        ms2.setIsMember(false);
        assertEquals(ms, ms2);

        ms2.setMemberName(null);
        assertNotEquals(ms, ms2);
        ms2.setMemberName("test.member");
        assertEquals(ms, ms2);

        ms2.setAuditRef(null);
        assertNotEquals(ms, ms2);
        ms2.setAuditRef("audit-ref");
        assertEquals(ms, ms2);

        ms2.setActive(null);
        assertNotEquals(ms, ms2);
        ms2.setActive(true);
        assertEquals(ms, ms2);

        ms2.setApproved(null);
        assertNotEquals(ms, ms2);
        ms2.setApproved(true);
        assertNotEquals(ms, ms2);
        ms2.setApproved(false);
        assertEquals(ms, ms2);

        ms2.setSystemDisabled(2);
        assertNotEquals(ms, ms2);
        ms2.setSystemDisabled(null);
        assertNotEquals(ms, ms2);
        ms2.setSystemDisabled(1);
        assertEquals(ms, ms2);

        ms2.setPendingState("DELETE");
        assertNotEquals(ms, ms2);
        ms2.setPendingState(null);
        assertNotEquals(ms, ms2);
        ms2.setPendingState("ADD");
        assertEquals(ms, ms2);

        assertNotEquals(ms2, null);
        assertNotEquals("data", ms);
    }

    @Test
    public void testGroupAuditLog() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        // GroupAuditlog test
        GroupAuditLog ral = new GroupAuditLog().setMember("user.test").setAdmin("user.admin")
                .setCreated(Timestamp.fromMillis(123456789123L)).setAction("add").setAuditRef("zmstest");
        Result result = validator.validate(ral, "GroupAuditLog");
        assertTrue(result.valid);

        assertEquals(ral.getMember(), "user.test");
        assertEquals(ral.getAdmin(), "user.admin");
        assertEquals(ral.getCreated(), Timestamp.fromMillis(123456789123L));
        assertEquals(ral.getAction(), "add");
        assertEquals(ral.getAuditRef(), "zmstest");

        GroupAuditLog ral2 = new GroupAuditLog().setMember("user.test").setAdmin("user.admin")
                .setCreated(Timestamp.fromMillis(123456789123L)).setAction("add").setAuditRef("zmstest");

        assertEquals(ral, ral2);
        assertEquals(ral, ral);

        ral2.setAuditRef(null);
        assertNotEquals(ral, ral2);
        ral2.setAction(null);
        assertNotEquals(ral, ral2);
        ral2.setCreated(null);
        assertNotEquals(ral, ral2);
        ral2.setAdmin(null);
        assertNotEquals(ral, ral2);
        ral2.setMember(null);
        assertNotEquals(ral, ral2);
        assertNotEquals("data", ral2);
    }

    @Test
    public void testDomainGroupMembership() {

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        List<DomainGroupMember> list1 = new ArrayList<>();
        list1.add(new DomainGroupMember().setMemberName("mbr1").setMemberGroups(Collections.emptyList()));
        DomainGroupMembers mbr1 = new DomainGroupMembers().setDomainName("dom1").setMembers(list1);

        List<DomainGroupMembers> list2 = new ArrayList<>();
        list2.add(mbr1);

        DomainGroupMembership groupMembership1 = new DomainGroupMembership().setDomainGroupMembersList(list2);
        Result result = validator.validate(groupMembership1, "DomainGroupMembership");
        assertTrue(result.valid);

        assertEquals(groupMembership1.getDomainGroupMembersList(), list2);

        DomainGroupMembership groupMembership2 = new DomainGroupMembership().setDomainGroupMembersList(list2);

        assertEquals(groupMembership1, groupMembership2);
        assertEquals(groupMembership1, groupMembership1);
        assertNotEquals(groupMembership1, null);
        assertNotEquals("data", groupMembership1);

        List<DomainGroupMembers> list3 = Collections.emptyList();

        groupMembership2.setDomainGroupMembersList(list3);
        assertNotEquals(groupMembership1, groupMembership2);
        groupMembership2.setDomainGroupMembersList(null);
        assertNotEquals(groupMembership1, groupMembership2);
        groupMembership2.setDomainGroupMembersList(list2);
    }
}
