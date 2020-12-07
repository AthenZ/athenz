/**
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

package com.yahoo.athenz.zms;

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;
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

        List<GroupAuditLog> rall = Arrays.asList(ral);

        // Group test
        List<String> members = Arrays.asList("user.boynton");
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
                .setUserAuthorityFilter("attr2,attr3");

        Result result = validator.validate(r, "Group");
        assertTrue(result.valid);

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
                .setUserAuthorityFilter("attr2,attr3");

        assertTrue(r2.equals(r));
        assertTrue(r.equals(r));

        r2.setLastReviewedDate(Timestamp.fromMillis(123456789124L));
        assertFalse(r2.equals(r));
        r2.setLastReviewedDate(null);
        assertFalse(r2.equals(r));
        r2.setLastReviewedDate(Timestamp.fromMillis(123456789123L));
        assertTrue(r2.equals(r));

        r2.setNotifyRoles("group1");
        assertFalse(r2.equals(r));
        r2.setNotifyRoles(null);
        assertFalse(r2.equals(r));
        r2.setNotifyRoles("role1,domain:role.role2");
        assertTrue(r2.equals(r));

        r2.setReviewEnabled(true);
        assertFalse(r2.equals(r));
        r2.setReviewEnabled(null);
        assertFalse(r2.equals(r));
        r2.setReviewEnabled(false);
        assertTrue(r2.equals(r));

        r2.setAuditEnabled(false);
        assertFalse(r2.equals(r));
        r2.setAuditEnabled(null);
        assertFalse(r2.equals(r));
        r2.setAuditEnabled(true);
        assertTrue(r2.equals(r));

        r2.setSelfServe(true);
        assertFalse(r2.equals(r));
        r2.setSelfServe(null);
        assertFalse(r2.equals(r));
        r2.setSelfServe(false);
        assertTrue(r2.equals(r));

        r2.setUserAuthorityExpiration("attr11");
        assertFalse(r2.equals(r));
        r2.setUserAuthorityExpiration(null);
        assertFalse(r2.equals(r));
        r2.setUserAuthorityExpiration("attr1");
        assertTrue(r2.equals(r));

        r2.setUserAuthorityFilter("attr2");
        assertFalse(r2.equals(r));
        r2.setUserAuthorityFilter(null);
        assertFalse(r2.equals(r));
        r2.setUserAuthorityFilter("attr2,attr3");
        assertTrue(r2.equals(r));

        r2.setAuditLog(null);
        assertFalse(r2.equals(r));
        r2.setGroupMembers(null);
        assertFalse(r2.equals(r));
        r2.setModified(null);
        assertFalse(r2.equals(r));
        r2.setName(null);
        assertFalse(r2.equals(r));
        assertFalse(r.equals(new String()));

        List<Group> rl = Arrays.asList(r);

        // Groups test
        Groups rs1 = new Groups().setList(rl);
        assertTrue(rs1.equals(rs1));

        result = validator.validate(rs1, "Groups");
        assertTrue(result.valid);

        assertEquals(rs1.getList(), rl);

        Groups rs2 = new Groups().setList(rl);
        assertTrue(rs2.equals(rs1));

        rs2.setList(null);
        assertFalse(rs2.equals(rs1));

        assertFalse(rs1.equals(null));
        assertFalse(rs1.equals(new String()));
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
                .setPrincipalType(1);

        assertTrue(rm.equals(rm));

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
                .setPrincipalType(1);
        assertTrue(rm2.equals(rm));

        rm2.setRequestPrincipal("user.test2");
        assertFalse(rm2.equals(rm));
        rm2.setRequestPrincipal(null);
        assertFalse(rm2.equals(rm));
        rm2.setRequestPrincipal("user.admin");
        assertTrue(rm2.equals(rm));

        rm2.setDomainName("domain2");
        assertFalse(rm2.equals(rm));
        rm2.setDomainName(null);
        assertFalse(rm2.equals(rm));
        rm2.setDomainName("domain1");
        assertTrue(rm2.equals(rm));

        rm2.setGroupName("group2");
        assertFalse(rm2.equals(rm));
        rm2.setGroupName(null);
        assertFalse(rm2.equals(rm));
        rm2.setGroupName("group1");
        assertTrue(rm2.equals(rm));

        rm2.setMemberName("user.test2");
        assertFalse(rm2.equals(rm));
        rm2.setMemberName(null);
        assertFalse(rm2.equals(rm));
        rm2.setMemberName("user.test1");
        assertTrue(rm2.equals(rm));

        rm2.setExpiration(Timestamp.fromMillis(123456789124L));
        assertFalse(rm2.equals(rm));
        rm2.setExpiration(null);
        assertFalse(rm2.equals(rm));
        rm2.setExpiration(Timestamp.fromMillis(123456789123L));
        assertTrue(rm2.equals(rm));

        rm2.setRequestTime(Timestamp.fromMillis(123456789125L));
        assertFalse(rm2.equals(rm));
        rm2.setRequestTime(null);
        assertFalse(rm2.equals(rm));
        rm2.setRequestTime(Timestamp.fromMillis(123456789124L));
        assertTrue(rm2.equals(rm));

        rm2.setLastNotifiedTime(Timestamp.fromMillis(123456789128L));
        assertFalse(rm2.equals(rm));
        rm2.setLastNotifiedTime(null);
        assertFalse(rm2.equals(rm));
        rm2.setLastNotifiedTime(Timestamp.fromMillis(123456789125L));
        assertTrue(rm2.equals(rm));

        rm2.setAuditRef("audit2-ref");
        assertFalse(rm2.equals(rm));
        rm2.setAuditRef(null);
        assertFalse(rm2.equals(rm));
        rm2.setAuditRef("audit-ref");
        assertTrue(rm2.equals(rm));

        rm2.setActive(true);
        assertFalse(rm2.equals(rm));
        rm2.setActive(null);
        assertFalse(rm2.equals(rm));
        rm2.setActive(false);
        assertTrue(rm2.equals(rm));

        rm2.setApproved(false);
        assertFalse(rm2.equals(rm));
        rm2.setApproved(null);
        assertFalse(rm2.equals(rm));
        rm2.setApproved(true);
        assertTrue(rm2.equals(rm));

        rm2.setReviewLastNotifiedTime(Timestamp.fromMillis(123456789124L));
        assertFalse(rm2.equals(rm));
        rm2.setReviewLastNotifiedTime(null);
        assertFalse(rm2.equals(rm));
        rm2.setReviewLastNotifiedTime(Timestamp.fromMillis(123456789127L));
        assertTrue(rm2.equals(rm));

        rm2.setSystemDisabled(2);
        assertFalse(rm2.equals(rm));
        rm2.setSystemDisabled(null);
        assertFalse(rm2.equals(rm));
        rm2.setSystemDisabled(1);
        assertTrue(rm2.equals(rm));

        rm2.setPrincipalType(2);
        assertFalse(rm2.equals(rm));
        rm2.setPrincipalType(null);
        assertFalse(rm2.equals(rm));
        rm2.setPrincipalType(1);
        assertTrue(rm2.equals(rm));

        assertFalse(rm2.equals(null));

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

        assertTrue(mbr1.equals(mbr1));
        assertFalse(mbr1.equals(null));

        DomainGroupMember mbr2 = new DomainGroupMember();
        assertFalse(mbr2.equals(mbr1));

        mbr2.setMemberName("mbr2");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setMemberName("mbr1");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setMemberGroups(list2);
        assertFalse(mbr2.equals(mbr1));

        list2.add(new GroupMember().setGroupName("group1"));
        assertTrue(mbr2.equals(mbr1));

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

        assertTrue(mbr1.equals(mbr1));
        assertFalse(mbr1.equals(null));

        DomainGroupMembers mbr2 = new DomainGroupMembers();
        assertFalse(mbr2.equals(mbr1));

        mbr2.setDomainName("dom2");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setDomainName("dom1");
        assertFalse(mbr2.equals(mbr1));

        mbr2.setMembers(list2);
        assertFalse(mbr2.equals(mbr1));

        list2.add(new DomainGroupMember().setMemberName("mbr1"));
        assertTrue(mbr2.equals(mbr1));
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
        assertFalse(rsm2.equals(rsm));
        rsm2.setAuditEnabled(false);
        assertTrue(rsm2.equals(rsm));
        assertTrue(rsm.equals(rsm));

        rsm2.setAuditEnabled(null);
        assertFalse(rsm2.equals(rsm));

        assertFalse(rsm2.equals(null));
        assertFalse(rsm.equals(new String()));
    }

    @Test
    public void testGroupMetaMethod() {

        GroupMeta rm = new GroupMeta()
                .setSelfServe(false)
                .setNotifyRoles("role1,domain:role.role2")
                .setReviewEnabled(false)
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3");
        assertTrue(rm.equals(rm));

        assertFalse(rm.getSelfServe());
        assertEquals(rm.getNotifyRoles(), "role1,domain:role.role2");
        assertFalse(rm.getReviewEnabled());
        assertEquals(rm.getUserAuthorityExpiration(), "attr1");
        assertEquals(rm.getUserAuthorityFilter(), "attr2,attr3");

        GroupMeta rm2 = new GroupMeta()
                .setSelfServe(false)
                .setNotifyRoles("role1,domain:role.role2")
                .setReviewEnabled(false)
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3");
        assertTrue(rm2.equals(rm));

        rm2.setNotifyRoles("role1");
        assertFalse(rm2.equals(rm));
        rm2.setNotifyRoles(null);
        assertFalse(rm2.equals(rm));
        rm2.setNotifyRoles("role1,domain:role.role2");
        assertTrue(rm2.equals(rm));

        rm2.setReviewEnabled(true);
        assertFalse(rm2.equals(rm));
        rm2.setReviewEnabled(null);
        assertFalse(rm2.equals(rm));
        rm2.setReviewEnabled(false);
        assertTrue(rm2.equals(rm));

        rm2.setSelfServe(true);
        assertFalse(rm2.equals(rm));
        rm2.setSelfServe(null);
        assertFalse(rm2.equals(rm));
        rm2.setSelfServe(false);
        assertTrue(rm2.equals(rm));

        rm2.setUserAuthorityExpiration("attr11");
        assertFalse(rm2.equals(rm));
        rm2.setUserAuthorityExpiration(null);
        assertFalse(rm2.equals(rm));
        rm2.setUserAuthorityExpiration("attr1");
        assertTrue(rm2.equals(rm));

        rm2.setUserAuthorityFilter("attr2");
        assertFalse(rm2.equals(rm));
        rm2.setUserAuthorityFilter(null);
        assertFalse(rm2.equals(rm));
        rm2.setUserAuthorityFilter("attr2,attr3");
        assertTrue(rm2.equals(rm));

        assertFalse(rm2.equals(null));
        assertFalse(rm.equals(new String()));

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Result result = validator.validate(rm, "GroupMeta");
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
                .setSystemDisabled(1);

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

        GroupMembership ms2 = new GroupMembership().setMemberName("test.member").setIsMember(false)
                .setExpiration(Timestamp.fromMillis(100)).setGroupName("group1")
                .setActive(true).setAuditRef("audit-ref").setApproved(false)
                .setRequestPrincipal("user.admin").setSystemDisabled(1);

        assertTrue(ms2.equals(ms));
        assertTrue(ms.equals(ms));

        ms2.setRequestPrincipal("user.test2");
        assertFalse(ms2.equals(ms));
        ms2.setRequestPrincipal(null);
        assertFalse(ms2.equals(ms));
        ms2.setRequestPrincipal("user.admin");
        assertTrue(ms2.equals(ms));

        ms2.setExpiration(null);
        assertFalse(ms2.equals(ms));
        ms2.setExpiration(Timestamp.fromMillis(100));
        assertTrue(ms2.equals(ms));

        ms2.setGroupName(null);
        assertFalse(ms2.equals(ms));
        ms2.setGroupName("group1");
        assertTrue(ms2.equals(ms));

        ms2.setIsMember(null);
        assertFalse(ms2.equals(ms));
        ms2.setIsMember(false);
        assertTrue(ms2.equals(ms));

        ms2.setMemberName(null);
        assertFalse(ms2.equals(ms));
        ms2.setMemberName("test.member");
        assertTrue(ms2.equals(ms));

        ms2.setAuditRef(null);
        assertFalse(ms2.equals(ms));
        ms2.setAuditRef("audit-ref");
        assertTrue(ms2.equals(ms));

        ms2.setActive(null);
        assertFalse(ms2.equals(ms));
        ms2.setActive(true);
        assertTrue(ms2.equals(ms));

        ms2.setApproved(null);
        assertFalse(ms2.equals(ms));
        ms2.setApproved(true);
        assertFalse(ms2.equals(ms));
        ms2.setApproved(false);
        assertTrue(ms2.equals(ms));

        ms2.setSystemDisabled(2);
        assertFalse(ms2.equals(ms));
        ms2.setSystemDisabled(null);
        assertFalse(ms2.equals(ms));
        ms2.setSystemDisabled(1);
        assertTrue(ms2.equals(ms));

        assertFalse(ms2.equals(null));
        assertFalse(ms.equals(new String()));
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

        assertTrue(ral2.equals(ral));
        assertTrue(ral.equals(ral));

        ral2.setAuditRef(null);
        assertFalse(ral2.equals(ral));
        ral2.setAction(null);
        assertFalse(ral2.equals(ral));
        ral2.setCreated(null);
        assertFalse(ral2.equals(ral));
        ral2.setAdmin(null);
        assertFalse(ral2.equals(ral));
        ral2.setMember(null);
        assertFalse(ral2.equals(ral));
        assertFalse(ral2.equals(new String()));
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

        assertTrue(groupMembership2.equals(groupMembership1));
        assertTrue(groupMembership1.equals(groupMembership1));
        assertFalse(groupMembership1.equals(null));
        assertFalse(groupMembership1.equals(new String()));

        List<DomainGroupMembers> list3 = Collections.emptyList();

        groupMembership2.setDomainGroupMembersList(list3);
        assertFalse(groupMembership2.equals(groupMembership1));
        groupMembership2.setDomainGroupMembersList(null);
        assertFalse(groupMembership2.equals(groupMembership1));
        groupMembership2.setDomainGroupMembersList(list2);
    }
}
