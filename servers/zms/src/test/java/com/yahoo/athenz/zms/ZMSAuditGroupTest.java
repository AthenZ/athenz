/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms;

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.*;

import java.util.List;

import static org.testng.Assert.*;

public class ZMSAuditGroupTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
    }

    @Test
    public void testAuditGroupFailures() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName1 = "audit-group-not-domain";
        final String domainName2 = "audit-group-with-members";
        final String groupName1 = "group";
        final String groupName2 = "group";
        final String groupName3 = "group2";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", "user.user1");
        dom2.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        // should be rejected since the domain is not audit enabled

        Group group1 = zmsTestInitializer.createGroupObject(domainName1, groupName1,
                "user.user1", "user.joe");
        group1.setAuditEnabled(true);
        try {
            zmsImpl.putGroup(ctx, domainName1, groupName1, auditRef, false, null, group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("domain is not audit-enabled"));
        }

        // create a group with members in domain2 without audit enabled

        Group group2 = zmsTestInitializer.createGroupObject(domainName2, groupName2,
                "user.user1", "user.joe");
        zmsImpl.putGroup(ctx, domainName2, groupName2, auditRef, false, null, group2);

        // modify the group and set audit enabled flag

        group2.setAuditEnabled(true);
        try {
            zmsImpl.putGroup(ctx, domainName2, groupName2, auditRef, false, null, group2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Only system admins can set the group as audit-enabled if it has members"));
        }

        // create a group with audit enabled flag

        Group group3 = zmsTestInitializer.createGroupObject(domainName2, groupName3,
                "user.user1", "user.joe");
        group3.setAuditEnabled(true);

        zmsImpl.putGroup(ctx, domainName2, groupName3, auditRef, false, null, group3);

        // now try to modify the group and remove the audit enabled flag

        group3.setAuditEnabled(false);
        try {
            zmsImpl.putGroup(ctx, domainName2, groupName3, auditRef, false, null, group3);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Only system admins can remove the audit-enabled flag from a group"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
    }

    @Test
    public void testAuditGroupChanges() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-group-no-changes";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Approval Test Domain1",
                "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group auditedGroup = zmsTestInitializer.createGroupObject(domainName, groupName,
                "user.john", "user.jane");
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);
        GroupSystemMeta rsm = ZMSTestUtils.createGroupSystemMetaObject(true);
        zmsImpl.putGroupSystemMeta(ctx, domainName, groupName, "auditenabled", auditRef, rsm);

        Group resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 2);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jane", true);

        // now let's put the same group with audit flag enabled, and it
        // should be successful since there are no changes

        auditedGroup.setAuditEnabled(true);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);

        resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 2);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jane", true);

        // now let's add a new member using putGroupMembership

        GroupMembership mbr = new GroupMembership();
        mbr.setMemberName("user.bob");
        mbr.setActive(false);
        mbr.setApproved(false);
        zmsImpl.putGroupMembership(ctx, domainName, groupName, "user.bob", auditRef, false, null, mbr);

        // verify the response that we have 1 pending member

        resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 3);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jane", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.bob", false);

        // now let's put the group again with audit flag enabled
        // with user.bob which should be converted to pending

        auditedGroup.setAuditEnabled(true);
        auditedGroup.getGroupMembers().add(new GroupMember().setMemberName("user.bob"));
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);

        resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 3);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jane", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.bob", false);

        // now let's add one more user and delete another user

        auditedGroup.getGroupMembers().add(new GroupMember().setMemberName("user.jack"));
        auditedGroup.getGroupMembers().removeIf(rm -> "user.jane".equals(rm.getMemberName()));
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);

        resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 3);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jack", false);
        verifyGroupMember(resgroup.getGroupMembers(), "user.bob", false);

        // now let's remove a temporary user. this is not going to remove
        // our temporary member since those are not handled by the putGroup call

        auditedGroup.getGroupMembers().removeIf(rm -> "user.bob".equals(rm.getMemberName()));
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);

        resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 3);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jack", false);
        verifyGroupMember(resgroup.getGroupMembers(), "user.bob", false);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testNewAuditGroupSetup() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-group-new-setup";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Approval Test Domain1",
                "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group auditedGroup = zmsTestInitializer.createGroupObject(domainName, groupName,
                "user.john", "user.jane");
        auditedGroup.setAuditEnabled(true);

        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);

        // both users should be added as pending users

        Group resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 2);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", false);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jane", false);

        // let's process the same group without any new members

        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);

        // both users should still be presented as pending users

        resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 2);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", false);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jane", false);

        // now let's add one more user to the list

        auditedGroup.getGroupMembers().add(new GroupMember().setMemberName("user.jack"));

        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);

        // both users should still be presented as pending users

        resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 3);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", false);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jane", false);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jack", false);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditGroupChangesWithExpiry() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-group-expiry-changes";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Approval Test Domain1",
                "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group auditedGroup = zmsTestInitializer.createGroupObject(domainName, groupName,
                "user.john", "user.jane");
        auditedGroup.getGroupMembers().add(new GroupMember().setMemberName("user.jack")
                .setExpiration(Timestamp.fromMillis(10000L)));

        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);

        GroupSystemMeta rsm = ZMSTestUtils.createGroupSystemMetaObject(true);
        zmsImpl.putGroupSystemMeta(ctx, domainName, groupName, "auditenabled", auditRef, rsm);

        Group resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 3);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jane", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jack", true);

        // now let's put the group with updated expiry dates for the users

        for (GroupMember rmem : auditedGroup.getGroupMembers()) {
            if ("user.john".equals(rmem.getMemberName())) {
                rmem.setExpiration(Timestamp.fromMillis(20000L));
            } else if ("user.jack".equals(rmem.getMemberName())) {
                rmem.setExpiration(Timestamp.fromMillis(30000L));
            }
        }

        auditedGroup.setAuditEnabled(true);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, auditedGroup);

        // we should now get both standard and pending users for john and jack

        resgroup = zmsImpl.getGroup(ctx, domainName, groupName, false, true);
        assertEquals(resgroup.getGroupMembers().size(), 5);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jane", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jack", true);
        verifyGroupMember(resgroup.getGroupMembers(), "user.john", false);
        verifyGroupMember(resgroup.getGroupMembers(), "user.jack", false);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    void verifyGroupMember(List<GroupMember> groupMembers, String memberName, boolean approved) {
        for (GroupMember rmem : groupMembers) {
            if (memberName.equals(rmem.getMemberName()) && rmem.getApproved() == approved) {
                return;
            }
        }
        fail("Member " + memberName + " not found in group members with approved state of " + approved);
    }
}
