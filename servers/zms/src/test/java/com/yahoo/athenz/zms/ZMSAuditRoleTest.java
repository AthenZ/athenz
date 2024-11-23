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

import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.*;

import java.util.List;

import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class ZMSAuditRoleTest {

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

        DynamicConfigBoolean dynamicConfigBoolean = Mockito.mock(DynamicConfigBoolean.class);
        when(dynamicConfigBoolean.get()).thenReturn(true);
        zmsTestInitializer.getZms().validateUserRoleMembers = dynamicConfigBoolean;
    }

    @AfterMethod
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
    }

    @Test
    public void testAuditRoleFailures() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName1 = "audit-role-not-domain";
        final String domainName2 = "audit-role-with-members";
        final String roleName1 = "role";
        final String roleName2 = "role";
        final String roleName3 = "role3";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", "user.user1");
        dom2.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        // should be rejected since the domain is not audit enabled

        Role role1 = zmsTestInitializer.createRoleObject(domainName1, roleName1, null,
                "user.user1", "user.joe");
        role1.setAuditEnabled(true);
        try {
            zmsImpl.putRole(ctx, domainName1, roleName1, auditRef, false, null, role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("domain is not audit-enabled"));
        }

        // create a role with members in domain2 without audit enabled

        Role role2 = zmsTestInitializer.createRoleObject(domainName2, roleName2, null,
                "user.user1", "user.joe");
        zmsImpl.putRole(ctx, domainName2, roleName2, auditRef, false, null, role2);

        // modify the role and set audit enabled flag

        role2.setAuditEnabled(true);
        try {
            zmsImpl.putRole(ctx, domainName2, roleName2, auditRef, false, null, role2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Only system admins can set the role as audit-enabled if it has members"));
        }

        // create a role with audit enabled flag

        Role role3 = zmsTestInitializer.createRoleObject(domainName2, roleName3, null,
                "user.user1", "user.joe");
        role3.setAuditEnabled(true);

        zmsImpl.putRole(ctx, domainName2, roleName3, auditRef, false, null, role3);

        // now try to modify the role and remove the audit enabled flag

        role3.setAuditEnabled(false);
        try {
            zmsImpl.putRole(ctx, domainName2, roleName3, auditRef, false, null, role3);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Only system admins can remove the audit-enabled flag from a role"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
    }

    @Test
    public void testAuditRoleChanges() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-role-no-changes";
        final String roleName = "role1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Approval Test Domain1",
                "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role auditedRole = zmsTestInitializer.createRoleObject(domainName, roleName, null,
                "user.john", "user.jane");
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);
        RoleSystemMeta rsm = ZMSTestUtils.createRoleSystemMetaObject(true);
        zmsImpl.putRoleSystemMeta(ctx, domainName, roleName, "auditenabled", auditRef, rsm);

        Role resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 2);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jane", true);

        // now let's put the same role with audit flag enabled, and it
        // should be successful since there are no changes

        auditedRole.setAuditEnabled(true);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);

        resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 2);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jane", true);

        // now let's add a new member using putMembership

        Membership mbr = new Membership();
        mbr.setMemberName("user.bob");
        mbr.setActive(false);
        mbr.setApproved(false);
        zmsImpl.putMembership(ctx, domainName, roleName, "user.bob", auditRef, false, null, mbr);

        // verify the response that we have 1 pending member

        resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 3);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jane", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.bob", false);

        // now let's put the role again with audit flag enabled
        // with user.bob which should be converted to pending

        auditedRole.setAuditEnabled(true);
        auditedRole.getRoleMembers().add(new RoleMember().setMemberName("user.bob"));
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);

        resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 3);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jane", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.bob", false);

        // now let's add one more user and delete another user

        auditedRole.getRoleMembers().add(new RoleMember().setMemberName("user.jack"));
        auditedRole.getRoleMembers().removeIf(rm -> "user.jane".equals(rm.getMemberName()));
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);

        resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 3);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jack", false);
        verifyRoleMember(resrole.getRoleMembers(), "user.bob", false);

        // now let's remove a temporary user. this is not going to remove
        // our temporary member since those are not handled by the putRole call

        auditedRole.getRoleMembers().removeIf(rm -> "user.bob".equals(rm.getMemberName()));
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);

        resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 3);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jack", false);
        verifyRoleMember(resrole.getRoleMembers(), "user.bob", false);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testNewAuditRoleSetup() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-role-new-setup";
        final String roleName = "role1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Approval Test Domain1",
                "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role auditedRole = zmsTestInitializer.createRoleObject(domainName, roleName, null,
                "user.john", "user.jane");
        auditedRole.setAuditEnabled(true);

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);

        // both users should be added as pending users

        Role resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 2);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", false);
        verifyRoleMember(resrole.getRoleMembers(), "user.jane", false);

        // let's process the same role without any new members

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);

        // both users should still be presented as pending users

        resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 2);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", false);
        verifyRoleMember(resrole.getRoleMembers(), "user.jane", false);

        // now let's add one more user to the list

        auditedRole.getRoleMembers().add(new RoleMember().setMemberName("user.jack"));

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);

        // both users should still be presented as pending users

        resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 3);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", false);
        verifyRoleMember(resrole.getRoleMembers(), "user.jane", false);
        verifyRoleMember(resrole.getRoleMembers(), "user.jack", false);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditRoleChangesWithExpiry() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-role-expiry-changes";
        final String roleName = "role1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Approval Test Domain1",
                "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role auditedRole = zmsTestInitializer.createRoleObject(domainName, roleName, null,
                "user.john", "user.jane");
        auditedRole.getRoleMembers().add(new RoleMember().setMemberName("user.jack")
                .setExpiration(Timestamp.fromMillis(10000L)));

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);

        RoleSystemMeta rsm = ZMSTestUtils.createRoleSystemMetaObject(true);
        zmsImpl.putRoleSystemMeta(ctx, domainName, roleName, "auditenabled", auditRef, rsm);

        Role resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 3);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jane", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jack", true);

        // now let's put the role with updated expiry dates for the users

        auditedRole.setAuditEnabled(true);
        for (RoleMember rmem : auditedRole.getRoleMembers()) {
            if ("user.john".equals(rmem.getMemberName())) {
                rmem.setExpiration(Timestamp.fromMillis(20000L));
            } else if ("user.jack".equals(rmem.getMemberName())) {
                rmem.setExpiration(Timestamp.fromMillis(30000L));
            }
        }

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, auditedRole);

        // we should now get both standard and pending users for john and jack

        resrole = zmsImpl.getRole(ctx, domainName, roleName, false, false, true);
        assertEquals(resrole.getRoleMembers().size(), 5);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jane", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.jack", true);
        verifyRoleMember(resrole.getRoleMembers(), "user.john", false);
        verifyRoleMember(resrole.getRoleMembers(), "user.jack", false);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    void verifyRoleMember(List<RoleMember> roleMembers, String memberName, boolean approved) {
        for (RoleMember rmem : roleMembers) {
            if (memberName.equals(rmem.getMemberName()) && rmem.getApproved() == approved) {
                return;
            }
        }
        fail("Member " + memberName + " not found in role members with approved state of " + approved);
    }
}
