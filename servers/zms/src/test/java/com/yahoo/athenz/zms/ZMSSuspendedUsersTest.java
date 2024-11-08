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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import org.mockito.Mockito;
import org.testng.annotations.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class ZMSSuspendedUsersTest {

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
    public void testRoleSuspendedMemberNotPresent() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);

        // check response with an empty role members first

        Role emptyRole = new Role().setName("athenz:role.role1");

        assertTrue(zmsImpl.suspendedMemberNotPresent(emptyRole, "user.user1"));
        assertTrue(zmsImpl.suspendedMemberNotPresent(emptyRole, "user.user2"));

        // now verify with different role members

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user1"));
        roleMembers.add(new RoleMember().setMemberName("user.user2")
                .setSystemDisabled(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue()));
        roleMembers.add(new RoleMember().setMemberName("user.user3")
                .setSystemDisabled(Principal.State.ATHENZ_SYSTEM_DISABLED.getValue()));
        roleMembers.add(new RoleMember().setMemberName("user.user4")
                .setSystemDisabled(Principal.State.ATHENZ_SYSTEM_DISABLED.getValue() | Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue()));
        Role role = new Role().setName("athenz:role.role2").setRoleMembers(roleMembers);

        assertTrue(zmsImpl.suspendedMemberNotPresent(role, "user.user1"));
        assertFalse(zmsImpl.suspendedMemberNotPresent(role, "user.user2"));
        assertTrue(zmsImpl.suspendedMemberNotPresent(role, "user.user3"));
        assertFalse(zmsImpl.suspendedMemberNotPresent(role, "user.user4"));
    }

    @Test
    public void testGroupSuspendedMemberNotPresent() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);

        // check response with an empty group members first

        Group emptyGroup = new Group().setName("athenz:group.group1");

        assertTrue(zmsImpl.suspendedMemberNotPresent(emptyGroup, "user.user1"));
        assertTrue(zmsImpl.suspendedMemberNotPresent(emptyGroup, "user.user2"));

        // now verify with different group members

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user1"));
        groupMembers.add(new GroupMember().setMemberName("user.user2")
                .setSystemDisabled(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue()));
        groupMembers.add(new GroupMember().setMemberName("user.user3")
                .setSystemDisabled(Principal.State.ATHENZ_SYSTEM_DISABLED.getValue()));
        groupMembers.add(new GroupMember().setMemberName("user.user4")
                .setSystemDisabled(Principal.State.ATHENZ_SYSTEM_DISABLED.getValue() | Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue()));
        Group group = new Group().setName("athenz:group.group2").setGroupMembers(groupMembers);

        assertTrue(zmsImpl.suspendedMemberNotPresent(group, "user.user1"));
        assertFalse(zmsImpl.suspendedMemberNotPresent(group, "user.user2"));
        assertTrue(zmsImpl.suspendedMemberNotPresent(group, "user.user3"));
        assertFalse(zmsImpl.suspendedMemberNotPresent(group, "user.user4"));
    }

    @Test
    public void testPostUserDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        final String auditRef = zmsTestInitializer.getAuditRef();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=john-doe;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx = zmsTestInitializer.createResourceContext(principal1);
        UserDomain dom1 = zmsTestInitializer.createUserDomainObject("john-doe", "Test Domain1", "testOrg");

        Authority savedAuthority = zmsImpl.userAuthority;

        Authority authority = Mockito.mock(Authority.class);
        when(authority.getUserType("user.john-doe")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zmsImpl.userAuthority = authority;

        try {
            zmsImpl.postUserDomain(rsrcCtx, "john-doe", auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("postUserDomain: User is suspended: user.john-doe"));
        }
        zmsImpl.userAuthority = savedAuthority;
    }

    @Test
    public void testPostTopLevelDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        Authority savedAuthority = zmsImpl.userAuthority;

        Authority authority = Mockito.mock(Authority.class);
        when(authority.getUserType("user.john-doe")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zmsImpl.userAuthority = authority;

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("test-domain-name",
                "Test Domain1", "testOrg", "user.john-doe");

        try {
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("User is suspended: user.john-doe"));
        }
        zmsImpl.userAuthority = savedAuthority;
    }

    @Test
    public void testValidateRoleMemberPrincipals() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        final String auditRef = zmsTestInitializer.getAuditRef();

        Authority savedAuthority = zmsImpl.userAuthority;

        Authority authority = Mockito.mock(Authority.class);
        when(authority.getUserType("user.user2")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zmsImpl.userAuthority = authority;

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user1").setPrincipalType(Principal.Type.USER.getValue()));
        roleMembers.add(new RoleMember().setMemberName("user.user2")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setSystemDisabled(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue()));
        Role role = new Role().setName("athenz:role.role2").setRoleMembers(roleMembers);

        // create original role 1 without the suspended user not present which
        // should cause our operation to fail

        List<RoleMember> originalRoleMembers = new ArrayList<>();
        originalRoleMembers.add(new RoleMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue()));
        Role originalRole = new Role().setName("athenz:role.role2").setRoleMembers(originalRoleMembers);

        try {
            zmsImpl.validateRoleMemberPrincipals(role, null, null, false, originalRole, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("User is suspended: user.user2"));
        }

        // now let's add the suspended user to the original role which would
        // cause our operation to succeed

        originalRoleMembers.add(new RoleMember().setMemberName("user.user2")
                .setSystemDisabled(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue()));
        zmsImpl.validateRoleMemberPrincipals(role, null, null, false, originalRole, auditRef);

        zmsImpl.userAuthority = savedAuthority;
    }

    @Test
    public void testPutMembership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "put-membership-suspended";
        final String roleName1 = "role1";
        final String roleName2 = "role2";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName1, null,
                "user.user1", "user.joe");
        zmsImpl.putRole(ctx, domainName, roleName1, auditRef, false, null, role1);

        Role role2 = zmsTestInitializer.createRoleObject(domainName, roleName2, null,
                "user.user1", "user.user2");
        zmsImpl.putRole(ctx, domainName, roleName2, auditRef, false, null, role2);

        Authority savedAuthority = zmsImpl.userAuthority;

        Authority authority = Mockito.mock(Authority.class);
        when(authority.getUserType("user.user2")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zmsImpl.userAuthority = authority;

        // first let's add to role1 which should fail since user2 is suspended
        // and not included in the original role

        try {
            Membership mbr = zmsTestInitializer.generateMembership(roleName1, "user.user2");
            zmsImpl.putMembership(ctx, domainName, roleName1, "user.user2", auditRef, false, null, mbr);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("User is suspended: user.user2"));
        }

        PrincipalMember member = new PrincipalMember().setPrincipalName("user.user2").setSuspendedState(0);
        zmsImpl.dbService.updatePrincipalByState(Collections.singletonList(member), true,
                Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue(), auditRef);

        // now let's add to role2 which should succeed since user2 is suspended
        // but is included in the original role

        Membership mbr = zmsTestInitializer.generateMembership(roleName2, "user.user2");
        zmsImpl.putMembership(ctx, domainName, roleName2, "user.user2", auditRef, false, null, mbr);

        zmsImpl.userAuthority = savedAuthority;
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutMembershipDecision() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "put-membership-suspended";
        final String roleName1 = "role1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1", "user.joe");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName1, null,
                "user.user1", "user.joe");
        zmsImpl.putRole(ctx, domainName, roleName1, auditRef, false, null, role1);

        RoleMeta rm = new RoleMeta().setReviewEnabled(true);
        zmsImpl.putRoleMeta(ctx, domainName, roleName1, auditRef, null, rm);

        // now let's add a member to the role which should be in pending state

        Membership mbr = zmsTestInitializer.generateMembership(roleName1, "user.user2");
        zmsImpl.putMembership(ctx, domainName, roleName1, "user.user2", auditRef, false, null, mbr);

        Authority savedAuthority = zmsImpl.userAuthority;

        Authority authority = Mockito.mock(Authority.class);
        when(authority.getUserType("user.user2")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zmsImpl.userAuthority = authority;

        // execute the decision which should fail since user2 is suspended

        mbr.setApproved(true).setActive(true);

        try {
            Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
            Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=joe;s=signature",
                    "10.11.12.13", "GET", null);
            ResourceContext rsrcCtx = zmsTestInitializer.createResourceContext(principal1);

            zmsImpl.putMembershipDecision(rsrcCtx, domainName, roleName1, "user.user2", auditRef, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("User is suspended: user.user2"));
        }

        zmsImpl.userAuthority = savedAuthority;
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateGroupMemberPrincipals() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        final String auditRef = zmsTestInitializer.getAuditRef();

        Authority savedAuthority = zmsImpl.userAuthority;

        Authority authority = Mockito.mock(Authority.class);
        when(authority.getUserType("user.user2")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zmsImpl.userAuthority = authority;

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user1").setPrincipalType(Principal.Type.USER.getValue()));
        groupMembers.add(new GroupMember().setMemberName("user.user2")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setSystemDisabled(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue()));
        Group group = new Group().setName("athenz:role.role2").setGroupMembers(groupMembers);

        // create original role 1 without the suspended user not present which
        // should cause our operation to fail

        List<GroupMember> originalGroupMembers = new ArrayList<>();
        originalGroupMembers.add(new GroupMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue()));
        Group originalGroup = new Group().setName("athenz:role.role2").setGroupMembers(originalGroupMembers);

        try {
            zmsImpl.validateGroupMemberPrincipals(group, null, null, originalGroup, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("User is suspended: user.user2"));
        }

        // now let's add the suspended user to the original role which would
        // cause our operation to succeed

        originalGroupMembers.add(new GroupMember().setMemberName("user.user2")
                .setSystemDisabled(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue()));
        zmsImpl.validateGroupMemberPrincipals(group, null, null, originalGroup, auditRef);

        zmsImpl.userAuthority = savedAuthority;
    }

    @Test
    public void testPutGroupMembership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "put-group-membership-suspended";
        final String groupName1 = "group1";
        final String groupName2 = "group2";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName1,
                "user.user1", "user.joe");
        zmsImpl.putGroup(ctx, domainName, groupName1, auditRef, false, null, group1);

        Group group2 = zmsTestInitializer.createGroupObject(domainName, groupName2,
                "user.user1", "user.user2");
        zmsImpl.putGroup(ctx, domainName, groupName2, auditRef, false, null, group2);

        Authority savedAuthority = zmsImpl.userAuthority;

        Authority authority = Mockito.mock(Authority.class);
        when(authority.getUserType("user.user2")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zmsImpl.userAuthority = authority;

        // first let's add to group1 which should fail since user2 is suspended
        // and not included in the original group

        try {
            GroupMembership mbr = zmsTestInitializer.generateGroupMembership(groupName1, "user.user2");
            zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.user2", auditRef, false, null, mbr);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("User is suspended: user.user2"));
        }

        PrincipalMember member = new PrincipalMember().setPrincipalName("user.user2").setSuspendedState(0);
        zmsImpl.dbService.updatePrincipalByState(Collections.singletonList(member), true,
                Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue(), auditRef);

        // now let's add to group2 which should succeed since user2 is suspended
        // but is included in the original group

        GroupMembership mbr = zmsTestInitializer.generateGroupMembership(groupName2, "user.user2");
        zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.user2", auditRef, false, null, mbr);

        zmsImpl.userAuthority = savedAuthority;
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutGroupMembershipDecision() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "put-group-membership-suspended";
        final String groupName1 = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1", "user.joe");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName1,
                "user.user1", "user.joe");
        zmsImpl.putGroup(ctx, domainName, groupName1, auditRef, false, null, group);

        GroupMeta gm = new GroupMeta().setReviewEnabled(true);
        zmsImpl.putGroupMeta(ctx, domainName, groupName1, auditRef, null, gm);

        // now let's add a member to the group which should be in pending state

        GroupMembership mbr = zmsTestInitializer.generateGroupMembership(groupName1, "user.user2");
        zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.user2", auditRef, false, null, mbr);

        Authority savedAuthority = zmsImpl.userAuthority;

        Authority authority = Mockito.mock(Authority.class);
        when(authority.getUserType("user.user2")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zmsImpl.userAuthority = authority;

        // execute the decision which should fail since user2 is suspended

        mbr.setApproved(true).setActive(true);

        try {
            Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
            Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=joe;s=signature",
                    "10.11.12.13", "GET", null);
            ResourceContext rsrcCtx = zmsTestInitializer.createResourceContext(principal1);

            zmsImpl.putGroupMembershipDecision(rsrcCtx, domainName, groupName1, "user.user2", auditRef, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("User is suspended: user.user2"));
        }

        zmsImpl.userAuthority = savedAuthority;
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
