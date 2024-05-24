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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;
import static org.testng.Assert.assertTrue;

public class ZMSExpiryTest {

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
        MockitoAnnotations.openMocks(this);
        zmsTestInitializer.setUp();
    }

    @Test
    public void testRoleExpiryWithAuthority() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // add a role with an elevated clearance option

        final String domainName = "role-expiry-with-authority";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // create a role with 2 members with no expiry

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.john"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        roleMembers.add(new RoleMember().setMemberName("user.joe"));

        final String roleName1 = "expiry-role1";
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName1, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName1, auditRef, false, null, role1);

        final String roleName2 = "expiry-role2";
        Role role2 = zmsTestInitializer.createRoleObject(domainName, roleName2, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName2, auditRef, false, null, role2);

        Authority savedAuthority = zmsImpl.userAuthority;
        Authority authority = Mockito.mock(Authority.class);
        Set<String> attrs = new HashSet<>();
        attrs.add("elevated-clearance");
        when(authority.dateAttributesSupported()).thenReturn(attrs);
        Timestamp days15 = ZMSTestUtils.addDays(Timestamp.fromCurrentTime(), 15);
        Timestamp days45 = ZMSTestUtils.addDays(Timestamp.fromCurrentTime(), 45);
        when(authority.getDateAttribute("user.john", "elevated-clearance")).thenReturn(days45.toDate());
        when(authority.getDateAttribute("user.jane", "elevated-clearance")).thenReturn(days15.toDate());
        when(authority.getDateAttribute("user.joe", "elevated-clearance")).thenReturn(null);
        when(authority.getDateAttribute("user.john1", "elevated-clearance")).thenReturn(days45.toDate());
        when(authority.getDateAttribute("user.jane1", "elevated-clearance")).thenReturn(days15.toDate());
        when(authority.getDateAttribute("user.joe1", "elevated-clearance")).thenReturn(null);
        zmsImpl.userAuthority = authority;
        zmsImpl.dbService.zmsConfig.setUserAuthority(authority);

        // let's set the meta attributes for expiry and authority expiry

        RoleMeta rm1 = new RoleMeta().setMemberExpiryDays(30).setUserAuthorityExpiration("elevated-clearance");
        zmsImpl.putRoleMeta(ctx, domainName, roleName1, auditRef, null, rm1);

        RoleMeta rm2 = new RoleMeta().setUserAuthorityExpiration("elevated-clearance");
        zmsImpl.putRoleMeta(ctx, domainName, roleName2, auditRef, null, rm2);

        // now let's retrieve the roles and verify the expiry

        Role role1Res = zmsImpl.getRole(ctx, domainName, roleName1, false, false, false);
        assertNotNull(role1Res);

        // john should have 30 days user expiry since elevated clearance is 45
        RoleMember userJohn = ZMSTestUtils.getRoleMember(role1Res, "user.john");
        assertTrue(ZMSTestUtils.validateDueDate(userJohn.getExpiration().millis(), 30L * 24 * 60 * 60 * 1000));

        // jane should have 15 days user expiry since elevated clearance is 15
        RoleMember userJane = ZMSTestUtils.getRoleMember(role1Res, "user.jane");
        assertTrue(ZMSTestUtils.validateDueDate(userJane.getExpiration().millis(), 15L * 24 * 60 * 60 * 1000));

        // joe has no expiry so it must be expired
        RoleMember userJoe = ZMSTestUtils.getRoleMember(role1Res, "user.joe");
        assertTrue(ZMSTestUtils.validateDueDate(userJoe.getExpiration().millis(), 0));

        // role2 is standard user authority expiry

        Role role2Res = zmsImpl.getRole(ctx, domainName, roleName2, false, false, false);
        assertNotNull(role2Res);

        userJohn = ZMSTestUtils.getRoleMember(role2Res, "user.john");
        assertTrue(ZMSTestUtils.validateDueDate(userJohn.getExpiration().millis(), 45L * 24 * 60 * 60 * 1000));

        userJane = ZMSTestUtils.getRoleMember(role2Res, "user.jane");
        assertTrue(ZMSTestUtils.validateDueDate(userJane.getExpiration().millis(), 15L * 24 * 60 * 60 * 1000));

        userJoe = ZMSTestUtils.getRoleMember(role2Res, "user.joe");
        assertTrue(ZMSTestUtils.validateDueDate(userJoe.getExpiration().millis(), 0));

        // add a new member john1 to both roles and verify expected outcome

        Membership mbrJohn1 = new Membership().setRoleName(roleName1).setMemberName("user.john1");
        zmsImpl.putMembership(ctx, domainName, roleName1, "user.john1", auditRef, false, null, mbrJohn1);
        role1Res = zmsImpl.getRole(ctx, domainName, roleName1, false, false, false);
        RoleMember userJohn1 = ZMSTestUtils.getRoleMember(role1Res, "user.john1");
        assertTrue(ZMSTestUtils.validateDueDate(userJohn1.getExpiration().millis(), 30L * 24 * 60 * 60 * 1000));

        mbrJohn1 = new Membership().setRoleName(roleName2).setMemberName("user.john1");
        zmsImpl.putMembership(ctx, domainName, roleName2, "user.john1", auditRef, false, null, mbrJohn1);
        role2Res = zmsImpl.getRole(ctx, domainName, roleName2, false, false, false);
        userJohn1 = ZMSTestUtils.getRoleMember(role2Res, "user.john1");
        assertTrue(ZMSTestUtils.validateDueDate(userJohn1.getExpiration().millis(), 45L * 24 * 60 * 60 * 1000));

        // add jane1 to both roles and verify expected outcome

        Membership mbrJane1 = new Membership().setRoleName(roleName1).setMemberName("user.jane1");
        zmsImpl.putMembership(ctx, domainName, roleName1, "user.jane1", auditRef, false, null, mbrJane1);
        role1Res = zmsImpl.getRole(ctx, domainName, roleName1, false, false, false);
        RoleMember userJane1 = ZMSTestUtils.getRoleMember(role1Res, "user.jane1");
        assertTrue(ZMSTestUtils.validateDueDate(userJane1.getExpiration().millis(), 15L * 24 * 60 * 60 * 1000));

        mbrJane1 = new Membership().setRoleName(roleName2).setMemberName("user.jane1");
        zmsImpl.putMembership(ctx, domainName, roleName2, "user.jane1", auditRef, false, null, mbrJane1);
        role2Res = zmsImpl.getRole(ctx, domainName, roleName2, false, false, false);
        userJane1 = ZMSTestUtils.getRoleMember(role2Res, "user.jane1");
        assertTrue(ZMSTestUtils.validateDueDate(userJane1.getExpiration().millis(), 15L * 24 * 60 * 60 * 1000));

        // add joe1 to both roles and verify expected outcome

        try {
            Membership mbrJoe1 = new Membership().setRoleName(roleName1).setMemberName("user.joe1");
            zmsImpl.putMembership(ctx, domainName, roleName1, "user.joe1", auditRef, false, null, mbrJoe1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("User does not have required user authority expiry configured"));
        }

        try {
            Membership mbrJoe1 = new Membership().setRoleName(roleName2).setMemberName("user.joe1");
            zmsImpl.putMembership(ctx, domainName, roleName2, "user.joe1", auditRef, false, null, mbrJoe1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("User does not have required user authority expiry configured"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zmsImpl.userAuthority = savedAuthority;
    }

    @Test
    public void testGroupExpiryWithAuthority() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // add a role with an elevated clearance option

        final String domainName = "group-expiry-with-authority";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // create a role with 2 members with no expiry

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.john"));
        groupMembers.add(new GroupMember().setMemberName("user.jane"));
        groupMembers.add(new GroupMember().setMemberName("user.joe"));

        final String groupName1 = "expiry-group1";
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName1, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName1, auditRef, false, null, group1);

        final String groupName2 = "expiry-group2";
        Group group2 = zmsTestInitializer.createGroupObject(domainName, groupName2, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName2, auditRef, false, null, group2);

        Authority savedAuthority = zmsImpl.userAuthority;
        Authority authority = Mockito.mock(Authority.class);
        Set<String> attrs = new HashSet<>();
        attrs.add("elevated-clearance");
        when(authority.dateAttributesSupported()).thenReturn(attrs);
        when(authority.isValidUser(any())).thenReturn(true);
        Timestamp days15 = ZMSTestUtils.addDays(Timestamp.fromCurrentTime(), 15);
        Timestamp days45 = ZMSTestUtils.addDays(Timestamp.fromCurrentTime(), 45);
        when(authority.getDateAttribute("user.john", "elevated-clearance")).thenReturn(days45.toDate());
        when(authority.getDateAttribute("user.jane", "elevated-clearance")).thenReturn(days15.toDate());
        when(authority.getDateAttribute("user.joe", "elevated-clearance")).thenReturn(null);
        when(authority.getDateAttribute("user.john1", "elevated-clearance")).thenReturn(days45.toDate());
        when(authority.getDateAttribute("user.jane1", "elevated-clearance")).thenReturn(days15.toDate());
        when(authority.getDateAttribute("user.joe1", "elevated-clearance")).thenReturn(null);

        zmsImpl.userAuthority = authority;
        zmsImpl.dbService.zmsConfig.setUserAuthority(authority);

        // let's set the meta attributes for expiry and authority expiry

        GroupMeta gm1 = new GroupMeta().setMemberExpiryDays(30).setUserAuthorityExpiration("elevated-clearance");
        zmsImpl.putGroupMeta(ctx, domainName, groupName1, auditRef, null, gm1);

        GroupMeta gm2 = new GroupMeta().setUserAuthorityExpiration("elevated-clearance");
        zmsImpl.putGroupMeta(ctx, domainName, groupName2, auditRef, null, gm2);

        // now let's retrieve the roles and verify the expiry

        Group group1Res = zmsImpl.getGroup(ctx, domainName, groupName1, false, false);
        assertNotNull(group1Res);

        // john should have 30 days user expiry since elevated clearance is 45
        GroupMember userJohn = ZMSTestUtils.getGroupMember(group1Res, "user.john");
        assertTrue(ZMSTestUtils.validateDueDate(userJohn.getExpiration().millis(), 30L * 24 * 60 * 60 * 1000));

        // jane should have 15 days user expiry since elevated clearance is 15
        GroupMember userJane = ZMSTestUtils.getGroupMember(group1Res, "user.jane");
        assertTrue(ZMSTestUtils.validateDueDate(userJane.getExpiration().millis(), 15L * 24 * 60 * 60 * 1000));

        // joe has no expiry so it must be expired
        GroupMember userJoe = ZMSTestUtils.getGroupMember(group1Res, "user.joe");
        assertTrue(ZMSTestUtils.validateDueDate(userJoe.getExpiration().millis(), 0));

        // role2 is standard user authority expiry

        Group group2Res = zmsImpl.getGroup(ctx, domainName, groupName2, false, false);
        assertNotNull(group2Res);

        userJohn = ZMSTestUtils.getGroupMember(group2Res, "user.john");
        assertTrue(ZMSTestUtils.validateDueDate(userJohn.getExpiration().millis(), 45L * 24 * 60 * 60 * 1000));

        userJane = ZMSTestUtils.getGroupMember(group2Res, "user.jane");
        assertTrue(ZMSTestUtils.validateDueDate(userJane.getExpiration().millis(), 15L * 24 * 60 * 60 * 1000));

        userJoe = ZMSTestUtils.getGroupMember(group2Res, "user.joe");
        assertTrue(ZMSTestUtils.validateDueDate(userJoe.getExpiration().millis(), 0));

        // add a new member john1 to both roles and verify expected outcome

        GroupMembership mbrJohn1 = new GroupMembership().setGroupName(groupName1).setMemberName("user.john1");
        zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.john1", auditRef, false, null, mbrJohn1);
        group1Res = zmsImpl.getGroup(ctx, domainName, groupName1, false, false);
        GroupMember userJohn1 = ZMSTestUtils.getGroupMember(group1Res, "user.john1");
        assertTrue(ZMSTestUtils.validateDueDate(userJohn1.getExpiration().millis(), 30L * 24 * 60 * 60 * 1000));

        mbrJohn1 = new GroupMembership().setGroupName(groupName2).setMemberName("user.john1");
        zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.john1", auditRef, false, null, mbrJohn1);
        group2Res = zmsImpl.getGroup(ctx, domainName, groupName2, false, false);
        userJohn1 = ZMSTestUtils.getGroupMember(group2Res, "user.john1");
        assertTrue(ZMSTestUtils.validateDueDate(userJohn1.getExpiration().millis(), 45L * 24 * 60 * 60 * 1000));

        // add jane1 to both roles and verify expected outcome

        GroupMembership mbrJane1 = new GroupMembership().setGroupName(groupName1).setMemberName("user.jane1");
        zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.jane1", auditRef, false, null, mbrJane1);
        group1Res = zmsImpl.getGroup(ctx, domainName, groupName1, false, false);
        GroupMember userJane1 = ZMSTestUtils.getGroupMember(group1Res, "user.jane1");
        assertTrue(ZMSTestUtils.validateDueDate(userJane1.getExpiration().millis(), 15L * 24 * 60 * 60 * 1000));

        mbrJane1 = new GroupMembership().setGroupName(groupName2).setMemberName("user.jane1");
        zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.jane1", auditRef, false, null, mbrJane1);
        group2Res = zmsImpl.getGroup(ctx, domainName, groupName2, false, false);
        userJane1 = ZMSTestUtils.getGroupMember(group2Res, "user.jane1");
        assertTrue(ZMSTestUtils.validateDueDate(userJane1.getExpiration().millis(), 15L * 24 * 60 * 60 * 1000));

        // add joe1 to both roles and verify expected outcome

        try {
            GroupMembership mbrJoe1 = new GroupMembership().setGroupName(groupName1).setMemberName("user.joe1");
            zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.joe1", auditRef, false, null, mbrJoe1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("User does not have required user authority expiry configured"));
        }

        try {
            GroupMembership mbrJoe1 = new GroupMembership().setGroupName(groupName2).setMemberName("user.joe1");
            zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.joe1", auditRef, false, null, mbrJoe1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("User does not have required user authority expiry configured"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zmsImpl.userAuthority = savedAuthority;
    }
}
