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
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.rdl.Timestamp;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;

import static org.testng.Assert.*;

public class SelfRenewTest {

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

    @Test
    public void testIsRoleSelfRenewAllowed() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // first check for self serve option not set

        Role role = new Role().setSelfRenew(null);
        assertFalse(zmsImpl.isRoleSelfRenewAllowed(role, null, null));

        role.setSelfRenew(Boolean.FALSE);
        assertFalse(zmsImpl.isRoleSelfRenewAllowed(role, null, null));

        // next check for null or negative renew mins

        role.setSelfRenew(Boolean.TRUE);
        role.setSelfRenewMins(null);
        assertFalse(zmsImpl.isRoleSelfRenewAllowed(role, null, null));

        role.setSelfRenewMins(-1);
        assertFalse(zmsImpl.isRoleSelfRenewAllowed(role, null, null));

        role.setSelfRenewMins(0);
        assertFalse(zmsImpl.isRoleSelfRenewAllowed(role, null, null));

        // set a valid value for renew mins

        role.setSelfRenewMins(10);

        // next check for principal name mismatch

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=jane";
        Principal principal = SimplePrincipal.create("user", "jane", unsignedCreds + ";s=signature", 0, principalAuthority);

        RoleMember member = new RoleMember().setMemberName("user.joe");
        assertFalse(zmsImpl.isRoleSelfRenewAllowed(role, principal, member));

        // next check null role members

        member.setMemberName("user.jane");
        role.setRoleMembers(null);
        assertFalse(zmsImpl.isRoleSelfRenewAllowed(role, principal, member));

        // next check for mismatch for role members

        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.jack"));
        members.add(new RoleMember().setMemberName("user.doe"));
        role.setRoleMembers(members);

        assertFalse(zmsImpl.isRoleSelfRenewAllowed(role, principal, member));

        // finally add jane as a member

        members.add(new RoleMember().setMemberName("user.jane"));
        assertTrue(zmsImpl.isRoleSelfRenewAllowed(role, principal, member));
    }

    @Test
    public void testUpdateRoleMemberSelfRenewExpiration() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // member expiry null, we'll set an expiry

        RoleMember member = new RoleMember().setMemberName("user.jane").setExpiration(null);
        zmsImpl.updateRoleMemberSelfRenewExpiration(member, 10);
        assertNotNull(member.getExpiration());

        // the value should be between 9 and 11 minutes

        long currentTime = System.currentTimeMillis();
        assertTrue(member.getExpiration().millis() >= currentTime + 9 * 60 * 1000);
        assertTrue(member.getExpiration().millis() <= currentTime + 11 * 60 * 1000);

        // member expiry set longer than 10 minutes, we need to override it

        member.setExpiration(Timestamp.fromMillis(currentTime + 20 * 60 * 1000));
        zmsImpl.updateRoleMemberSelfRenewExpiration(member, 10);
        assertTrue(member.getExpiration().millis() >= currentTime + 9 * 60 * 1000);
        assertTrue(member.getExpiration().millis() <= currentTime + 11 * 60 * 1000);

        // finally set the expiry to be valid in 5 minutes - we should not override it

        Timestamp expiry = Timestamp.fromMillis(currentTime + 5 * 60 * 1000);
        member.setExpiration(expiry);
        zmsImpl.updateRoleMemberSelfRenewExpiration(member, 10);
        assertEquals(member.getExpiration(), expiry);
    }

    @Test
    public void testIsGroupSelfRenewAllowed() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // first check for self serve option not set

        Group group = new Group().setSelfRenew(null);
        assertFalse(zmsImpl.isGroupSelfRenewAllowed(group, null, null));

        group.setSelfRenew(Boolean.FALSE);
        assertFalse(zmsImpl.isGroupSelfRenewAllowed(group, null, null));

        // next check for null or negative renew mins

        group.setSelfRenew(Boolean.TRUE);
        group.setSelfRenewMins(null);
        assertFalse(zmsImpl.isGroupSelfRenewAllowed(group, null, null));

        group.setSelfRenewMins(-1);
        assertFalse(zmsImpl.isGroupSelfRenewAllowed(group, null, null));

        group.setSelfRenewMins(0);
        assertFalse(zmsImpl.isGroupSelfRenewAllowed(group, null, null));

        // set a valid value for renew mins

        group.setSelfRenewMins(10);

        // next check for principal name mismatch

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=jane";
        Principal principal = SimplePrincipal.create("user", "jane", unsignedCreds + ";s=signature", 0, principalAuthority);

        GroupMember member = new GroupMember().setMemberName("user.joe");
        assertFalse(zmsImpl.isGroupSelfRenewAllowed(group, principal, member));

        // next check null group members

        member.setMemberName("user.jane");
        group.setGroupMembers(null);
        assertFalse(zmsImpl.isGroupSelfRenewAllowed(group, principal, member));

        // next check for mismatch for group members

        List<GroupMember> members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.jack"));
        members.add(new GroupMember().setMemberName("user.doe"));
        group.setGroupMembers(members);

        assertFalse(zmsImpl.isGroupSelfRenewAllowed(group, principal, member));

        // finally add jane as a member

        members.add(new GroupMember().setMemberName("user.jane"));
        assertTrue(zmsImpl.isGroupSelfRenewAllowed(group, principal, member));
    }

    @Test
    public void testUpdateGroupMemberSelfRenewExpiration() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // member expiry null, we'll set an expiry

        GroupMember member = new GroupMember().setMemberName("user.jane").setExpiration(null);
        zmsImpl.updateGroupMemberSelfRenewExpiration(member, 10);
        assertNotNull(member.getExpiration());

        // the value should be between 9 and 11 minutes

        long currentTime = System.currentTimeMillis();
        assertTrue(member.getExpiration().millis() >= currentTime + 9 * 60 * 1000);
        assertTrue(member.getExpiration().millis() <= currentTime + 11 * 60 * 1000);

        // member expiry set longer than 10 minutes, we need to override it

        member.setExpiration(Timestamp.fromMillis(currentTime + 20 * 60 * 1000));
        zmsImpl.updateGroupMemberSelfRenewExpiration(member, 10);
        assertTrue(member.getExpiration().millis() >= currentTime + 9 * 60 * 1000);
        assertTrue(member.getExpiration().millis() <= currentTime + 11 * 60 * 1000);

        // finally set the expiry to be valid in 5 minutes - we should not override it

        Timestamp expiry = Timestamp.fromMillis(currentTime + 5 * 60 * 1000);
        member.setExpiration(expiry);
        zmsImpl.updateGroupMemberSelfRenewExpiration(member, 10);
        assertEquals(member.getExpiration(), expiry);
    }

    @Test
    public void testRoleSelfRenew() {

        final String domainName = "role-self-review";
        final String roleName = "role1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // Create a role with members

        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.jack"));
        members.add(new RoleMember().setMemberName("user.doe"));

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null, members);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        // create a principal for user.jane and try to execute put membership

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=jane";
        Principal principal = SimplePrincipal.create("user", "jane", unsignedCreds + ";s=signature", 0, principalAuthority);
        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        Membership membership = new Membership().setMemberName("user.jane");
        try {
            zmsImpl.putMembership(rsrcCtx1, domainName, roleName, "user.jane", auditRef, false, null, membership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        // now set the self serve flag to true and try again

        role.setSelfRenew(true);
        role.setSelfRenewMins(10);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        // we should get an exception since the user.jane is not a member

        try {
            zmsImpl.putMembership(rsrcCtx1, domainName, roleName, "user.jane", auditRef, false, null, membership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        // now add user.jane as a member and try again - this time it should work

        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.jack"));
        members.add(new RoleMember().setMemberName("user.doe"));
        members.add(new RoleMember().setMemberName("user.jane"));
        role.setRoleMembers(members);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        // now we should get a success

        zmsImpl.putMembership(rsrcCtx1, domainName, roleName, "user.jane", auditRef, false, null, membership);

        // get the user.jane member and verify expiration

        Membership membershipRes = zmsImpl.getMembership(ctx, domainName, roleName, "user.jane", null);
        assertNotNull(membershipRes);
        assertTrue(membershipRes.isMember);
        assertNotNull(membershipRes.getExpiration());

        long currentTime = System.currentTimeMillis();
        assertTrue(membershipRes.getExpiration().millis() >= currentTime + 9 * 60 * 1000);
        assertTrue(membershipRes.getExpiration().millis() <= currentTime + 11 * 60 * 1000);
    }

    @Test
    public void testGroupSelfRenew() {

        final String domainName = "group-self-review";
        final String groupName = "group1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // Create a group in domain with members

        List<GroupMember> members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.jack"));
        members.add(new GroupMember().setMemberName("user.doe"));

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, members);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        // create a principal for user.jane and try to execute put membership

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=jane";
        Principal principal = SimplePrincipal.create("user", "jane", unsignedCreds + ";s=signature", 0, principalAuthority);
        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        GroupMembership membership = new GroupMembership().setMemberName("user.jane");
        try {
            zmsImpl.putGroupMembership(rsrcCtx1, domainName, groupName, "user.jane", auditRef, false, null, membership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        // now set the self serve flag to true and try again

        group.setSelfRenew(true);
        group.setSelfRenewMins(10);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        // we should get an exception since the user.jane is not a member

        try {
            zmsImpl.putGroupMembership(rsrcCtx1, domainName, groupName, "user.jane", auditRef, false, null, membership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        // now add user.jane as a member and try again - this time it should work

        members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.jack"));
        members.add(new GroupMember().setMemberName("user.doe"));
        members.add(new GroupMember().setMemberName("user.jane"));
        group.setGroupMembers(members);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        // now we should get a success

        zmsImpl.putGroupMembership(rsrcCtx1, domainName, groupName, "user.jane", auditRef, false, null, membership);

        // get the user.jane member and verify expiration

        GroupMembership membershipRes = zmsImpl.getGroupMembership(ctx, domainName, groupName, "user.jane", null);
        assertNotNull(membershipRes);
        assertTrue(membershipRes.isMember);
        assertNotNull(membershipRes.getExpiration());

        long currentTime = System.currentTimeMillis();
        assertTrue(membershipRes.getExpiration().millis() >= currentTime + 9 * 60 * 1000);
        assertTrue(membershipRes.getExpiration().millis() <= currentTime + 11 * 60 * 1000);
    }

    @Test
    public void testValidateRoleSelfRenewFlag() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // meta does not touch either field - no validation should happen
        // even if the stored role would be inconsistent

        RoleMeta meta = new RoleMeta();
        Role role = new Role().setSelfRenew(Boolean.TRUE).setSelfRenewMins(null);
        zmsImpl.validateRoleMetaSelfRenewFlag(meta, role, "validateRoleSelfRenewFlag");

        // meta sets selfRenew=true with no mins, stored role also has no mins -> reject

        meta.setSelfRenew(Boolean.TRUE);
        role = new Role().setSelfRenew(null).setSelfRenewMins(null);
        try {
            zmsImpl.validateRoleMetaSelfRenewFlag(meta, role, "validateRoleSelfRenewFlag");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Role cannot enable self-renew without a positive selfRenewMins value"));
        }

        // meta sets selfRenew=true and stored role has a valid mins -> ok

        role = new Role().setSelfRenew(null).setSelfRenewMins(15);
        zmsImpl.validateRoleMetaSelfRenewFlag(meta, role, "validateRoleSelfRenewFlag");

        // meta sets selfRenew=true and mins=0 -> reject regardless of stored

        meta.setSelfRenewMins(0);
        try {
            zmsImpl.validateRoleMetaSelfRenewFlag(meta, role, "validateRoleSelfRenewFlag");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // meta sets mins=0 while stored selfRenew=true -> reject

        meta = new RoleMeta().setSelfRenewMins(0);
        role = new Role().setSelfRenew(Boolean.TRUE).setSelfRenewMins(10);
        try {
            zmsImpl.validateRoleMetaSelfRenewFlag(meta, role, "validateRoleSelfRenewFlag");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // meta sets mins=0 while stored selfRenew=false -> ok

        role = new Role().setSelfRenew(Boolean.FALSE).setSelfRenewMins(10);
        zmsImpl.validateRoleMetaSelfRenewFlag(meta, role, "validateRoleSelfRenewFlag");

        // meta disables selfRenew while leaving mins null -> ok regardless of stored mins

        meta = new RoleMeta().setSelfRenew(Boolean.FALSE);
        role = new Role().setSelfRenew(Boolean.TRUE).setSelfRenewMins(null);
        zmsImpl.validateRoleMetaSelfRenewFlag(meta, role, "validateRoleSelfRenewFlag");

        // meta provides both, valid -> ok

        meta = new RoleMeta().setSelfRenew(Boolean.TRUE).setSelfRenewMins(20);
        role = new Role().setSelfRenew(null).setSelfRenewMins(null);
        zmsImpl.validateRoleMetaSelfRenewFlag(meta, role, "validateRoleSelfRenewFlag");
    }

    @Test
    public void testValidateGroupSelfRenewFlag() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // meta does not touch either field - no validation should happen

        GroupMeta meta = new GroupMeta();
        Group group = new Group().setSelfRenew(Boolean.TRUE).setSelfRenewMins(null);
        zmsImpl.validateGroupMetaSelfRenewFlag(meta, group, "validateGroupSelfRenewFlag");

        // meta sets selfRenew=true with no mins, stored group also has no mins -> reject

        meta.setSelfRenew(Boolean.TRUE);
        group = new Group().setSelfRenew(null).setSelfRenewMins(null);
        try {
            zmsImpl.validateGroupMetaSelfRenewFlag(meta, group, "validateGroupSelfRenewFlag");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Group cannot enable self-renew without a positive selfRenewMins value"));
        }

        // meta sets selfRenew=true and stored group has a valid mins -> ok

        group = new Group().setSelfRenew(null).setSelfRenewMins(15);
        zmsImpl.validateGroupMetaSelfRenewFlag(meta, group, "validateGroupSelfRenewFlag");

        // meta sets mins=0 while stored selfRenew=true -> reject

        meta = new GroupMeta().setSelfRenewMins(0);
        group = new Group().setSelfRenew(Boolean.TRUE).setSelfRenewMins(10);
        try {
            zmsImpl.validateGroupMetaSelfRenewFlag(meta, group, "validateGroupSelfRenewFlag");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // meta sets mins=0 while stored selfRenew=false -> ok

        group = new Group().setSelfRenew(Boolean.FALSE).setSelfRenewMins(10);
        zmsImpl.validateGroupMetaSelfRenewFlag(meta, group, "validateGroupSelfRenewFlag");

        // meta provides both, valid -> ok

        meta = new GroupMeta().setSelfRenew(Boolean.TRUE).setSelfRenewMins(20);
        group = new Group().setSelfRenew(null).setSelfRenewMins(null);
        zmsImpl.validateGroupMetaSelfRenewFlag(meta, group, "validateGroupSelfRenewFlag");
    }

    @Test
    public void testPutRoleSelfRenewWithoutMinsRejected() {

        final String domainName = "role-self-renew-bad-put";
        final String roleName = "role1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.jack"));

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null, members);
        role.setSelfRenew(Boolean.TRUE);
        role.setSelfRenewMins(null);

        try {
            zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Role cannot enable self-renew without a positive selfRenewMins value"));
        }

        role.setSelfRenewMins(0);
        try {
            zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // a valid pair is accepted

        role.setSelfRenewMins(10);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutGroupSelfRenewWithoutMinsRejected() {

        final String domainName = "group-self-renew-bad-put";
        final String groupName = "group1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<GroupMember> members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.jack"));

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, members);
        group.setSelfRenew(Boolean.TRUE);
        group.setSelfRenewMins(null);

        try {
            zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Group cannot enable self-renew without a positive selfRenewMins value"));
        }

        group.setSelfRenewMins(0);
        try {
            zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // a valid pair is accepted

        group.setSelfRenewMins(10);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutRoleMetaSelfRenewMergeAware() {

        final String domainName = "role-self-renew-meta";
        final String roleName = "role1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.jack"));
        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null, members);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        // PATCH selfRenew=true while stored selfRenewMins is null -> reject

        RoleMeta rm = new RoleMeta().setSelfRenew(Boolean.TRUE);
        try {
            zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, rm);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Role cannot enable self-renew without a positive selfRenewMins value"));
        }

        // PATCH a valid pair together -> accepted

        rm = new RoleMeta().setSelfRenew(Boolean.TRUE).setSelfRenewMins(10);
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, rm);

        // PATCH selfRenew=true alone now that stored mins is valid -> accepted (no-op semantically)

        rm = new RoleMeta().setSelfRenew(Boolean.TRUE);
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, rm);

        // PATCH mins=0 while stored selfRenew=true -> reject

        rm = new RoleMeta().setSelfRenewMins(0);
        try {
            zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, rm);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // PATCH unrelated meta (description) does not touch self-renew fields -> always accepted

        rm = new RoleMeta().setDescription("just a description");
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, rm);

        // PATCH that disables selfRenew first, then mins=0 -> both accepted

        rm = new RoleMeta().setSelfRenew(Boolean.FALSE);
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, rm);

        rm = new RoleMeta().setSelfRenewMins(0);
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, rm);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutGroupMetaSelfRenewMergeAware() {

        final String domainName = "group-self-renew-meta";
        final String groupName = "group1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<GroupMember> members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.jack"));
        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, members);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        // PATCH selfRenew=true while stored selfRenewMins is null -> reject

        GroupMeta gm = new GroupMeta().setSelfRenew(Boolean.TRUE);
        try {
            zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, gm);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Group cannot enable self-renew without a positive selfRenewMins value"));
        }

        // PATCH a valid pair together -> accepted

        gm = new GroupMeta().setSelfRenew(Boolean.TRUE).setSelfRenewMins(10);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, gm);

        // PATCH selfRenew=true alone now that stored mins is valid -> accepted

        gm = new GroupMeta().setSelfRenew(Boolean.TRUE);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, gm);

        // PATCH mins=0 while stored selfRenew=true -> reject

        gm = new GroupMeta().setSelfRenewMins(0);
        try {
            zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, gm);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // PATCH that disables selfRenew first, then mins=0 -> both accepted

        gm = new GroupMeta().setSelfRenew(Boolean.FALSE);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, gm);

        gm = new GroupMeta().setSelfRenewMins(0);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, gm);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
