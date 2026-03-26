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
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.common.server.store.impl.JDBCConnection;
import com.yahoo.athenz.zms.provider.ServiceProviderManager;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.*;

public class ZMSPrincipalRolesTest {

    @Mock private JDBCConnection mockJdbcConn;
    @Mock private ObjectStore mockObjStore;

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

    @AfterMethod
    public void clearConnections() throws Exception {
        zmsTestInitializer.clearConnections();
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        if (zmsImpl != null) {
            ServiceProviderManager.getInstance(zmsImpl.dbService, zmsImpl).shutdown();
            Field instance = ServiceProviderManager.class.getDeclaredField("instance");
            instance.setAccessible(true);
            instance.set(null, null);
        }
    }

    @Test
    public void testGetPrincipalRoles() {

        zmsTestInitializer.createTopLevelDomain("domain1");
        zmsTestInitializer.createTopLevelDomain("domain2");
        zmsTestInitializer.createTopLevelDomain("domain3");

        String principal = "user.john-doe";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        insertRecordsForGetPrincipalRolesTest(principal);
        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(ctx, principal, null, null);
        verifyGetPrincipalRoles(principal, domainRoleMember, true);
        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, principal, "domain1", Boolean.FALSE);
        verifyGetPrincipalRoles(principal, domainRoleMember, false);

        zmsImpl.deleteTopLevelDomain(ctx,"domain1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx,"domain2", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx,"domain3", auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesCurrentPrincipal() {
        zmsTestInitializer.createTopLevelDomain("domain1");
        zmsTestInitializer.createTopLevelDomain("domain2");
        zmsTestInitializer.createTopLevelDomain("domain3");

        String principalName = "user.john-doe";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=john-doe";
        Principal principal = SimplePrincipal.create("user", "john-doe", unsignedCreds + ";s=signature",
                0, principalAuthority);
        assertNotNull(principal);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);

        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        insertRecordsForGetPrincipalRolesTest(principalName);
        // we'll don't pass a principal. Current user will be used
        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(rsrcCtx1, null, null, null);
        verifyGetPrincipalRoles(principalName, domainRoleMember, true);
        // we'll don't pass a principal. Current user will be used
        domainRoleMember = zmsImpl.getPrincipalRoles(rsrcCtx1, null, "domain1", Boolean.FALSE);
        verifyGetPrincipalRoles(principalName, domainRoleMember, false);

        zmsImpl.deleteTopLevelDomain(ctx,"domain1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx,"domain2", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx,"domain3", auditRef, null);
    }

    private void verifyGetPrincipalRoles(final String principal, DomainRoleMember domainRoleMember, boolean isAllDomains) {
        MemberRole memberRole0 = new MemberRole();
        memberRole0.setDomainName("domain1");
        memberRole0.setRoleName("role1");

        MemberRole memberRole1 = new MemberRole();
        memberRole1.setDomainName("domain1");
        memberRole1.setRoleName("role2");

        MemberRole memberRole2 = new MemberRole();
        memberRole2.setDomainName("domain3");
        memberRole2.setRoleName("role1");

        assertEquals(domainRoleMember.getMemberName(), principal);
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole0));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole1));
        if (isAllDomains) {
            assertEquals(domainRoleMember.getMemberRoles().size(), 3);
            assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole2));
        } else {
            assertEquals(domainRoleMember.getMemberRoles().size(), 2);
        }
    }

    private void insertRecordsForGetPrincipalRolesTest(final String principal) {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName("user.test2"));
        roleMembers.add(new RoleMember().setMemberName(principal));

        // Create role1 in domain1 with members and principal
        Role role = zmsTestInitializer.createRoleObject("domain1", "Role1", null, roleMembers);
        zmsImpl.putRole(ctx, "domain1", "Role1", auditRef, false, null, role);

        // Create role2 in domain1 with members and principal
        role = zmsTestInitializer.createRoleObject("domain1", "role2", null, roleMembers);
        zmsImpl.putRole(ctx, "domain1", "Role2", auditRef, false, null, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName("user.test2"));

        // Create role1 in domain2 with members but without the principal
        role = zmsTestInitializer.createRoleObject("domain2", "role1", null, roleMembers);
        zmsImpl.putRole(ctx, "domain2", "Role1", auditRef, false, null, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName(principal));

        // Create role1 in domain3 only principal
        role = zmsTestInitializer.createRoleObject("domain3", "role1", null, roleMembers);
        zmsImpl.putRole(ctx, "domain3", "Role1", auditRef, false, null, role);
    }

    private void insertRecordsForGetPrincipalExpandRolesTest(final String principal) {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName(principal));

        // direct membership:
        //   user.john-doe is a member of domain1:role.direct-role

        Role role = zmsTestInitializer.createRoleObject("domain1", "direct-role", null, roleMembers);
        zmsImpl.putRole(ctx, "domain1", "direct-role", auditRef, false, null, role);

        // group membership:
        //   user.john-doe is a member of domain2:group.dev-team
        //   domain2:group.dev-team is a member of domain1:role.group-role

        Group group = zmsTestInitializer.createGroupObject("domain2", "dev-team", "user.test1", principal);
        zmsImpl.putGroup(ctx, "domain2", "dev-team", auditRef, false, null, group);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("domain2:group.dev-team"));

        role = zmsTestInitializer.createRoleObject("domain1", "group-role", null, roleMembers);
        zmsImpl.putRole(ctx, "domain1", "group-role", auditRef, false, null, role);

        // trust user delegation:
        //   role domain1:role.trust-user-role is delegated to domain2:role.trust-user-role
        //   user.john-doe is a member of domain2:role.trust-user-role

        role = zmsTestInitializer.createRoleObject("domain1", "trust-user-role", "domain2", null);
        zmsImpl.putRole(ctx, "domain1", "trust-user-role", auditRef, false, null, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName(principal));

        role = zmsTestInitializer.createRoleObject("domain2", "trust-user-role", null, roleMembers);
        zmsImpl.putRole(ctx, "domain2", "trust-user-role", auditRef, false, null, role);

        Policy policy = zmsTestInitializer.createPolicyObject("domain2", "trust-policy", "trust-user-role",
                "assume_role", "domain1:role.trust-user-role", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "domain2", "trust-policy", auditRef, false, null, policy);

        // trust group delegation:
        //   role domain1:role.trust-group-role is delegated to domain3:role.trust-group-role
        //   domain2:group.dev-team is a member of domain3:role.trust-group-role

        role = zmsTestInitializer.createRoleObject("domain1", "trust-group-role", "domain3", null);
        zmsImpl.putRole(ctx, "domain1", "trust-group-role", auditRef, false, null, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("domain2:group.dev-team"));

        role = zmsTestInitializer.createRoleObject("domain3", "trust-group-role", null, roleMembers);
        zmsImpl.putRole(ctx, "domain3", "trust-group-role", auditRef, false, null, role);

        policy = zmsTestInitializer.createPolicyObject("domain3", "trust-policy", "trust-group-role",
                "assume_role", "domain1:role.trust-group-role", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "domain3", "trust-policy", auditRef, false, null, policy);

        // trust user delegation with wildcard domain:
        //   role domain1:role.wild-user-role is delegated to domain4:role.trust-user-role
        //   domain4:role.trust-user-role assume-role assertion is set for *:role.*-user-role

        role = zmsTestInitializer.createRoleObject("domain1", "wild-user-role", "domain4", null);
        zmsImpl.putRole(ctx, "domain1", "wild-user-role", auditRef, false, null, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName(principal));

        role = zmsTestInitializer.createRoleObject("domain4", "trust-user-role", null, roleMembers);
        zmsImpl.putRole(ctx, "domain4", "trust-user-role", auditRef, false, null, role);

        policy = zmsTestInitializer.createPolicyObject("domain4", "trust-policy", "trust-user-role",
                "assume_role", "*:role.*-user-role", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "domain4", "trust-policy", auditRef, false, null, policy);
    }

    @Test
    public void testGetPrincipalRolesWithExpandOption() {

        // we're going to test the following scenario:
        // direct membership:
        //   user.john-doe is a member of domain1:role.direct-role
        // group membership:
        //   user.john-doe is a member of domain2:group.dev-team
        //   domain2:group.dev-team is a member of domain1:role.group-role
        //   thus our result should indicate that
        //     user.john-doe is a member of domain1:role.group-role
        //     and memberName in the output is set to domain2:group.dev-team
        // trust user delegation:
        //   role domain1:role.trust-user-role is delegated to domain2:role.trust-user-role
        //   user.john-doe is a member of domain2:role.trust-user-role
        //   thus our result should indicate that
        //     user.john-doe is a member of domain1:role.trust-user-role
        //     and trustRoleName is set to domain2:role.trust-user-role
        // trust group delegation:
        //   role domain1:role.trust-group-role is delegated to domain3:role.trust-group-role
        //   domain2:group.dev-team is a member of domain3:role.trust-group-role
        //   thus our result should indicate that
        //     user.john-doe is a member of domain1:role.trust-group-role
        //     and trustRoleName is set to domain3:role.trust-group-role
        //     and memberName is set to domain2:group.dev-team
        // trust user delegation with wildcard domain:
        //   role domain1:role.wild-user-role is delegated to domain4:role.trust-user-role
        //   domain4:role.trust-user-role assume-role assertion is set for *:role.*-user-role
        //   user.john-doe is a member of domain4:role.trust-user-role
        //   thus our result should indicate that
        //     user.john-doe is a member of domain4:role.trust-user-role
        //     and trustRoleName is set to domain1:role.wild-user-role

        zmsTestInitializer.createTopLevelDomain("domain1");
        zmsTestInitializer.createTopLevelDomain("domain2");
        zmsTestInitializer.createTopLevelDomain("domain3");
        zmsTestInitializer.createTopLevelDomain("domain4");

        String principalName = "user.john-doe";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=john-doe";
        Principal principal = SimplePrincipal.create("user", "john-doe", unsignedCreds + ";s=signature",
                0, principalAuthority);
        assertNotNull(principal);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);

        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        // set up our test case

        insertRecordsForGetPrincipalExpandRolesTest(principalName);

        // we won't pass a principal. Current user will be used

        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(rsrcCtx1, null, null, Boolean.TRUE);
        assertNotNull(domainRoleMember);
        verifyGetPrincipalExpandedRoles(principalName, domainRoleMember, true);

        // now get the data with domain1 only

        domainRoleMember = zmsImpl.getPrincipalRoles(rsrcCtx1, null, "domain1", Boolean.TRUE);
        assertNotNull(domainRoleMember);
        verifyGetPrincipalExpandedRoles(principalName, domainRoleMember, false);

        zmsImpl.deleteTopLevelDomain(ctx, "domain4", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "domain3", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "domain1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "domain2", auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesWithExpandOptionForbidden() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=john-doe";
        Principal principal = SimplePrincipal.create("user", "john-doe", unsignedCreds + ";s=signature",
                0, principalAuthority);
        assertNotNull(principal);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);

        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        try {
            zmsImpl.getPrincipalRoles(rsrcCtx1, "user.jane", null, Boolean.TRUE);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
        }
    }

    private void verifyGetPrincipalExpandedRoles(final String principal, DomainRoleMember domainRoleMember,
                                                 boolean isAllDomains) {

        MemberRole memberRole0 = new MemberRole();
        memberRole0.setDomainName("domain1");
        memberRole0.setRoleName("direct-role");

        MemberRole memberRole1 = new MemberRole();
        memberRole1.setDomainName("domain1");
        memberRole1.setRoleName("group-role");
        memberRole1.setMemberName("domain2:group.dev-team");

        MemberRole memberRole2 = new MemberRole();
        memberRole2.setDomainName("domain1");
        memberRole2.setRoleName("trust-user-role");
        memberRole2.setTrustRoleName("domain2:role.trust-user-role");

        MemberRole memberRole3 = new MemberRole();
        memberRole3.setDomainName("domain1");
        memberRole3.setRoleName("trust-group-role");
        memberRole3.setMemberName("domain2:group.dev-team");
        memberRole3.setTrustRoleName("domain3:role.trust-group-role");

        MemberRole memberRole4 = new MemberRole();
        memberRole4.setDomainName("domain1");
        memberRole4.setRoleName("wild-user-role");
        memberRole4.setTrustRoleName("domain4:role.trust-user-role");

        MemberRole memberRole5 = new MemberRole();
        memberRole5.setDomainName("domain2");
        memberRole5.setRoleName("trust-user-role");

        MemberRole memberRole6 = new MemberRole();
        memberRole6.setDomainName("domain3");
        memberRole6.setRoleName("trust-group-role");
        memberRole6.setMemberName("domain2:group.dev-team");

        MemberRole memberRole7 = new MemberRole();
        memberRole7.setDomainName("domain4");
        memberRole7.setRoleName("trust-user-role");

        assertEquals(domainRoleMember.getMemberName(), principal);
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole0));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole1));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole2));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole3));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole4));
        if (isAllDomains) {
            assertEquals(domainRoleMember.getMemberRoles().size(), 8);
            assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole5));
            assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole6));
            assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole7));
        } else {
            assertEquals(domainRoleMember.getMemberRoles().size(), 5);
        }
    }

    @Test
    public void testIsAllowedExpandedRoleLookup() {

        final String domainName = "domain1";

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=john";
        Principal principal = SimplePrincipal.create("user", "john", unsignedCreds + ";s=signature",
                0, principalAuthority);

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // without any setup, the principal will only work if the checkPrincipal
        // matches the principal

        assertTrue(zmsImpl.isAllowedExpandedRoleLookup(principal, "user.john", null));
        assertFalse(zmsImpl.isAllowedExpandedRoleLookup(principal, "user.jane", ""));

        // invalid principals should return failure

        assertFalse(zmsImpl.isAllowedExpandedRoleLookup(principal, "unknown-domain", null));

        // asking for a domain that doesn't exist, must return failure

        assertFalse(zmsImpl.isAllowedExpandedRoleLookup(principal, "unknown-domain.service", ""));

        // let's create the domain and without proper access, it still returns failure

        zmsTestInitializer.createTopLevelDomain(domainName);
        assertFalse(zmsImpl.isAllowedExpandedRoleLookup(principal, domainName + ".api", null));

        // now let's grant user.john update access over the service

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.john"));

        Role role = zmsTestInitializer.createRoleObject(domainName, "service-role", null, roleMembers);
        zmsImpl.putRole(ctx, domainName, "service-role", auditRef, false, null, role);

        Policy policy = zmsTestInitializer.createPolicyObject(domainName, "service-policy", "service-role",
                "update", domainName + ":service.api", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, domainName, "service-policy", auditRef, false, null, policy);

        // now our access check should work

        assertTrue(zmsImpl.isAllowedExpandedRoleLookup(principal, domainName + ".api", ""));

        // delete the policy and verify that it fails again

        zmsImpl.deletePolicy(ctx, domainName, "service-policy", auditRef, null);
        assertFalse(zmsImpl.isAllowedExpandedRoleLookup(principal, domainName + ".api", null));

        // now let's set up the user as system role lookup user

        role = zmsTestInitializer.createRoleObject("sys.auth", "service-role", null, roleMembers);
        zmsImpl.putRole(ctx, "sys.auth", "service-role", auditRef, false, null, role);

        policy = zmsTestInitializer.createPolicyObject("sys.auth", "service-policy", "service-role",
                "access", "sys.auth:meta.role.lookup", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "sys.auth", "service-policy", auditRef, false, null, policy);

        // now our access check should work

        assertTrue(zmsImpl.isAllowedExpandedRoleLookup(principal, domainName + ".api", null));

        // clean up our system domain
        zmsImpl.deletePolicy(ctx, "sys.auth", "service-policy", auditRef, null);
        zmsImpl.deleteRole(ctx, "sys.auth", "service-role", auditRef, null);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testIsAllowedExpandedRoleLookupForDomainAdmins() {

        final String domainName = "domain1";

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=john";
        Principal principal = SimplePrincipal.create("user", "john", unsignedCreds + ";s=signature",
                0, principalAuthority);
        assertNotNull(principal);

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // without the domain being present, we should get failure since the
        // principal does not match our check principal name

        assertFalse(zmsImpl.isAllowedExpandedRoleLookup(principal, "user.jane", domainName));

        // let's create the domain and without proper access, it still returns failure

        zmsTestInitializer.createTopLevelDomain(domainName);
        assertFalse(zmsImpl.isAllowedExpandedRoleLookup(principal, domainName + ".api", domainName));

        // now let's grant user.john update access over the domain

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.john"));

        Role role = zmsTestInitializer.createRoleObject(domainName, "domain-role", null, roleMembers);
        zmsImpl.putRole(ctx, domainName, "domain-role", auditRef, false, null, role);

        Policy policy = zmsTestInitializer.createPolicyObject(domainName, "domain-policy", "domain-role",
                "access", domainName + ":meta.role.lookup", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, domainName, "domain-policy", auditRef, false, null, policy);

        // now our access check should work

        assertTrue(zmsImpl.isAllowedExpandedRoleLookup(principal, domainName + ".api", domainName));

        // delete the policy and verify that it fails again

        zmsImpl.deletePolicy(ctx, domainName, "domain-policy", auditRef, null);
        assertFalse(zmsImpl.isAllowedExpandedRoleLookup(principal, domainName + ".api", domainName));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesWithExpandOptionNoIndirectMatches() {

        // we're going to test the following scenario:
        //   user.john-doe is not a member of any roles
        //   user.john-doe is a member of domain2:group.qa-team
        //      but domain2:group.qa-team is not a member of any role
        // trust user delegation:
        //   role domain1:role.trust-user-role is delegated to domain2
        //      user.john-doe is a member of domain2:role.trust-user-role
        //      but domain2 does not have assume_role policy for trust-user-role
        // so with all domains we should only get 1 result
        //   role membership in domain2:role.trust-user-role
        // with domain1 filter - there are no matches

        zmsTestInitializer.createTopLevelDomain("domain1");
        zmsTestInitializer.createTopLevelDomain("domain2");

        String principalName = "user.john-doe";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=john-doe";
        Principal principal = SimplePrincipal.create("user", "john-doe", unsignedCreds + ";s=signature",
                0, principalAuthority);
        assertNotNull(principal);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);

        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        // set up our test case

        insertRecordsForGetPrincipalExpandRolesTestNoIndirectMatches(principalName);

        // we won't pass a principal. Current user will be used

        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(rsrcCtx1, null, null, Boolean.TRUE);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 1);

        MemberRole memberRole1 = new MemberRole();
        memberRole1.setDomainName("domain2");
        memberRole1.setRoleName("trust-user-role");

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole1));

        // now get the data with domain1 only - no matches

        domainRoleMember = zmsImpl.getPrincipalRoles(rsrcCtx1, null, "domain1", Boolean.TRUE);
        assertNotNull(domainRoleMember);
        assertTrue(domainRoleMember.getMemberRoles().isEmpty());

        zmsImpl.deleteTopLevelDomain(ctx,"domain1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx,"domain2", auditRef, null);
    }

    private void insertRecordsForGetPrincipalExpandRolesTestNoIndirectMatches(final String principal) {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName(principal));

        // group membership:
        //   user.john-doe is a member of domain2:group.qa-team
        //      but domain2:group.qa-team is not a member of any role

        Group group = zmsTestInitializer.createGroupObject("domain2", "qa-team", "user.test1", principal);
        zmsImpl.putGroup(ctx, "domain2", "qa-team", auditRef, false, null, group);

        // trust user delegation:
        //   role domain1:role.trust-user-role is delegated to domain2
        //      user.john-doe is a member of domain2:role.trust-user-role
        //      but domain2 does not have assume_role policy for trust-user-role

        Role role = zmsTestInitializer.createRoleObject("domain1", "trust-user-role", "domain2", null);
        zmsImpl.putRole(ctx, "domain1", "trust-user-role", auditRef, false, null, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName(principal));

        role = zmsTestInitializer.createRoleObject("domain2", "trust-user-role", null, roleMembers);
        zmsImpl.putRole(ctx, "domain2", "trust-user-role", auditRef, false, null, role);

        Policy policy = zmsTestInitializer.createPolicyObject("domain2", "trust-policy", "trust-user-role",
                "assume_role", "domain1:role.no-match-role", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "domain2", "trust-policy", auditRef, false, null, policy);

        policy = zmsTestInitializer.createPolicyObject("domain2", "trust-policy2", "trust-user-role",
                "assume_role", "domain5:role.no-match-role", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "domain2", "trust-policy2", auditRef, false, null, policy);
    }

    @Test
    public void testGetPrincipalRolesGroupFailure() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        Mockito.when(mockObjStore.getConnection(true, false)).thenReturn(mockJdbcConn);

        DomainRoleMember principalRoles = new DomainRoleMember();
        principalRoles.setMemberRoles(new ArrayList<>());
        Mockito.when(mockJdbcConn.getPrincipalRoles("user.john-doe", null)).thenReturn(principalRoles);

        DomainGroupMember principalGroups = new DomainGroupMember();
        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setDomainName("domain1").setGroupName("eng-team"));
        principalGroups.setMemberGroups(groupMembers);
        Mockito.when(mockJdbcConn.getPrincipalGroups("user.john-doe", null)).thenReturn(principalGroups);

        Mockito.when(mockJdbcConn.getPrincipalRoles("domain1:group.eng-team", null))
                .thenThrow(new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR));

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=john-doe";
        Principal principal = SimplePrincipal.create("user", "john-doe", unsignedCreds + ";s=signature",
                0, principalAuthority);
        assertNotNull(principal);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);

        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        try {
            zmsImpl.getPrincipalRoles(rsrcCtx1, null, null, Boolean.TRUE);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        zmsImpl.dbService.store = saveStore;
    }

    private void setupExternalMemberValidator(final String domainName) {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zms,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zms.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zms.externalMemberValidatorManager.refreshValidators();
    }

    private void addExternalMemberToRole(final String domainName, final String roleName,
            final String externalMember) {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        Membership mbr = zmsTestInitializer.generateMembership(roleName, externalMember);
        zms.putMembership(ctx, domainName, roleName, externalMember, auditRef, false, null, mbr);
    }

    private void addExternalMemberToGroup(final String domainName, final String groupName,
            final String externalMember) {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        GroupMembership gmbr = zmsTestInitializer.generateGroupMembership(groupName, externalMember);
        zms.putGroupMembership(ctx, domainName, groupName, externalMember, auditRef, false, null, gmbr);
    }

    private void setupRoleLookupAuthorization() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName(ctx.principal().getFullName()));

        Role role = zmsTestInitializer.createRoleObject("sys.auth", "role-lookup", null, roleMembers);
        zms.putRole(ctx, "sys.auth", "role-lookup", auditRef, false, null, role);

        Policy policy = zmsTestInitializer.createPolicyObject("sys.auth", "role-lookup-policy",
                "role-lookup", "access", "sys.auth:meta.role.lookup", AssertionEffect.ALLOW);
        zms.putPolicy(ctx, "sys.auth", "role-lookup-policy", auditRef, false, null, policy);
    }

    private void cleanupRoleLookupAuthorization() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        zms.deletePolicy(ctx, "sys.auth", "role-lookup-policy", auditRef, null);
        zms.deleteRole(ctx, "sys.auth", "role-lookup", auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesExternalMember() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName1 = "ext-pr-basic1";
        final String domainName2 = "ext-pr-basic2";
        final String externalMember = domainName1 + ":ext.partner-user";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        setupExternalMemberValidator(domainName1);

        // create two roles in domain1 with the external member

        Role role1 = zmsTestInitializer.createRoleObject(domainName1, "role1", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName1, "role1", auditRef, false, null, role1);
        addExternalMemberToRole(domainName1, "role1", externalMember);

        Role role2 = zmsTestInitializer.createRoleObject(domainName1, "role2", null,
                "user.jane", null);
        zmsImpl.putRole(ctx, domainName1, "role2", auditRef, false, null, role2);
        addExternalMemberToRole(domainName1, "role2", externalMember);

        // create a role in domain2 without the external member

        Role role3 = zmsTestInitializer.createRoleObject(domainName2, "role1", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName2, "role1", auditRef, false, null, role3);

        // get all roles for the external member across all domains

        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, null, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberName(), externalMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 2);

        MemberRole memberRole0 = new MemberRole();
        memberRole0.setDomainName(domainName1);
        memberRole0.setRoleName("role1");

        MemberRole memberRole1 = new MemberRole();
        memberRole1.setDomainName(domainName1);
        memberRole1.setRoleName("role2");

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole0));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole1));

        // get roles filtered by domain1

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, domainName1, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 2);

        // get roles filtered by domain2 - external member has no roles there

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, domainName2, null);
        assertNotNull(domainRoleMember);
        assertTrue(domainRoleMember.getMemberRoles().isEmpty());

        // remove external member from role1 and verify updated results

        zmsImpl.deleteMembership(ctx, domainName1, "role1", externalMember, auditRef, null);

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, null, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 1);
        assertEquals(domainRoleMember.getMemberRoles().get(0).getRoleName(), "role2");

        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesExternalMemberWithExpandOption() {

        // test scenario:
        // direct membership:
        //   external member is directly in domain:role.direct-role
        // group membership:
        //   external member is in domain:group.partners
        //   domain:group.partners is a member of domain:role.group-role
        //   with expand=true, external member should appear in domain:role.group-role
        //     with memberName set to domain:group.partners

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-pr-expand";
        final String externalMember = domainName + ":ext.partner-user";
        final String groupResourceName = domainName + ":group.partners";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);
        setupRoleLookupAuthorization();

        // direct membership: external member in domain:role.direct-role

        Role directRole = zmsTestInitializer.createRoleObject(domainName, "direct-role", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName, "direct-role", auditRef, false, null, directRole);
        addExternalMemberToRole(domainName, "direct-role", externalMember);

        // group membership: external member in domain:group.partners
        //   domain:group.partners is a member of domain:role.group-role

        Group group = zmsTestInitializer.createGroupObject(domainName, "partners",
                null, null);
        zmsImpl.putGroup(ctx, domainName, "partners", auditRef, false, null, group);
        addExternalMemberToGroup(domainName, "partners", externalMember);

        List<RoleMember> groupRoleMembers = new ArrayList<>();
        groupRoleMembers.add(new RoleMember().setMemberName(groupResourceName));

        Role groupRole = zmsTestInitializer.createRoleObject(domainName, "group-role", null,
                groupRoleMembers);
        zmsImpl.putRole(ctx, domainName, "group-role", auditRef, false, null, groupRole);

        // without expand - should only return direct role membership

        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember,
                null, Boolean.FALSE);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 1);

        MemberRole directMemberRole = new MemberRole();
        directMemberRole.setDomainName(domainName);
        directMemberRole.setRoleName("direct-role");

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, directMemberRole));

        // with expand - should return both direct and group-based roles

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, null, Boolean.TRUE);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 2);

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, directMemberRole));

        MemberRole groupMemberRole = new MemberRole();
        groupMemberRole.setDomainName(domainName);
        groupMemberRole.setRoleName("group-role");
        groupMemberRole.setMemberName(groupResourceName);

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, groupMemberRole));

        // with expand and domain filter - same result since everything is in one domain

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, domainName, Boolean.TRUE);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 2);

        cleanupRoleLookupAuthorization();
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesExternalMemberGroupOnlyWithExpand() {

        // test scenario:
        // external member is only in a group (not directly in any role)
        // the group is a member of a role
        // without expand: no roles returned
        // with expand: the group-based role is returned

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-pr-grp-expand";
        final String externalMember = domainName + ":ext.partner-user";
        final String groupResourceName = domainName + ":group.partners";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);
        setupRoleLookupAuthorization();

        // create a group with the external member

        Group group = zmsTestInitializer.createGroupObject(domainName, "partners",
                null, null);
        zmsImpl.putGroup(ctx, domainName, "partners", auditRef, false, null, group);
        addExternalMemberToGroup(domainName, "partners", externalMember);

        // create a role with the group as a member

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName(groupResourceName));

        Role role = zmsTestInitializer.createRoleObject(domainName, "group-role", null,
                roleMembers);
        zmsImpl.putRole(ctx, domainName, "group-role", auditRef, false, null, role);

        // create another role without the group or external member

        Role otherRole = zmsTestInitializer.createRoleObject(domainName, "other-role", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName, "other-role", auditRef, false, null, otherRole);

        // without expand - external member is not directly in any role

        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember,
                null, Boolean.FALSE);
        assertNotNull(domainRoleMember);
        assertTrue(domainRoleMember.getMemberRoles().isEmpty());

        // with expand - should return the role through group membership

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, null, Boolean.TRUE);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 1);

        MemberRole memberRole = new MemberRole();
        memberRole.setDomainName(domainName);
        memberRole.setRoleName("group-role");
        memberRole.setMemberName(groupResourceName);

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole));

        cleanupRoleLookupAuthorization();
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesExternalMemberMixedWithRegularMember() {

        // test scenario:
        // a role contains both regular and external members
        // querying for the external member returns only roles the external member is in
        // querying for the regular member returns only roles the regular member is in

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-pr-mixed";
        final String externalMember = domainName + ":ext.partner-user";
        final String regularMember = "user.john-doe";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);

        // role1: both regular and external members

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                regularMember, null);
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);
        addExternalMemberToRole(domainName, "role1", externalMember);

        // role2: only the external member

        Role role2 = zmsTestInitializer.createRoleObject(domainName, "role2", null,
                null, null);
        zmsImpl.putRole(ctx, domainName, "role2", auditRef, false, null, role2);
        addExternalMemberToRole(domainName, "role2", externalMember);

        // role3: only the regular member

        Role role3 = zmsTestInitializer.createRoleObject(domainName, "role3", null,
                regularMember, null);
        zmsImpl.putRole(ctx, domainName, "role3", auditRef, false, null, role3);

        // query for external member - should return role1 and role2

        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember,
                null, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberName(), externalMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 2);

        MemberRole extRole1 = new MemberRole();
        extRole1.setDomainName(domainName);
        extRole1.setRoleName("role1");

        MemberRole extRole2 = new MemberRole();
        extRole2.setDomainName(domainName);
        extRole2.setRoleName("role2");

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, extRole1));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, extRole2));

        // query for regular member - should return role1 and role3

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, regularMember, null, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberName(), regularMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 2);

        MemberRole regRole1 = new MemberRole();
        regRole1.setDomainName(domainName);
        regRole1.setRoleName("role1");

        MemberRole regRole3 = new MemberRole();
        regRole3.setDomainName(domainName);
        regRole3.setRoleName("role3");

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, regRole1));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, regRole3));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesExternalMemberNoRoles() {

        // test scenario:
        // external member is added to a group but not to any role
        // getPrincipalRoles without expand should return empty

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-pr-no-roles";
        final String externalMember = domainName + ":ext.partner-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);
        setupRoleLookupAuthorization();

        // add the external member to a group but not to any role

        Group group = zmsTestInitializer.createGroupObject(domainName, "partners",
                null, null);
        zmsImpl.putGroup(ctx, domainName, "partners", auditRef, false, null, group);
        addExternalMemberToGroup(domainName, "partners", externalMember);

        // create a role without the external member or the group

        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role);

        // query without expand - should return empty

        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember,
                null, null);
        assertNotNull(domainRoleMember);
        assertTrue(domainRoleMember.getMemberRoles().isEmpty());

        // query with expand - still empty since the group is not a member of any role

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, null, Boolean.TRUE);
        assertNotNull(domainRoleMember);
        assertTrue(domainRoleMember.getMemberRoles().isEmpty());

        cleanupRoleLookupAuthorization();
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
