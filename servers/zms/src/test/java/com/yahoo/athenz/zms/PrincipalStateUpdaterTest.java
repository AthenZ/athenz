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
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.zms.provider.ServiceProviderManager;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.*;

import java.lang.reflect.Field;
import java.util.*;

import static com.yahoo.athenz.zms.ZMSConsts.ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.testng.Assert.*;

public class PrincipalStateUpdaterTest {

    @Mock DBService dbsvc;
    @Mock Authority authority;

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeClass
    public void setUpClass() {
        MockitoAnnotations.openMocks(this);
        zmsTestInitializer.startMemoryMySQL();
    }

    @BeforeMethod
    public void setUpMethod() throws Exception {
        Mockito.reset(dbsvc, authority);
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void clearConnections() throws Exception {
        zmsTestInitializer.clearConnections();
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        if (zmsImpl != null) {
            zmsImpl.externalMemberValidatorManager.shutdown();
            ServiceProviderManager.getInstance(zmsImpl.dbService, zmsImpl).shutdown();
            Field instance = ServiceProviderManager.class.getDeclaredField("instance");
            instance.setAccessible(true);
            instance.set(null, null);
        }
    }

    @Test
    public void testRefreshUserStateFromAuthority() {
        List<PrincipalMember> currSuspended = new ArrayList<>();
        currSuspended.add(new PrincipalMember().setPrincipalName("user.user1").setSuspendedState(7));
        currSuspended.add(new PrincipalMember().setPrincipalName("user.user2").setSuspendedState(2));
        currSuspended.add(new PrincipalMember().setPrincipalName("user.user3"));

        List<Principal> newSuspended = new ArrayList<>();
        newSuspended.add(SimplePrincipal.create("user", "user2", (String) null));
        newSuspended.add(SimplePrincipal.create("user", "user3", (String) null));
        newSuspended.add(SimplePrincipal.create("user", "user4", (String) null));

        Mockito.when(dbsvc.getPrincipal("user.user2")).thenReturn(new PrincipalMember()
                .setPrincipalName("user.user2").setSuspendedState(2));
        Mockito.when(dbsvc.getPrincipal("user.user3")).thenReturn(new PrincipalMember()
                .setPrincipalName("user.user3"));
        Mockito.when(dbsvc.getPrincipal("user.user4")).thenReturn(new PrincipalMember()
                .setPrincipalName("user.user4"));

        // make sure the list are not empty otherwise throw exceptions
        Mockito.doThrow(new ResourceException(400)).when(dbsvc).updatePrincipalByState(new ArrayList<>(), true,
                Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue(), "audit-ref");
        Mockito.doThrow(new ResourceException(400)).when(dbsvc).updatePrincipalByState(new ArrayList<>(), false,
                Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue(), "audit-ref");
        Mockito.when(dbsvc.getPrincipals(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue())).thenReturn(currSuspended);
        Mockito.when(authority.getPrincipals(EnumSet.of(Principal.State.AUTHORITY_SYSTEM_SUSPENDED))).thenReturn(newSuspended);

        try {
            PrincipalStateUpdater updater = new PrincipalStateUpdater(dbsvc, authority);
            updater.refreshPrincipalStateFromAuthority();
            updater.shutdown();
        } catch (ResourceException rex) {
            fail();
        }
    }

    @Test
    public void testShutdown() {
        Mockito.when(dbsvc.getPrincipals(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue())).thenReturn(Collections.emptyList());
        Mockito.when(authority.getPrincipals(EnumSet.of(Principal.State.AUTHORITY_SYSTEM_SUSPENDED))).thenReturn(Collections.emptyList());

        System.setProperty(ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER, "false");
        try {
            PrincipalStateUpdater principalStateUpdater = new PrincipalStateUpdater(dbsvc, authority);
            principalStateUpdater.shutdown();
        } catch (ResourceException rex) {
            System.setProperty(ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER, "true");
            fail();
        }
        System.setProperty(ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER, "true");
    }

    @Test
    public void testNoAuthority() {

        // we're configuring our db service to throw an exception since
        // this should never be called without an authority

        Mockito.when(dbsvc.getPrincipals(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue()))
                .thenThrow(new ResourceException(400, "Invalid argument"));

        try {
            PrincipalStateUpdater principalStateUpdater = new PrincipalStateUpdater(dbsvc, null);
            principalStateUpdater.refreshPrincipalStateFromAuthority();
            principalStateUpdater.shutdown();
        } catch (ResourceException rex) {
            fail();
        }
    }

    @Test
    public void testGetSystemDisabledPrincipals() {

        Mockito.when(dbsvc.getPrincipal("user.user1")).thenReturn(new PrincipalMember().setPrincipalName("user.user1"));
        Mockito.when(dbsvc.getPrincipal("user.user2")).thenReturn(null);
        Mockito.when(dbsvc.getPrincipal("user.user3")).thenThrow(new ResourceException(400, "Invalid argument"));

        PrincipalStateUpdater principalStateUpdater = new PrincipalStateUpdater(dbsvc, null);
        List<PrincipalMember> principals = principalStateUpdater.getSystemDisabledPrincipals(
                Arrays.asList(SimplePrincipal.create("user", "user1", (String) null),
                        SimplePrincipal.create("user", "user2", (String) null),
                        SimplePrincipal.create("user", "user3", (String) null)));
        assertEquals(principals.size(), 1);
        assertEquals(principals.get(0).getPrincipalName(), "user.user1");
        principalStateUpdater.shutdown();
    }

    @Test
    public void testNoTimer() {
        Mockito.when(dbsvc.getPrincipals(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue())).thenReturn(Collections.emptyList());
        Mockito.when(authority.getPrincipals(EnumSet.of(Principal.State.AUTHORITY_SYSTEM_SUSPENDED))).thenReturn(Collections.emptyList());
        System.setProperty(ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER, "true");
        try {
            new PrincipalStateUpdater(dbsvc, authority);
        } catch (ResourceException rex) {
            fail();
        }
    }

    @Test
    public void testPutPrincipalStateNoMember() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        setupUserAdminForStateChanges("user.user1", "user.joe");

        zms.putPrincipalState(ctx, "user.joe", auditRef, new PrincipalState().setSuspended(true));

        PrincipalMember pm = zms.dbService.getPrincipal("user.joe");
        assertNotNull(pm);
        assertEquals(pm.getPrincipalName(), "user.joe");
        assertEquals(pm.getSuspendedState(), Principal.State.ATHENZ_SYSTEM_DISABLED.getValue());

        zms.putPrincipalState(ctx, "user.joe", auditRef, new PrincipalState().setSuspended(false));
        pm = zms.dbService.getPrincipal("user.joe");
        assertEquals(pm.getPrincipalName(), "user.joe");
        assertEquals(pm.getSuspendedState(), 0);

        cleanUpUserAdminAuthz();
    }

    @Test
    public void testPutPrincipalStateServiceAuthorization() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "state-service-authz";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root", "users", "host1");
        zms.putServiceIdentity(ctx, domainName, "service1", auditRef, true, null, service1);

        final String fullServiceName = ResourceUtils.serviceResourceName(domainName, "service1");
        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null, fullServiceName, "user.joe");
        zms.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        // when updating the service we should be authorized since we're
        // the domain admin

        zms.putPrincipalState(ctx, fullServiceName, auditRef, new PrincipalState().setSuspended(true));
        PrincipalMember pm = zms.dbService.getPrincipal(fullServiceName);
        assertNotNull(pm);
        assertEquals(pm.getPrincipalName(), fullServiceName);
        assertEquals(pm.getSuspendedState(), Principal.State.ATHENZ_SYSTEM_DISABLED.getValue());

        // now when trying to modify the user we should get a forbidden error

        try {
            zms.putPrincipalState(ctx, "user.joe", auditRef, new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unauthorized to update principal state"));
        }
    }

    @Test
    public void testPutPrincipalStateInvalidCases() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();


        // try without audit reference

        try {
            zms.putPrincipalState(ctx, "user.joe", null, new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference is required"));
        }

        try {
            zms.putPrincipalState(ctx, "user.joe", "", new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference is required"));
        }

        // try invalid principal name

        try {
            zms.putPrincipalState(ctx, "athenz:group.dev-team", auditRef, new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid principal name"));
        }

        // try an unknown domain

        try {
            zms.putPrincipalState(ctx, "unknown-domain.api", auditRef, new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("Domain not found"));
        }

        // without any authorization we should get back forbidden error

        try {
            zms.putPrincipalState(ctx, "user.unknown-user", auditRef, new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unauthorized to update principal state"));
        }

        // setup for authorization

        setupUserAdminForStateChanges("user.user1", "user.joe");

        // try to update a non-existing principal

        try {
            zms.putPrincipalState(ctx, "user.unknown-user", auditRef, new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("Principal not found"));
        }

        cleanUpUserAdminAuthz();
    }

    private void setupUserAdminForStateChanges(final String... admins) {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        List<RoleMember> roleMembers = new ArrayList<>();
        for (String admin : admins) {
            roleMembers.add(new RoleMember().setMemberName(admin));
        }
        Role role = new Role().setName("sys.auth:role.state-admin").setRoleMembers(roleMembers);
        zms.putRole(ctx, "sys.auth", "state-admin", auditRef, false, null, role);

        List<Assertion> assertions = new ArrayList<>();
        assertions.add(new Assertion().setRole("sys.auth:role.state-admin").setResource("sys.auth:state.*")
                .setAction("update"));
        Policy policy = new Policy().setName("sys.auth:policy.state-admin").setAssertions(assertions);
        zms.putPolicy(ctx, "sys.auth", "state-admin", auditRef, false, null, policy);
    }

    private void cleanUpUserAdminAuthz() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        zms.deletePolicy(ctx, "sys.auth", "state-admin", auditRef, null);
        zms.deleteRole(ctx, "sys.auth", "state-admin", auditRef, null);
    }

    @Test
    public void testPutPrincipalStateNoMemberConnectionFailure() throws ServerResourceException {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        setupUserAdminForStateChanges("user.user1", "user.joe");

        zms.putPrincipalState(ctx, "user.joe", auditRef, new PrincipalState().setSuspended(true));

        ObjectStore mockObjStore = Mockito.mock(ObjectStore.class);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
                .thenThrow(new ServerResourceException(500, "DB Error"));

        try {
            zms.dbService.executePutPrincipalState(ctx, "user", "user.joe",
                    new PrincipalState().setSuspended(true), auditRef, "putPrincipalState");
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 500);
        }

        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = saveRetryCount;

        cleanUpUserAdminAuthz();
    }

    @Test
    public void testPutPrincipalStateServiceWithMembers() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "principal-state-members";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null, "user.jane", "user.joe");
        zms.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        Role role2 = zmsTestInitializer.createRoleObject(domainName, "role2", null, "user.joe", "user.doe");
        zms.putRole(ctx, domainName, "role2", auditRef, false, null, role2);

        Group group1 = zmsTestInitializer.createGroupObject(domainName, "group1", "user.jane", "user.joe");
        zms.putGroup(ctx, domainName, "group1", auditRef, false, null, group1);

        Group group2 = zmsTestInitializer.createGroupObject(domainName, "group2", "user.joe", "user.doe");
        zms.putGroup(ctx, domainName, "group2", auditRef, false, null, group2);

        setupUserAdminForStateChanges("user.user1");

        // let's suspend the user.joe principal

        zms.putPrincipalState(ctx, "user.joe", auditRef, new PrincipalState().setSuspended(true));

        // now let's verify that the members of the roles and groups

        Role role = zms.getRole(ctx, domainName, "role1", false, false, false);
        assertEquals(role.getRoleMembers().size(), 2);
        for (RoleMember member : role.getRoleMembers()) {
            if (member.getMemberName().equals("user.jane")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals("user.joe")) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        role = zms.getRole(ctx, domainName, "role2", false, false, false);
        assertEquals(role.getRoleMembers().size(), 2);
        for (RoleMember member : role.getRoleMembers()) {
            if (member.getMemberName().equals("user.doe")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals("user.joe")) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        Group group = zms.getGroup(ctx, domainName, "group1", false, false);
        assertEquals(group.getGroupMembers().size(), 2);
        for (GroupMember member : group.getGroupMembers()) {
            if (member.getMemberName().equals("user.jane")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals("user.joe")) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        group = zms.getGroup(ctx, domainName, "group2", false, false);
        assertEquals(group.getGroupMembers().size(), 2);
        for (GroupMember member : group.getGroupMembers()) {
            if (member.getMemberName().equals("user.doe")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals("user.joe")) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        // now let's enable joe and suspend jane

        zms.putPrincipalState(ctx, "user.joe", auditRef, new PrincipalState().setSuspended(false));
        zms.putPrincipalState(ctx, "user.jane", auditRef, new PrincipalState().setSuspended(true));

        // let's again verify that the members of the roles and groups

        role = zms.getRole(ctx, domainName, "role1", false, false, false);
        assertEquals(role.getRoleMembers().size(), 2);
        for (RoleMember member : role.getRoleMembers()) {
            if (member.getMemberName().equals("user.jane")) {
                assertEquals(member.getSystemDisabled(), 4);
            } else if (member.getMemberName().equals("user.joe")) {
                assertNull(member.getSystemDisabled());
            } else {
                fail();
            }
        }

        role = zms.getRole(ctx, domainName, "role2", false, false, false);
        assertEquals(role.getRoleMembers().size(), 2);
        for (RoleMember member : role.getRoleMembers()) {
            if (member.getMemberName().equals("user.doe")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals("user.joe")) {
                assertNull(member.getSystemDisabled());
            } else {
                fail();
            }
        }

        group = zms.getGroup(ctx, domainName, "group1", false, false);
        assertEquals(group.getGroupMembers().size(), 2);
        for (GroupMember member : group.getGroupMembers()) {
            if (member.getMemberName().equals("user.jane")) {
                assertEquals(member.getSystemDisabled(), 4);
            } else if (member.getMemberName().equals("user.joe")) {
                assertNull(member.getSystemDisabled());
            } else {
                fail();
            }
        }

        group = zms.getGroup(ctx, domainName, "group2", false, false);
        assertEquals(group.getGroupMembers().size(), 2);
        for (GroupMember member : group.getGroupMembers()) {
            if (member.getMemberName().equals("user.doe")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals("user.joe")) {
                assertNull(member.getSystemDisabled());
            } else {
                fail();
            }
        }

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

    @Test
    public void testPutPrincipalStateExternalMember() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-state-basic";
        final String externalMember = domainName + ":ext.partner-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);

        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.joe", null);
        zms.putRole(ctx, domainName, "role1", auditRef, false, null, role);

        addExternalMemberToRole(domainName, "role1", externalMember);

        // set up system-level state-admin authorization

        setupUserAdminForStateChanges("user.user1");

        // suspend the external member and verify the state

        zms.putPrincipalState(ctx, externalMember, auditRef, new PrincipalState().setSuspended(true));

        PrincipalMember pm = zms.dbService.getPrincipal(externalMember);
        assertNotNull(pm);
        assertEquals(pm.getPrincipalName(), externalMember);
        assertEquals(pm.getSuspendedState(), Principal.State.ATHENZ_SYSTEM_DISABLED.getValue());

        // unsuspend the external member and verify the state is cleared

        zms.putPrincipalState(ctx, externalMember, auditRef, new PrincipalState().setSuspended(false));

        pm = zms.dbService.getPrincipal(externalMember);
        assertEquals(pm.getPrincipalName(), externalMember);
        assertEquals(pm.getSuspendedState(), 0);

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        cleanUpUserAdminAuthz();
    }

    @Test
    public void testPutPrincipalStateExternalMemberDomainAdmin() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-state-domain-admin";
        final String externalMember = domainName + ":ext.partner-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);

        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.joe", null);
        zms.putRole(ctx, domainName, "role1", auditRef, false, null, role);

        addExternalMemberToRole(domainName, "role1", externalMember);

        // the caller (user.user1) is a domain admin, so they should be
        // authorized to update the external member state without any
        // system-level state-admin authorization

        zms.putPrincipalState(ctx, externalMember, auditRef, new PrincipalState().setSuspended(true));

        PrincipalMember pm = zms.dbService.getPrincipal(externalMember);
        assertNotNull(pm);
        assertEquals(pm.getPrincipalName(), externalMember);
        assertEquals(pm.getSuspendedState(), Principal.State.ATHENZ_SYSTEM_DISABLED.getValue());

        // unsuspend via domain admin authorization

        zms.putPrincipalState(ctx, externalMember, auditRef, new PrincipalState().setSuspended(false));

        pm = zms.dbService.getPrincipal(externalMember);
        assertEquals(pm.getSuspendedState(), 0);

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutPrincipalStateExternalMemberWithRolesAndGroups() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-state-roles-groups";
        final String externalMember = domainName + ":ext.partner-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);

        // create roles with external member

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.joe", null);
        zms.putRole(ctx, domainName, "role1", auditRef, false, null, role1);
        addExternalMemberToRole(domainName, "role1", externalMember);

        Role role2 = zmsTestInitializer.createRoleObject(domainName, "role2", null,
                "user.jane", null);
        zms.putRole(ctx, domainName, "role2", auditRef, false, null, role2);
        addExternalMemberToRole(domainName, "role2", externalMember);

        // create groups with external member

        Group group1 = zmsTestInitializer.createGroupObject(domainName, "group1",
                "user.joe", null);
        zms.putGroup(ctx, domainName, "group1", auditRef, false, null, group1);
        addExternalMemberToGroup(domainName, "group1", externalMember);

        Group group2 = zmsTestInitializer.createGroupObject(domainName, "group2",
                "user.jane", null);
        zms.putGroup(ctx, domainName, "group2", auditRef, false, null, group2);
        addExternalMemberToGroup(domainName, "group2", externalMember);

        setupUserAdminForStateChanges("user.user1");

        // suspend the external member

        zms.putPrincipalState(ctx, externalMember, auditRef, new PrincipalState().setSuspended(true));

        // verify systemDisabled is set on all role memberships for the external member

        Role role = zms.getRole(ctx, domainName, "role1", false, false, false);
        assertEquals(role.getRoleMembers().size(), 2);
        for (RoleMember member : role.getRoleMembers()) {
            if (member.getMemberName().equals("user.joe")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals(externalMember)) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        role = zms.getRole(ctx, domainName, "role2", false, false, false);
        assertEquals(role.getRoleMembers().size(), 2);
        for (RoleMember member : role.getRoleMembers()) {
            if (member.getMemberName().equals("user.jane")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals(externalMember)) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        // verify systemDisabled is set on all group memberships for the external member

        Group group = zms.getGroup(ctx, domainName, "group1", false, false);
        assertEquals(group.getGroupMembers().size(), 2);
        for (GroupMember member : group.getGroupMembers()) {
            if (member.getMemberName().equals("user.joe")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals(externalMember)) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        group = zms.getGroup(ctx, domainName, "group2", false, false);
        assertEquals(group.getGroupMembers().size(), 2);
        for (GroupMember member : group.getGroupMembers()) {
            if (member.getMemberName().equals("user.jane")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals(externalMember)) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        // unsuspend the external member

        zms.putPrincipalState(ctx, externalMember, auditRef, new PrincipalState().setSuspended(false));

        // verify systemDisabled is cleared on all role memberships

        role = zms.getRole(ctx, domainName, "role1", false, false, false);
        assertEquals(role.getRoleMembers().size(), 2);
        for (RoleMember member : role.getRoleMembers()) {
            assertNull(member.getSystemDisabled());
        }

        role = zms.getRole(ctx, domainName, "role2", false, false, false);
        assertEquals(role.getRoleMembers().size(), 2);
        for (RoleMember member : role.getRoleMembers()) {
            assertNull(member.getSystemDisabled());
        }

        // verify systemDisabled is cleared on all group memberships

        group = zms.getGroup(ctx, domainName, "group1", false, false);
        assertEquals(group.getGroupMembers().size(), 2);
        for (GroupMember member : group.getGroupMembers()) {
            assertNull(member.getSystemDisabled());
        }

        group = zms.getGroup(ctx, domainName, "group2", false, false);
        assertEquals(group.getGroupMembers().size(), 2);
        for (GroupMember member : group.getGroupMembers()) {
            assertNull(member.getSystemDisabled());
        }

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        cleanUpUserAdminAuthz();
    }

    @Test
    public void testPutPrincipalStateExternalMemberMixedWithRegular() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-state-mixed";
        final String externalMember = domainName + ":ext.partner-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);

        // create a role with both regular and external members

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.joe", "user.jane");
        zms.putRole(ctx, domainName, "role1", auditRef, false, null, role1);
        addExternalMemberToRole(domainName, "role1", externalMember);

        // create a group with both regular and external members

        Group group1 = zmsTestInitializer.createGroupObject(domainName, "group1",
                "user.joe", "user.jane");
        zms.putGroup(ctx, domainName, "group1", auditRef, false, null, group1);
        addExternalMemberToGroup(domainName, "group1", externalMember);

        setupUserAdminForStateChanges("user.user1");

        // suspend only the external member

        zms.putPrincipalState(ctx, externalMember, auditRef, new PrincipalState().setSuspended(true));

        // verify only the external member is suspended in the role, regular members unaffected

        Role role = zms.getRole(ctx, domainName, "role1", false, false, false);
        assertEquals(role.getRoleMembers().size(), 3);
        for (RoleMember member : role.getRoleMembers()) {
            if (member.getMemberName().equals("user.joe")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals("user.jane")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals(externalMember)) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        // verify only the external member is suspended in the group

        Group group = zms.getGroup(ctx, domainName, "group1", false, false);
        assertEquals(group.getGroupMembers().size(), 3);
        for (GroupMember member : group.getGroupMembers()) {
            if (member.getMemberName().equals("user.joe")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals("user.jane")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals(externalMember)) {
                assertEquals(member.getSystemDisabled(), 4);
            } else {
                fail();
            }
        }

        // unsuspend the external member

        zms.putPrincipalState(ctx, externalMember, auditRef, new PrincipalState().setSuspended(false));

        // now suspend a regular member and verify external member is NOT affected

        zms.putPrincipalState(ctx, "user.joe", auditRef, new PrincipalState().setSuspended(true));

        role = zms.getRole(ctx, domainName, "role1", false, false, false);
        assertEquals(role.getRoleMembers().size(), 3);
        for (RoleMember member : role.getRoleMembers()) {
            if (member.getMemberName().equals("user.joe")) {
                assertEquals(member.getSystemDisabled(), 4);
            } else if (member.getMemberName().equals("user.jane")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals(externalMember)) {
                assertNull(member.getSystemDisabled());
            } else {
                fail();
            }
        }

        group = zms.getGroup(ctx, domainName, "group1", false, false);
        assertEquals(group.getGroupMembers().size(), 3);
        for (GroupMember member : group.getGroupMembers()) {
            if (member.getMemberName().equals("user.joe")) {
                assertEquals(member.getSystemDisabled(), 4);
            } else if (member.getMemberName().equals("user.jane")) {
                assertNull(member.getSystemDisabled());
            } else if (member.getMemberName().equals(externalMember)) {
                assertNull(member.getSystemDisabled());
            } else {
                fail();
            }
        }

        // clean up the regular user suspension

        zms.putPrincipalState(ctx, "user.joe", auditRef, new PrincipalState().setSuspended(false));

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        cleanUpUserAdminAuthz();
    }

    @Test
    public void testPutPrincipalStateExternalMemberUnauthorized() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-state-unauth";
        final String externalMember = domainName + ":ext.partner-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);

        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.joe", null);
        zms.putRole(ctx, domainName, "role1", auditRef, false, null, role);
        addExternalMemberToRole(domainName, "role1", externalMember);

        // create a second domain where the caller is NOT an admin
        // and try to update an external member in that domain

        final String otherDomainName = "ext-state-unauth-other";
        final String otherExternalMember = otherDomainName + ":ext.partner-user";

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(otherDomainName,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom2);

        setupExternalMemberValidator(otherDomainName);

        Role role2 = zmsTestInitializer.createRoleObject(otherDomainName, "role1", null,
                "user.joe", null);
        zms.putRole(ctx, otherDomainName, "role1", auditRef, false, null, role2);
        addExternalMemberToRole(otherDomainName, "role1", otherExternalMember);

        // remove the caller from the admin role in the other domain

        zms.deleteMembership(ctx, otherDomainName, "admin",
                ctx.principal().getFullName(), auditRef, null);

        // try to suspend the external member in the other domain
        // without system-level auth - should fail with 403

        try {
            zms.putPrincipalState(ctx, otherExternalMember, auditRef,
                    new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unauthorized to update principal state"));
        }

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zms.deleteTopLevelDomain(ctx, otherDomainName, auditRef, null);
    }

    @Test
    public void testPutPrincipalStateExternalMemberNotFound() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-state-not-found";
        final String externalMember = domainName + ":ext.unknown-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom);

        // the domain exists and the caller is a domain admin, so
        // authorization passes but the external member is not in the DB

        try {
            zms.putPrincipalState(ctx, externalMember, auditRef,
                    new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("Principal not found"));
        }

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutPrincipalStateExternalMemberInvalidCases() {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-state-invalid";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom);

        final String externalMember = domainName + ":ext.partner-user";

        // try without audit reference

        try {
            zms.putPrincipalState(ctx, externalMember, null,
                    new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference is required"));
        }

        // try with empty audit reference

        try {
            zms.putPrincipalState(ctx, externalMember, "",
                    new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference is required"));
        }

        // try with an external member in a non-existing domain

        try {
            zms.putPrincipalState(ctx, "unknown-ext-domain:ext.partner-user", auditRef,
                    new PrincipalState().setSuspended(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("Domain not found"));
        }

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutPrincipalStateExternalMemberConnectionFailure() throws ServerResourceException {

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-state-conn-fail";
        final String externalMember = domainName + ":ext.partner-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom);

        setupExternalMemberValidator(domainName);

        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.joe", null);
        zms.putRole(ctx, domainName, "role1", auditRef, false, null, role);
        addExternalMemberToRole(domainName, "role1", externalMember);

        // mock a connection failure

        ObjectStore mockObjStore = Mockito.mock(ObjectStore.class);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
                .thenThrow(new ServerResourceException(500, "DB Error"));

        try {
            zms.dbService.executePutPrincipalState(ctx, domainName, externalMember,
                    new PrincipalState().setSuspended(true), auditRef, "putPrincipalState");
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 500);
        }

        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = saveRetryCount;

        zms.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}