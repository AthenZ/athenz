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
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.store.ObjectStore;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

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
    public void testPutPrincipalStateNoMemberConnectionFailure() {

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
                .thenThrow(new ResourceException(500, "DB Error"));

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
}