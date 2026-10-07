/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.zms;

import com.google.common.cache.CacheBuilder;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.store.AthenzDomain;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.common.server.store.ObjectStoreConnection;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.zms.config.SolutionTemplates;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class DBServiceAdminAccessTest {

    @Test
    public void testTemplateMetadataCopiesPreservationOverride() {
        ZMSImpl zms = mock(ZMSImpl.class, CALLS_REAL_METHODS);
        for (Boolean value : new Boolean[] {null, false, true}) {
            TemplateMetaData source = new TemplateMetaData().setPreserveAdminAccess(value);
            TemplateMetaData copy = zms.copyTemplateMetaData("admin-trust", source);
            assertEquals(copy.getPreserveAdminAccess(), value);
            assertEquals(copy.getTemplateName(), "admin-trust");
            assertNull(source.getTemplateName());
        }
    }

    @DataProvider(name = "delegatedAccessPolicies")
    public Object[][] delegatedAccessPolicies() {
        return new Object[][] {
                {List.of(policy(delegation(AssertionEffect.ALLOW))), true},
                {List.of(policy(delegation(null))), true},
                {List.of(policy(delegation(AssertionEffect.DENY))), false},
                {List.of(), false},
                {List.of(policy(delegation(AssertionEffect.ALLOW), delegation(AssertionEffect.DENY))), false},
                {List.of(policy(delegation(AssertionEffect.DENY), delegation(AssertionEffect.ALLOW))), false},
                {List.of(policy(delegation(AssertionEffect.ALLOW)), policy(delegation(AssertionEffect.DENY))), false},
                {List.of(policy(delegation(AssertionEffect.DENY)), policy(delegation(AssertionEffect.ALLOW))), false},
                {List.of(policy(delegation(AssertionEffect.DENY)).setActive(false),
                        policy(delegation(AssertionEffect.ALLOW))), true},
                {List.of(policy(delegation(AssertionEffect.ALLOW)).setActive(false)), false},
                {List.of(new Policy(), policy(), policy(delegation(AssertionEffect.ALLOW))), true},
                {List.of(policy(delegation(AssertionEffect.DENY).setResource("other:role.admin")),
                        policy(delegation(AssertionEffect.ALLOW))), true},
                {List.of(policy(delegation(AssertionEffect.DENY).setAction("update")),
                        policy(delegation(AssertionEffect.ALLOW))), true},
                {List.of(policy(delegation(AssertionEffect.DENY).setRole("trust:role.others")),
                        policy(delegation(AssertionEffect.ALLOW))), true},
                {List.of(policy(delegation(AssertionEffect.ALLOW)),
                        policy(delegation(AssertionEffect.DENY).setResource("target:role.*")
                                .setRole("trust:role.*"))), false},
                {List.of(policy(delegation(AssertionEffect.ALLOW).setConditions(conditions()))), false},
                {List.of(policy(delegation(AssertionEffect.ALLOW).setConditions(conditions())),
                        policy(delegation(AssertionEffect.ALLOW))), true},
                {List.of(policy(delegation(AssertionEffect.ALLOW)),
                        policy(delegation(AssertionEffect.DENY).setConditions(conditions()))), false},
        };
    }

    @Test(dataProvider = "delegatedAccessPolicies")
    public void testPreservedAccessHonorsPolicies(List<Policy> policies, boolean allowed)
            throws ServerResourceException {
        Fixture fixture = new Fixture();
        for (int i = 0; i < policies.size(); i++) {
            policies.get(i).setName("trust:policy.rule" + i);
        }
        fixture.trustDomain.setPolicies(policies);
        if (allowed) {
            fixture.apply();
            verify(fixture.con).deleteRoleMember("target", "admin", "user.alice", null, "audit");
            verify(fixture.con).commitChanges();
        } else {
            fixture.assertRejectedBeforeChanges();
        }
    }

    @DataProvider(name = "separateDenyRole")
    public Object[][] separateDenyRole() {
        return new Object[][] {
                {false, false}, {false, true}, {true, false}, {true, true},
        };
    }

    @Test(dataProvider = "separateDenyRole")
    public void testAllowAndDenyThroughDifferentRoles(boolean groupMembership, boolean denyFirst)
            throws ServerResourceException {
        Fixture fixture = new Fixture();
        Role denyRole = new Role().setName("trust:role.blocked").setRoleMembers(List.of(
                member(groupMembership ? "trust:group.blocked" : "user.alice")));
        fixture.trustDomain.setRoles(List.of(fixture.trustDomain.getRoles().get(0), denyRole));
        when(fixture.con.listGroupMembers("trust", "blocked", false))
                .thenReturn(List.of(new GroupMember().setMemberName("user.alice")));
        Policy allow = policy(delegation(AssertionEffect.ALLOW));
        Policy deny = policy(delegation(AssertionEffect.DENY).setRole("trust:role.blocked"))
                .setName("trust:policy.blocked");
        fixture.trustDomain.setPolicies(denyFirst ? List.of(deny, allow) : List.of(allow, deny));

        fixture.assertRejectedBeforeChanges();

        // A denial for another principal must not block Alice's valid grant.
        if (groupMembership) {
            when(fixture.con.listGroupMembers("trust", "blocked", false))
                    .thenReturn(List.of(new GroupMember().setMemberName("user.bob")));
        } else {
            denyRole.setRoleMembers(List.of(member("user.bob")));
        }
        fixture.apply();
        verify(fixture.con).commitChanges();
    }

    @Test
    public void testExpiredAndDisabledDelegatedMembersDoNotPreserveAccess() {
        DBService dbService = mock(DBService.class, CALLS_REAL_METHODS);
        AthenzDomain trustDomain = new AthenzDomain("trust");
        trustDomain.setPolicies(List.of(policy(delegation(AssertionEffect.ALLOW))));
        RoleMember member = new RoleMember().setMemberName("user.alice").setExpiration(Timestamp.fromMillis(1));
        trustDomain.setRoles(List.of(new Role().setName("trust:role.admins").setRoleMembers(List.of(member))));
        assertEquals(dbService.hasPreservedAdminAccess(trustDomain, "target:role.admin", "user.alice",
                name -> List.of()), false);
        member.setExpiration(null).setSystemDisabled(1);
        assertEquals(dbService.hasPreservedAdminAccess(trustDomain, "target:role.admin", "user.alice",
                name -> List.of()), false);
    }

    @DataProvider(name = "preservationDefaults")
    public Object[][] preservationDefaults() {
        return new Object[][] {
                {false, null, false}, {true, null, true},
                {false, new TemplateMetaData(), false}, {true, new TemplateMetaData(), true},
                {false, new TemplateMetaData().setPreserveAdminAccess(false), false},
                {true, new TemplateMetaData().setPreserveAdminAccess(false), false},
                {false, new TemplateMetaData().setPreserveAdminAccess(true), true},
                {true, new TemplateMetaData().setPreserveAdminAccess(true), true},
        };
    }

    @Test(dataProvider = "preservationDefaults")
    public void testDefaultAndTemplateOverrides(boolean serverDefault, TemplateMetaData metadata, boolean rejects)
            throws ServerResourceException {
        Fixture fixture = new Fixture();
        fixture.service.defaultPreserveAdminAccess = new DynamicConfigBoolean(serverDefault);
        fixture.template.setMetadata(metadata);
        fixture.trustDomain.setPolicies(List.of());

        if (rejects) {
            ResourceException ex = expectThrows(ResourceException.class, fixture::apply);
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("does not have delegated access"));
            verify(fixture.con, never()).updateRole(anyString(), any());
            verify(fixture.con, never()).deleteRoleMember(anyString(), anyString(), anyString(), any(), any());
            verify(fixture.con, never()).commitChanges();
        } else {
            fixture.apply();
            verify(fixture.con).updateRole(eq("target"), argThat(role -> "trust".equals(role.getTrust())));
            verify(fixture.con).deleteRoleMember("target", "admin", "user.alice", null, "audit");
            verify(fixture.con).commitChanges();
        }
    }

    @Test
    public void testAllCurrentAdminsMustRetainAccess() throws ServerResourceException {
        Fixture fixture = new Fixture();
        List<RoleMember> admins = List.of(member("user.alice"), member("user.bob"));
        when(fixture.con.listRoleMembers("target", "admin", false)).thenReturn(admins);
        when(fixture.con.listRoleMembers("target", "admin", true)).thenReturn(admins);

        ResourceException ex = expectThrows(ResourceException.class, fixture::apply);
        assertTrue(ex.getMessage().contains("admin user.bob does not have delegated access"));
        verify(fixture.con, never()).updateRole(anyString(), any());

        fixture.trustDomain.getRoles().get(0).setRoleMembers(admins);
        fixture.apply();
        verify(fixture.con).deleteRoleMember("target", "admin", "user.alice", null, "audit");
        verify(fixture.con).deleteRoleMember("target", "admin", "user.bob", null, "audit");
        verify(fixture.con).commitChanges();
    }

    @DataProvider(name = "existingTrust")
    public Object[][] existingTrust() {
        return new Object[][] {{null}, {"trust"}};
    }

    @Test(dataProvider = "existingTrust")
    public void testClearsApprovedAndPendingMembers(String existingTrust) throws ServerResourceException {
        Fixture fixture = new Fixture();
        fixture.currentAdmin.setTrust(existingTrust).setReviewEnabled(true).setDeleteProtection(true);
        when(fixture.con.listRoleMembers("target", "admin", true)).thenReturn(List.of(
                member("user.alice"), member("user.alice").setApproved(false),
                member("user.pending").setApproved(false)));

        fixture.apply();

        verify(fixture.con).deleteRoleMember("target", "admin", "user.alice", null, "audit");
        verify(fixture.con).deletePendingRoleMember("target", "admin", "user.alice", null, "audit");
        verify(fixture.con).deletePendingRoleMember("target", "admin", "user.pending", null, "audit");
        verify(fixture.con, never()).deleteRoleMember(eq("target"), eq("admin"), eq("user.pending"), any(), any());
        verify(fixture.con, never()).insertRoleMember(anyString(), anyString(), any(), any(), any());
        verify(fixture.con).commitChanges();
    }

    @Test
    public void testRejectsLegacyAdminWithoutDelegatedAccess() throws ServerResourceException {
        Fixture fixture = new Fixture();
        fixture.currentAdmin.setTrust("trust");
        fixture.trustDomain.setPolicies(List.of());

        fixture.assertRejectedBeforeChanges();
    }

    @Test
    public void testAllowsReapplyingCleanAdminTrust() throws ServerResourceException {
        Fixture fixture = new Fixture();
        fixture.currentAdmin.setTrust("trust");
        when(fixture.con.listRoleMembers("target", "admin", false)).thenReturn(List.of());
        when(fixture.con.listRoleMembers("target", "admin", true)).thenReturn(List.of());
        fixture.trustDomain.setPolicies(List.of());

        fixture.apply();

        verify(fixture.con, never()).deleteRoleMember(anyString(), anyString(), anyString(), any(), any());
        verify(fixture.con).commitChanges();
    }

    @Test
    public void testPendingCleanupFailureRollsBack() throws ServerResourceException {
        Fixture fixture = new Fixture();
        when(fixture.con.listRoleMembers("target", "admin", true)).thenReturn(
                List.of(member("user.alice"), member("user.pending").setApproved(false)));
        when(fixture.con.deletePendingRoleMember("target", "admin", "user.pending", null, "audit"))
                .thenReturn(false);

        expectThrows(ResourceException.class, fixture::apply);

        verify(fixture.con).rollbackChanges();
        verify(fixture.con, never()).updateRole(anyString(), any());
        verify(fixture.con, never()).commitChanges();
    }

    @Test
    public void testIgnoresExpiredAndDisabledSourceAdmins() throws ServerResourceException {
        Fixture fixture = new Fixture();
        when(fixture.con.listRoleMembers("target", "admin", false)).thenReturn(List.of(
                member("user.alice"), member("user.expired").setExpiration(Timestamp.fromMillis(1)),
                member("user.disabled").setSystemDisabled(1)));
        fixture.apply();
        verify(fixture.con).commitChanges();
    }

    @Test
    public void testRejectsDuplicateAdminTrustRolesImmediately() throws ServerResourceException {
        Role regular = new Role().setName("_domain_:role.admin");
        Role delegated = new Role().setName("_domain_:role.admin").setTrust("trust");
        Role missing = new Role().setName("_domain_:role.admin").setTrust("missing");
        for (List<Role> roles : List.of(List.of(delegated, missing), List.of(delegated, regular, missing),
                List.of(regular, delegated, missing), List.of(regular, regular, delegated, missing))) {
            Fixture fixture = new Fixture();
            fixture.template.setRoles(roles);

            ResourceException ex = expectThrows(ResourceException.class, fixture::apply);

            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("multiple admin roles are defined"), ex.getMessage());
            verify(fixture.con, never()).getDomain("missing");
            verify(fixture.con, never()).updateRole(anyString(), any());
            verify(fixture.con, never()).commitChanges();
        }
    }

    @Test
    public void testAllowsMultipleAdminRolesWithoutTrust() throws ServerResourceException {
        Fixture fixture = new Fixture();
        fixture.template.setRoles(List.of(new Role().setName("_domain_:role.admin"),
                new Role().setName("_domain_:role.admin")));

        fixture.apply();

        verify(fixture.con, never()).deleteRoleMember(anyString(), anyString(), anyString(), any(), any());
        verify(fixture.con).commitChanges();
    }

    @Test
    public void testRejectsAdminTrustMembersImmediately() throws ServerResourceException {
        for (boolean legacyMembers : new boolean[] {false, true}) {
            Fixture fixture = new Fixture();
            Role delegated = fixture.template.getRoles().get(0);
            if (legacyMembers) {
                delegated.setMembers(List.of("user.alice"));
            } else {
                delegated.setRoleMembers(List.of(member("user.alice")));
            }
            fixture.template.setRoles(List.of(delegated,
                    new Role().setName("_domain_:role.admin").setTrust("missing")));

            ResourceException ex = expectThrows(ResourceException.class, fixture::apply);

            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("template admin role cannot define members"), ex.getMessage());
            verify(fixture.con, never()).getDomain("missing");
            verify(fixture.con, never()).updateRole(anyString(), any());
            verify(fixture.con, never()).commitChanges();
        }
    }

    @Test
    public void testRejectsWildcardAdminsAndDifferentExistingTrust() throws ServerResourceException {
        Fixture fixture = new Fixture();
        when(fixture.con.listRoleMembers("target", "admin", false)).thenReturn(List.of(member("user.*")));
        ResourceException wildcard = expectThrows(ResourceException.class, fixture::apply);
        assertTrue(wildcard.getMessage().contains("cannot verify wildcard admin"));
        fixture.currentAdmin.setTrust("other");
        ResourceException trustChange = expectThrows(ResourceException.class, fixture::apply);
        assertTrue(trustChange.getMessage().contains("cannot change an existing admin trust domain"));
        verify(fixture.con, never()).updateRole(anyString(), any());
        verify(fixture.con, never()).commitChanges();
    }

    @Test
    public void testExpandsSourceAndDelegatedGroups() throws ServerResourceException {
        Fixture fixture = new Fixture();
        when(fixture.con.listRoleMembers("target", "admin", false))
                .thenReturn(List.of(member("target:group.admins")));
        when(fixture.con.listGroupMembers("target", "admins", false)).thenReturn(List.of(
                new GroupMember().setMemberName("user.alice"), new GroupMember().setMemberName("user.bob")));
        fixture.trustDomain.getRoles().get(0).setRoleMembers(List.of(member("target:group.admins")));
        fixture.apply();
        verify(fixture.con).commitChanges();
    }

    @DataProvider(name = "invalidDelegatedGroups")
    public Object[][] invalidDelegatedGroups() {
        return new Object[][] {
                {Timestamp.fromMillis(1), new GroupMember().setMemberName("user.alice")},
                {null, new GroupMember().setMemberName("user.alice").setExpiration(Timestamp.fromMillis(1))},
                {null, new GroupMember().setMemberName("user.alice").setSystemDisabled(1)},
                {null, new GroupMember().setMemberName("user.bob")},
        };
    }

    @Test(dataProvider = "invalidDelegatedGroups")
    public void testInvalidGroupGrantCannotPreserveAdmin(Timestamp groupExpiration, GroupMember groupMember)
            throws ServerResourceException {
        Fixture fixture = new Fixture();
        fixture.trustDomain.getRoles().get(0).setRoleMembers(List.of(
                member("trust:group.admins").setExpiration(groupExpiration)));
        when(fixture.con.listGroupMembers("trust", "admins", false)).thenReturn(List.of(groupMember));
        fixture.assertRejectedBeforeChanges();
    }

    @Test
    public void testRechecksDelegatedGroupBeforeCommit() throws ServerResourceException {
        Fixture fixture = new Fixture();
        fixture.trustDomain.getRoles().get(0).setRoleMembers(List.of(member("target:group.admins")));
        // The transaction initially preserves access, but its final group state no longer does.
        when(fixture.con.listGroupMembers("target", "admins", false))
                .thenReturn(List.of(new GroupMember().setMemberName("user.alice")))
                .thenReturn(List.of(new GroupMember().setMemberName("user.alice")
                        .setExpiration(Timestamp.fromMillis(1))));

        ResourceException ex = expectThrows(ResourceException.class, fixture::apply);

        assertTrue(ex.getMessage().contains("does not have delegated access"));
        verify(fixture.con).updateRole(eq("target"), any());
        verify(fixture.con).rollbackChanges();
        verify(fixture.con, never()).commitChanges();
    }

    @Test(dataProvider = "existingTrust")
    public void testDenyInFinalStateRollsBackConversion(String existingTrust) throws ServerResourceException {
        Fixture fixture = new Fixture();
        fixture.currentAdmin.setTrust(existingTrust);
        AthenzDomain finalTrustDomain = new AthenzDomain("trust");
        finalTrustDomain.setRoles(fixture.trustDomain.getRoles());
        finalTrustDomain.setPolicies(List.of(policy(delegation(AssertionEffect.ALLOW),
                delegation(AssertionEffect.DENY))));
        when(fixture.con.getAthenzDomain("trust")).thenReturn(fixture.trustDomain, finalTrustDomain);

        ResourceException ex = expectThrows(ResourceException.class, fixture::apply);

        assertTrue(ex.getMessage().contains("does not have delegated access"));
        verify(fixture.con).updateRole(eq("target"), any());
        verify(fixture.con).deleteRoleMember("target", "admin", "user.alice", null, "audit");
        verify(fixture.con).rollbackChanges();
        verify(fixture.con, never()).commitChanges();
    }

    @Test
    public void testRoleFailureAfterPendingAdminDeletionRollsBack() throws ServerResourceException {
        Fixture fixture = new Fixture();
        when(fixture.con.listRoleMembers("target", "admin", true)).thenReturn(List.of(
                member("user.pending").setApproved(false), member("user.alice")));
        when(fixture.con.updateRole(eq("target"), any())).thenThrow(new IllegalStateException("role update failed"));

        IllegalStateException ex = expectThrows(IllegalStateException.class, fixture::apply);

        assertEquals(ex.getMessage(), "role update failed");
        verify(fixture.con).deletePendingRoleMember("target", "admin", "user.pending", null, "audit");
        verify(fixture.con).rollbackChanges();
        verify(fixture.con, never()).commitChanges();
    }

    private class Fixture {
        final ObjectStoreConnection con = mock(ObjectStoreConnection.class);
        final DBService service = mock(DBService.class, CALLS_REAL_METHODS);
        final Role currentAdmin = new Role().setName("target:role.admin");
        final AthenzDomain trustDomain = new AthenzDomain("trust");
        final Template template = new Template().setMetadata(new TemplateMetaData().setPreserveAdminAccess(true))
                .setRoles(List.of(new Role().setName("_domain_:role.admin").setTrust("trust")));
        final SolutionTemplates templates = new SolutionTemplates();

        Fixture() throws ServerResourceException {
            service.store = mock(ObjectStore.class);
            service.zmsConfig = mock(ZMSConfig.class);
            service.auditRefSet = new BitSet();
            service.cacheStore = CacheBuilder.newBuilder().build();
            service.defaultPreserveAdminAccess = new DynamicConfigBoolean(false);
            when(service.store.getConnection(false, true)).thenReturn(con);
            when(service.zmsConfig.getValidator()).thenReturn(new Validator(ZMSSchema.instance()));
            when(service.zmsConfig.getUserDomainPrefix()).thenReturn("user.");
            when(service.zmsConfig.getHeadlessUserDomainPrefix()).thenReturn("headless.");
            when(con.getDomain("trust")).thenReturn(new Domain().setName("trust"));
            when(con.getRole("target", "admin")).thenReturn(currentAdmin);
            when(con.listRoleMembers("target", "admin", false)).thenReturn(List.of(member("user.alice")));
            when(con.listRoleMembers("target", "admin", true)).thenReturn(List.of(member("user.alice")));
            trustDomain.setRoles(List.of(new Role().setName("trust:role.admins")
                    .setRoleMembers(List.of(member("user.alice")))));
            trustDomain.setPolicies(List.of(policy(delegation(AssertionEffect.ALLOW))));
            when(con.getAthenzDomain("trust")).thenReturn(trustDomain);
            when(con.updateRole(eq("target"), any())).thenReturn(true);
            when(con.deleteRoleMember(eq("target"), eq("admin"), anyString(), isNull(), eq("audit")))
                    .thenReturn(true);
            when(con.deletePendingRoleMember(eq("target"), eq("admin"), anyString(), isNull(), eq("audit")))
                    .thenReturn(true);
            doNothing().when(service).auditLogRequest(nullable(ResourceContext.class), anyString(), anyString(),
                    anyString(), anyString(), anyString(), anyString());
            HashMap<String, Template> map = new HashMap<>();
            map.put("admin-trust", template);
            templates.setTemplates(map);
        }

        void apply() {
            service.executePutDomainTemplate(null, "target", new DomainTemplate()
                    .setTemplateNames(List.of("admin-trust")), "audit", "putDomainTemplate", templates);
        }

        void assertRejectedBeforeChanges() throws ServerResourceException {
            ResourceException ex = expectThrows(ResourceException.class, this::apply);
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("does not have delegated access"));
            verify(con, never()).updateRole(anyString(), any());
            verify(con, never()).deleteRoleMember(anyString(), anyString(), anyString(), any(), any());
            verify(con, never()).deletePendingRoleMember(anyString(), anyString(), anyString(), any(), any());
            verify(con, never()).insertDomainTemplate(anyString(), anyString(), any());
            verify(con, never()).commitChanges();
        }
    }

    private RoleMember member(String name) {
        return new RoleMember().setMemberName(name).setApproved(true);
    }

    private Policy policy(Assertion... assertions) {
        return new Policy().setName("trust:policy.admins").setAssertions(List.of(assertions));
    }

    private Assertion delegation(AssertionEffect effect) {
        return new Assertion().setAction("assume_role").setResource("target:role.admin")
                .setRole("trust:role.admins").setEffect(effect);
    }

    private AssertionConditions conditions() {
        return new AssertionConditions().setConditionsList(List.of(new AssertionCondition().setConditionsMap(
                Map.of("enforcement-state", new AssertionConditionData()
                        .setOperator(AssertionConditionOperator.EQUALS).setValue("enforce")))));
    }
}
