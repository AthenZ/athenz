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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.Group;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_FILE_NAME;
import static com.yahoo.athenz.common.ServerCommonConsts.METRIC_DEFAULT_FACTORY_CLASS;
import static org.testng.Assert.*;

public class ZTSExternalMemberTest {

    private ZTSImpl zts = null;
    private DataStore store = null;
    private PrivateKey privateKey = null;
    private CloudStore cloudStore = null;

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String MOCKCLIENTADDR = "10.11.12.13";

    @Mock private HttpServletRequest mockServletRequest;
    @Mock private HttpServletResponse mockServletResponse;

    @BeforeClass
    public void setupClass() {
        MockitoAnnotations.openMocks(this);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);

        System.setProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS, METRIC_DEFAULT_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.cloud:4443/zts/v1");
    }

    @BeforeMethod
    public void setUp() {

        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));

        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File privKeyFile = new File(privKeyName);
        String privKey = Crypto.encodedFile(privKeyFile);
        privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));

        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_IDENTITY, "false");

        ChangeLogStore structStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        cloudStore = new CloudStore();
        store = new DataStore(structStore, cloudStore, new com.yahoo.athenz.common.metrics.impl.NoOpMetric());
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";
    }

    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
    }

    private ResourceContext createResourceContext(Principal principal) {
        ServerResourceContext rsrcCtx = Mockito.mock(ServerResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        Mockito.when(mockServletRequest.isSecure()).thenReturn(true);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        Mockito.when(rsrcCtxWrapper.principal()).thenReturn(principal);
        Mockito.when(rsrcCtxWrapper.request()).thenReturn(mockServletRequest);
        Mockito.when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        if (principal != null) {
            Mockito.when(rsrcCtxWrapper.logPrincipal()).thenReturn(principal.getFullName());
            Mockito.when(rsrcCtxWrapper.getPrincipalDomain()).thenReturn(principal.getDomain());
        }
        return rsrcCtxWrapper;
    }

    @Test
    public void testAccessCheckWithExternalMember() {

        final String domainName = "ext-mbr-access-test";
        final String roleName = "readers";
        final String regularMember = "user.joe";
        final String externalMember = domainName + ":ext.partner-user";

        // create a role with a regular user and an external member

        Role role = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);
        role.getRoleMembers().add(new RoleMember().setMemberName(externalMember));

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        // create a policy that grants READ access on the domain's resources
        // to members of the readers role

        Policy policy = ZTSTestUtils.createPolicyObject(domainName, "read-policy",
                roleName, true, "READ", domainName + ":data",
                com.yahoo.athenz.zms.AssertionEffect.ALLOW);

        List<Policy> policies = new ArrayList<>();
        policies.add(policy);

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, policies,
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(signedDomain, false);

        // verify that the regular member has access

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal regularPrincipal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext regularCtx = createResourceContext(regularPrincipal);

        ResourceAccess access = zts.getResourceAccess(regularCtx, "READ", domainName + ":data", null, null);
        assertTrue(access.getGranted(), "Regular member should have READ access");

        // verify that the external member has access using checkPrincipal

        access = zts.getResourceAccess(regularCtx, "READ", domainName + ":data", null, externalMember);
        assertTrue(access.getGranted(), "External member should have READ access");

        // reprocess the domain without the external member to simulate removal

        Role roleWithoutExtMember = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(roleWithoutExtMember);

        SignedDomain updatedDomain = ZTSTestUtils.createSignedDomain(domainName, updatedRoles, policies,
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(updatedDomain, false);

        // verify the external member no longer has access

        access = zts.getResourceAccess(regularCtx, "READ", domainName + ":data", null, externalMember);
        assertFalse(access.getGranted(), "External member should no longer have READ access after removal");

        // verify that the regular member still has access

        access = zts.getResourceAccess(regularCtx, "READ", domainName + ":data", null, null);
        assertTrue(access.getGranted(), "Regular member should still have READ access");

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testAccessCheckWithExternalMemberViaGroup() {

        final String domainName = "ext-mbr-group-access";
        final String roleName = "readers";
        final String groupName = "partners";
        final String regularMember = "user.joe";
        final String externalMember = domainName + ":ext.partner-user";
        final String groupResourceName = ResourceUtils.groupResourceName(domainName, groupName);

        // create a group with the external member

        Group group = ZTSTestUtils.createGroupObject(domainName, groupName, externalMember);

        List<Group> groups = new ArrayList<>();
        groups.add(group);

        // create a role with a regular user and the group as members

        Role role = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);
        role.getRoleMembers().add(new RoleMember().setMemberName(groupResourceName));

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        // create a policy that grants READ access to members of the readers role

        Policy policy = ZTSTestUtils.createPolicyObject(domainName, "read-policy",
                roleName, true, "READ", domainName + ":data",
                com.yahoo.athenz.zms.AssertionEffect.ALLOW);

        List<Policy> policies = new ArrayList<>();
        policies.add(policy);

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, policies,
                (List<ServiceIdentity>) null, groups, privateKey);
        store.processSignedDomain(signedDomain, false);

        // verify that the regular member has access

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal regularPrincipal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext regularCtx = createResourceContext(regularPrincipal);

        ResourceAccess access = zts.getResourceAccess(regularCtx, "READ", domainName + ":data", null, null);
        assertTrue(access.getGranted(), "Regular member should have READ access");

        // verify that the external member has access through group membership

        access = zts.getResourceAccess(regularCtx, "READ", domainName + ":data", null, externalMember);
        assertTrue(access.getGranted(),
                "External member should have READ access through group membership");

        // reprocess the domain with the group having no external member to simulate removal

        Group groupWithoutExtMember = ZTSTestUtils.createGroupObject(domainName, groupName);

        List<Group> updatedGroups = new ArrayList<>();
        updatedGroups.add(groupWithoutExtMember);

        SignedDomain updatedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, policies,
                (List<ServiceIdentity>) null, updatedGroups, privateKey);
        store.processSignedDomain(updatedDomain, false);

        // verify the external member no longer has access

        access = zts.getResourceAccess(regularCtx, "READ", domainName + ":data", null, externalMember);
        assertFalse(access.getGranted(),
                "External member should no longer have READ access after removal from group");

        // verify that the regular member still has access

        access = zts.getResourceAccess(regularCtx, "READ", domainName + ":data", null, null);
        assertTrue(access.getGranted(), "Regular member should still have READ access");

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetAccessWithExternalMember() {

        final String domainName = "ext-mbr-getaccess";
        final String roleName = "readers";
        final String regularMember = "user.joe";
        final String externalMember = domainName + ":ext.partner-user";

        Role role = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);
        role.getRoleMembers().add(new RoleMember().setMemberName(externalMember));

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        List<Policy> policies = new ArrayList<>();

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, policies,
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // regular member should have access to the role

        Access access = zts.getAccess(ctx, domainName, roleName, regularMember);
        assertTrue(access.getGranted(), "Regular member should have access to role");

        // external member should have access to the role

        access = zts.getAccess(ctx, domainName, roleName, externalMember);
        assertTrue(access.getGranted(), "External member should have access to role");

        // external member that is not in the role should not have access

        access = zts.getAccess(ctx, domainName, roleName, domainName + ":ext.unknown");
        assertFalse(access.getGranted(), "Unknown external member should not have access");

        // reprocess the domain without the external member

        Role roleWithoutExtMember = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);
        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(roleWithoutExtMember);

        SignedDomain updatedDomain = ZTSTestUtils.createSignedDomain(domainName, updatedRoles, policies,
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(updatedDomain, false);

        // external member should no longer have access

        access = zts.getAccess(ctx, domainName, roleName, externalMember);
        assertFalse(access.getGranted(), "External member should no longer have access after removal");

        // regular member should still have access

        access = zts.getAccess(ctx, domainName, roleName, regularMember);
        assertTrue(access.getGranted(), "Regular member should still have access");

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetAccessWithExternalMemberViaGroup() {

        final String domainName = "ext-mbr-getaccess-grp";
        final String roleName = "readers";
        final String groupName = "partners";
        final String regularMember = "user.joe";
        final String externalMember = domainName + ":ext.partner-user";
        final String groupResourceName = ResourceUtils.groupResourceName(domainName, groupName);

        Group group = ZTSTestUtils.createGroupObject(domainName, groupName, externalMember);

        List<Group> groups = new ArrayList<>();
        groups.add(group);

        Role role = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);
        role.getRoleMembers().add(new RoleMember().setMemberName(groupResourceName));

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        List<Policy> policies = new ArrayList<>();

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, policies,
                (List<ServiceIdentity>) null, groups, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // regular member should have access

        Access access = zts.getAccess(ctx, domainName, roleName, regularMember);
        assertTrue(access.getGranted(), "Regular member should have access");

        // external member should have access through group membership

        access = zts.getAccess(ctx, domainName, roleName, externalMember);
        assertTrue(access.getGranted(), "External member should have access through group");

        // reprocess with group having no external member

        Group groupWithoutExtMember = ZTSTestUtils.createGroupObject(domainName, groupName);
        List<Group> updatedGroups = new ArrayList<>();
        updatedGroups.add(groupWithoutExtMember);

        SignedDomain updatedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, policies,
                (List<ServiceIdentity>) null, updatedGroups, privateKey);
        store.processSignedDomain(updatedDomain, false);

        // external member should no longer have access

        access = zts.getAccess(ctx, domainName, roleName, externalMember);
        assertFalse(access.getGranted(),
                "External member should no longer have access after removal from group");

        // regular member should still have access

        access = zts.getAccess(ctx, domainName, roleName, regularMember);
        assertTrue(access.getGranted(), "Regular member should still have access");

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetAccessWithExternalMemberMultipleRoles() {

        final String domainName = "ext-mbr-getaccess-multi";
        final String readersRole = "readers";
        final String writersRole = "writers";
        final String regularMember = "user.joe";
        final String extMember1 = domainName + ":ext.partner-reader";
        final String extMember2 = domainName + ":ext.partner-writer";

        // ext.partner-reader is only in readers role

        Role readers = ZTSTestUtils.createRoleObject(domainName, readersRole, regularMember);
        readers.getRoleMembers().add(new RoleMember().setMemberName(extMember1));

        // ext.partner-writer is only in writers role

        Role writers = ZTSTestUtils.createRoleObject(domainName, writersRole, regularMember);
        writers.getRoleMembers().add(new RoleMember().setMemberName(extMember2));

        List<Role> roles = new ArrayList<>();
        roles.add(readers);
        roles.add(writers);

        List<Policy> policies = new ArrayList<>();

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, policies,
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // ext.partner-reader has access to readers but not writers

        Access access = zts.getAccess(ctx, domainName, readersRole, extMember1);
        assertTrue(access.getGranted(), "ext.partner-reader should have access to readers");

        access = zts.getAccess(ctx, domainName, writersRole, extMember1);
        assertFalse(access.getGranted(), "ext.partner-reader should not have access to writers");

        // ext.partner-writer has access to writers but not readers

        access = zts.getAccess(ctx, domainName, writersRole, extMember2);
        assertTrue(access.getGranted(), "ext.partner-writer should have access to writers");

        access = zts.getAccess(ctx, domainName, readersRole, extMember2);
        assertFalse(access.getGranted(), "ext.partner-writer should not have access to readers");

        // regular member has access to both roles

        access = zts.getAccess(ctx, domainName, readersRole, regularMember);
        assertTrue(access.getGranted(), "Regular member should have access to readers");

        access = zts.getAccess(ctx, domainName, writersRole, regularMember);
        assertTrue(access.getGranted(), "Regular member should have access to writers");

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetRoleAccessWithExternalMember() {

        final String domainName = "ext-mbr-roleaccess";
        final String readersRole = "readers";
        final String writersRole = "writers";
        final String regularMember = "user.joe";
        final String externalMember = domainName + ":ext.partner-user";

        Role readers = ZTSTestUtils.createRoleObject(domainName, readersRole, regularMember);
        readers.getRoleMembers().add(new RoleMember().setMemberName(externalMember));

        Role writers = ZTSTestUtils.createRoleObject(domainName, writersRole, regularMember);

        List<Role> roles = new ArrayList<>();
        roles.add(readers);
        roles.add(writers);

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, new ArrayList<>(),
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // regular member should be in both roles

        RoleAccess roleAccess = zts.getRoleAccess(ctx, domainName, regularMember);
        assertEquals(roleAccess.getRoles().size(), 2);
        assertTrue(roleAccess.getRoles().contains(readersRole));
        assertTrue(roleAccess.getRoles().contains(writersRole));

        // external member should only be in the readers role

        roleAccess = zts.getRoleAccess(ctx, domainName, externalMember);
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(readersRole));

        // unknown external member should have no roles

        roleAccess = zts.getRoleAccess(ctx, domainName, domainName + ":ext.unknown");
        assertTrue(roleAccess.getRoles().isEmpty());

        // reprocess the domain without the external member

        Role readersWithoutExt = ZTSTestUtils.createRoleObject(domainName, readersRole, regularMember);
        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(readersWithoutExt);
        updatedRoles.add(writers);

        SignedDomain updatedDomain = ZTSTestUtils.createSignedDomain(domainName, updatedRoles, new ArrayList<>(),
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(updatedDomain, false);

        // external member should no longer have any roles

        roleAccess = zts.getRoleAccess(ctx, domainName, externalMember);
        assertTrue(roleAccess.getRoles().isEmpty());

        // regular member should still have both roles

        roleAccess = zts.getRoleAccess(ctx, domainName, regularMember);
        assertEquals(roleAccess.getRoles().size(), 2);

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetRoleAccessWithExternalMemberViaGroup() {

        final String domainName = "ext-mbr-roleaccess-grp";
        final String roleName = "readers";
        final String groupName = "partners";
        final String regularMember = "user.joe";
        final String externalMember = domainName + ":ext.partner-user";
        final String groupResourceName = ResourceUtils.groupResourceName(domainName, groupName);

        Group group = ZTSTestUtils.createGroupObject(domainName, groupName, externalMember);

        List<Group> groups = new ArrayList<>();
        groups.add(group);

        Role role = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);
        role.getRoleMembers().add(new RoleMember().setMemberName(groupResourceName));

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, new ArrayList<>(),
                (List<ServiceIdentity>) null, groups, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // regular member should have the role

        RoleAccess roleAccess = zts.getRoleAccess(ctx, domainName, regularMember);
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        // external member should have the role through group membership

        roleAccess = zts.getRoleAccess(ctx, domainName, externalMember);
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        // reprocess with group having no external member

        Group groupWithoutExt = ZTSTestUtils.createGroupObject(domainName, groupName);
        List<Group> updatedGroups = new ArrayList<>();
        updatedGroups.add(groupWithoutExt);

        SignedDomain updatedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, new ArrayList<>(),
                (List<ServiceIdentity>) null, updatedGroups, privateKey);
        store.processSignedDomain(updatedDomain, false);

        // external member should no longer have any roles

        roleAccess = zts.getRoleAccess(ctx, domainName, externalMember);
        assertTrue(roleAccess.getRoles().isEmpty());

        // regular member should still have the role

        roleAccess = zts.getRoleAccess(ctx, domainName, regularMember);
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetRoleAccessWithExternalMemberMultipleRoles() {

        final String domainName = "ext-mbr-roleaccess-multi";
        final String readersRole = "readers";
        final String writersRole = "writers";
        final String adminsRole = "admins";
        final String regularMember = "user.joe";
        final String externalMember = domainName + ":ext.partner-user";

        // external member is in readers and writers but not admins

        Role readers = ZTSTestUtils.createRoleObject(domainName, readersRole, regularMember);
        readers.getRoleMembers().add(new RoleMember().setMemberName(externalMember));

        Role writers = ZTSTestUtils.createRoleObject(domainName, writersRole, regularMember);
        writers.getRoleMembers().add(new RoleMember().setMemberName(externalMember));

        Role admins = ZTSTestUtils.createRoleObject(domainName, adminsRole, regularMember);

        List<Role> roles = new ArrayList<>();
        roles.add(readers);
        roles.add(writers);
        roles.add(admins);

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, new ArrayList<>(),
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // external member should be in readers and writers but not admins

        RoleAccess roleAccess = zts.getRoleAccess(ctx, domainName, externalMember);
        assertEquals(roleAccess.getRoles().size(), 2);
        assertTrue(roleAccess.getRoles().contains(readersRole));
        assertTrue(roleAccess.getRoles().contains(writersRole));
        assertFalse(roleAccess.getRoles().contains(adminsRole));

        // regular member should be in all three roles

        roleAccess = zts.getRoleAccess(ctx, domainName, regularMember);
        assertEquals(roleAccess.getRoles().size(), 3);
        assertTrue(roleAccess.getRoles().contains(readersRole));
        assertTrue(roleAccess.getRoles().contains(writersRole));
        assertTrue(roleAccess.getRoles().contains(adminsRole));

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetRoleAccessWithExternalMemberExpired() {

        final String domainName = "ext-mbr-roleaccess-exp";
        final String roleName = "readers";
        final String regularMember = "user.joe";
        final String expiredExtMember = domainName + ":ext.expired-partner";
        final String activeExtMember = domainName + ":ext.active-partner";

        Role role = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);

        role.getRoleMembers().add(new RoleMember()
                .setMemberName(expiredExtMember)
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 10000)));

        role.getRoleMembers().add(new RoleMember()
                .setMemberName(activeExtMember)
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, new ArrayList<>(),
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // expired external member should have no roles

        RoleAccess roleAccess = zts.getRoleAccess(ctx, domainName, expiredExtMember);
        assertTrue(roleAccess.getRoles().isEmpty());

        // active external member should have the role

        roleAccess = zts.getRoleAccess(ctx, domainName, activeExtMember);
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        // regular member should have the role

        roleAccess = zts.getRoleAccess(ctx, domainName, regularMember);
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetRoleAccessWithExternalMemberDisabled() {

        final String domainName = "ext-mbr-roleaccess-dis";
        final String roleName = "readers";
        final String regularMember = "user.joe";
        final String disabledExtMember = domainName + ":ext.disabled-partner";
        final String enabledExtMember = domainName + ":ext.enabled-partner";

        Role role = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);

        role.getRoleMembers().add(new RoleMember()
                .setMemberName(disabledExtMember)
                .setSystemDisabled(1));

        role.getRoleMembers().add(new RoleMember()
                .setMemberName(enabledExtMember));

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, new ArrayList<>(),
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // disabled external member should have no roles

        RoleAccess roleAccess = zts.getRoleAccess(ctx, domainName, disabledExtMember);
        assertTrue(roleAccess.getRoles().isEmpty());

        // enabled external member should have the role

        roleAccess = zts.getRoleAccess(ctx, domainName, enabledExtMember);
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        // regular member should have the role

        roleAccess = zts.getRoleAccess(ctx, domainName, regularMember);
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetAccessWithExternalMemberExpired() {

        final String domainName = "ext-mbr-getaccess-exp";
        final String roleName = "readers";
        final String regularMember = "user.joe";
        final String expiredExtMember = domainName + ":ext.expired-partner";
        final String activeExtMember = domainName + ":ext.active-partner";

        Role role = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);

        // add an expired external member

        role.getRoleMembers().add(new RoleMember()
                .setMemberName(expiredExtMember)
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 10000)));

        // add an active external member with future expiration

        role.getRoleMembers().add(new RoleMember()
                .setMemberName(activeExtMember)
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        List<Policy> policies = new ArrayList<>();

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, policies,
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // expired external member should not have access

        Access access = zts.getAccess(ctx, domainName, roleName, expiredExtMember);
        assertFalse(access.getGranted(), "Expired external member should not have access");

        // active external member should have access

        access = zts.getAccess(ctx, domainName, roleName, activeExtMember);
        assertTrue(access.getGranted(), "Active external member should have access");

        // regular member should still have access

        access = zts.getAccess(ctx, domainName, roleName, regularMember);
        assertTrue(access.getGranted(), "Regular member should have access");

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetAccessWithExternalMemberDisabled() {

        final String domainName = "ext-mbr-getaccess-dis";
        final String roleName = "readers";
        final String regularMember = "user.joe";
        final String disabledExtMember = domainName + ":ext.disabled-partner";
        final String enabledExtMember = domainName + ":ext.enabled-partner";

        Role role = ZTSTestUtils.createRoleObject(domainName, roleName, regularMember);

        // add a disabled external member

        role.getRoleMembers().add(new RoleMember()
                .setMemberName(disabledExtMember)
                .setSystemDisabled(1));

        // add an enabled external member

        role.getRoleMembers().add(new RoleMember()
                .setMemberName(enabledExtMember));

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        List<Policy> policies = new ArrayList<>();

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName, roles, policies,
                (List<ServiceIdentity>) null, (List<Group>) null, privateKey);
        store.processSignedDomain(signedDomain, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);

        // disabled external member should not have access

        Access access = zts.getAccess(ctx, domainName, roleName, disabledExtMember);
        assertFalse(access.getGranted(), "Disabled external member should not have access");

        // enabled external member should have access

        access = zts.getAccess(ctx, domainName, roleName, enabledExtMember);
        assertTrue(access.getGranted(), "Enabled external member should have access");

        // regular member should still have access

        access = zts.getAccess(ctx, domainName, roleName, regularMember);
        assertTrue(access.getGranted(), "Regular member should have access");

        store.getCacheStore().invalidate(domainName);
    }
}
