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

import com.yahoo.athenz.auth.Principal;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.*;
import java.util.stream.Collectors;

import static org.testng.Assert.*;

@SuppressWarnings("RedundantThrows")
public class ZMSClientMockTest {

    @Mock ZMSRDLGeneratedClient mockZMS;

    ZMSClient    zclt;
    String       zmsUrl   = "https://localhost";
    List<String> userList;
    String       auditRef = "zmsjcltmktest";

    static final Struct TABLE_PROVIDER_ROLE_ACTIONS = new Struct()
            .with("admin", "*").with("writer", "WRITE").with("reader", "READ");

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Mockito.doReturn(new DomainList()).when(mockZMS).getDomainList(ArgumentMatchers.isA(Integer.class),
                ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(Integer.class),
                ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(Integer.class), ArgumentMatchers.isA(String.class),
                ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(String.class),
                ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(String.class),
                ArgumentMatchers.isA(String.class), ArgumentMatchers.isA(String.class));
        userList = new ArrayList<>();
        userList.add("user.johnny");
        zclt = new ZMSClient(zmsUrl);
        zclt.client = mockZMS;
    }

    @Test
    public void testDomain() throws Exception {

        String domName = "testdom";
        Mockito.doReturn(new Domain()).when(mockZMS).getDomain(domName);
        Mockito.doReturn(new DomainList()).when(mockZMS).getDomainList(null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null);

        DomainList domList = zclt.getDomainList();
        assertNotNull(domList);

        Domain dom = zclt.getDomain(domName);
        assertNotNull(dom);

        try {
            TopLevelDomain tld = new TopLevelDomain().setName(domName).setOrg("testOrg")
                    .setDescription("test domain").setAdminUsers(userList);
            zclt.postTopLevelDomain(auditRef, tld);

            DomainMeta meta = new DomainMeta();
            zclt.putDomainMeta(domName, auditRef, meta);

            zclt.deleteTopLevelDomain(domName, auditRef);
        } catch (Exception exc) {
            fail();
        }
    }

    @Test
    public void testDomainListModifiedSince() throws Exception {

        DomainList domList = new DomainList();
        List<String> domains = new ArrayList<>();
        domains.add("dom1");
        domList.setNames(domains);

        Date now = new Date();
        DateFormat df = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss zzz");
        String modifiedSince = df.format(now);
        Mockito.doReturn(domList).when(mockZMS).getDomainList(null, null, null,
                null, null, null, null, null, null,null, null, null, null, null, modifiedSince);

        DomainList domainList = zclt.getDomainList(null, null, null,
                null, null, null, now);
        assertNotNull(domainList);
        assertTrue(domainList.getNames().contains("dom1"));
    }

    @Test
    public void testSubDomain() throws Exception {

        String parentName = "parentdom";
        String subDomName = "childdom";

        try {
            SubDomain subDom = new SubDomain();
            zclt.postSubDomain(parentName, auditRef, subDom);
            zclt.deleteSubDomain(parentName, subDomName, auditRef);

        } catch (Exception exc) {
            fail();
        }
    }

    @Test
    public void testUserDomain() throws Exception {

        String userDomName = "userid";

        try {
            UserDomain userDom = new UserDomain();
            userDom.setName(userDomName);

            zclt.postUserDomain(userDomName, auditRef, userDom);
            zclt.deleteUserDomain(userDomName, auditRef);

        } catch (Exception exc) {
            fail();
        }
    }

    @Test
    public void testGetUserToken() throws Exception {

        String uname = "johnny";
        Mockito.doReturn(new UserToken()).when(mockZMS).getUserToken(uname, null, null);
        Mockito.doReturn(new UserToken()).when(mockZMS).getUserToken(uname, "coretech.storage", null);

        UserToken utok = zclt.getUserToken(uname);
        assertNotNull(utok);

        utok = zclt.getUserToken(uname, "coretech.storage");
        assertNotNull(utok);

        utok = zclt.getUserToken(uname, "sports.hockey");
        assertNull(utok);
    }

    @Test
    public void testPolicy() throws Exception {

        String domName = "johnnies-place";
        String polName = "chefs";
        Mockito.doReturn(new Policy()).when(mockZMS).getPolicy(domName, polName);
        Mockito.doReturn(new PolicyList()).when(mockZMS).getPolicyList(domName, null, null);

        ZMSClient zmsclt2 = new ZMSClient(zmsUrl);
        zmsclt2.client = mockZMS;

        PolicyList polList = zmsclt2.getPolicyList(domName);
        assertNotNull(polList);

        Policy pol = zmsclt2.getPolicy(domName, polName);
        assertNotNull(pol);

        try {
            zmsclt2.putPolicy(domName, polName, auditRef, pol);
            zmsclt2.deletePolicy(domName, polName, auditRef);
        } catch (Exception exc) {
            fail();
        }
        zmsclt2.close();
    }

    @Test
    public void testPolicyVersion() throws Exception {

        String domName = "johnnies-place";
        String polName = "chefs";
        String version = "new-version";
        Mockito.doReturn(new Policy()).when(mockZMS).getPolicyVersion(domName, polName, version);
        Mockito.doReturn(new PolicyList()).when(mockZMS).getPolicyVersionList(domName, polName);

        ZMSClient zmsclt2 = new ZMSClient(zmsUrl);
        zmsclt2.client = mockZMS;

        PolicyList polList = zmsclt2.getPolicyVersionList(domName, polName);
        assertNotNull(polList);

        Policy pol = zmsclt2.getPolicyVersion(domName, polName, version);
        assertNotNull(pol);

        try {
            zmsclt2.putPolicyVersion(domName, polName, version, auditRef);
            zmsclt2.deletePolicyVersion(domName, polName, version, auditRef);
        } catch (Exception exc) {
            fail();
        }
        try {
            zmsclt2.putPolicyVersion(domName, polName, version, "from-version", auditRef);
            zmsclt2.deletePolicyVersion(domName, polName, version, auditRef);
        } catch (Exception exc) {
            fail();
        }
        zmsclt2.close();
    }

    @Test
    public void testRole() throws Exception {

        String domName  = "johnnies-place";
        String roleName = "manager";
        Mockito.doReturn(new Role()).when(mockZMS).getRole(domName, roleName, false, false, false);
        Mockito.doReturn(new RoleList()).when(mockZMS).getRoleList(domName, null, null);

        RoleList roleList = zclt.getRoleList(domName);
        assertNotNull(roleList);

        Role role = zclt.getRole(domName, roleName);
        assertNotNull(role);

        try {
            zclt.putRole(domName, roleName, auditRef, role);
            zclt.deletePolicy(domName, roleName, auditRef);
        } catch (Exception exc) {
            fail();
        }
    }

    @Test
    public void testRoleChangeLog() throws Exception {

        String domName  = "johnnies-place";
        String roleName = "manager";
        Role retRole = new Role();
        retRole.setName(domName + ":role." + roleName);

        List<RoleAuditLog> auditLogList = new ArrayList<>();
        RoleAuditLog logEntry = new RoleAuditLog();
        logEntry.setAction("ADD").setAdmin("user.admin").setMember("user.user1")
            .setAuditRef("").setCreated(Timestamp.fromCurrentTime());
        auditLogList.add(logEntry);

        logEntry = new RoleAuditLog();
        logEntry.setAction("DELETE").setAdmin("user.admin").setMember("user.user2")
            .setAuditRef("audit-ref").setCreated(Timestamp.fromCurrentTime());
        auditLogList.add(logEntry);

        retRole.setAuditLog(auditLogList);
        Mockito.doReturn(retRole).when(mockZMS).getRole(domName, roleName, true, false, false);

        Role role = zclt.getRole(domName, roleName, true);
        assertNotNull(role);
        List<RoleAuditLog> logList = role.getAuditLog();
        assertNotNull(logList);
        assertEquals(logList.size(), 2);
    }

    @Test
    public void testRoleExpand() throws Exception {

        String domName  = "role-expand";
        String roleName = "manager";

        Role retRoleExpand = new Role();
        retRoleExpand.setName(domName + ":role." + roleName);
        retRoleExpand.setTrust("trusted-domain");
        List<String> members = new ArrayList<>();
        members.add("user.user1");
        members.add("coretech.service");
        retRoleExpand.setMembers(members);

        Role retRoleNoExpand = new Role();
        retRoleNoExpand.setName(domName + ":role." + roleName);
        retRoleNoExpand.setTrust("trusted-domain");

        Mockito.doReturn(retRoleExpand).when(mockZMS).getRole(domName, roleName, false, true, false);
        Mockito.doReturn(retRoleNoExpand).when(mockZMS).getRole(domName, roleName, false, false, false);

        // first request with expand option set

        Role role = zclt.getRole(domName, roleName, false, true);
        assertNotNull(role);
        assertEquals(role.getTrust(), "trusted-domain");
        assertNotNull(role.getMembers());
        assertEquals(role.getMembers().size(), 2);
        assertTrue(role.getMembers().contains("user.user1"));
        assertTrue(role.getMembers().contains("coretech.service"));

        // next without expand option

        role = zclt.getRole(domName, roleName, false, false);
        assertNotNull(role);
        assertEquals(role.getTrust(), "trusted-domain");
        assertNull(role.getMembers());
    }

    @Test
    public void testGetRoles() throws Exception {

        String domName  = "roles-members";

        Role trustRole = new Role();
        trustRole.setName(domName + ":role.trust-role");
        trustRole.setTrust("trusted-domain");

        Role groupRoleWithMembers = new Role();
        groupRoleWithMembers.setName(domName + ":role.group-role");
        List<String> members = new ArrayList<>();
        members.add("user.user1");
        members.add("coretech.service");
        groupRoleWithMembers.setMembers(members);

        Role groupRoleWithoutMembers = new Role();
        groupRoleWithoutMembers.setName(domName + ":role.group-role");

        List<Role> retListWithMembers = new ArrayList<>();
        retListWithMembers.add(groupRoleWithMembers);
        retListWithMembers.add(trustRole);
        Roles retRolesWithMembers = new Roles().setList(retListWithMembers);

        List<Role> retListWithoutMembers = new ArrayList<>();
        retListWithoutMembers.add(groupRoleWithoutMembers);
        retListWithoutMembers.add(trustRole);
        Roles retRolesWithoutMembers = new Roles().setList(retListWithoutMembers);

        Mockito.doReturn(retRolesWithMembers).when(mockZMS).getRoles(domName, true, null, null);
        Mockito.doReturn(retRolesWithoutMembers).when(mockZMS).getRoles(domName, false, null, null);

        // first request with members option set

        Roles roles = zclt.getRoles(domName, true, null, null);
        assertNotNull(roles);
        assertNotNull(roles.getList());

        boolean groupRoleCheck = false;
        boolean trustRoleCheck = false;
        for (Role role : roles.getList()) {
            switch (role.getName()) {
                case "roles-members:role.trust-role":
                    assertEquals(role.getTrust(), "trusted-domain");
                    assertNull(role.getMembers());
                    trustRoleCheck = true;
                    break;
                case "roles-members:role.group-role":
                    assertNull(role.getTrust());
                    assertNotNull(role.getMembers());
                    assertEquals(role.getMembers().size(), 2);
                    assertTrue(role.getMembers().contains("user.user1"));
                    assertTrue(role.getMembers().contains("coretech.service"));
                    groupRoleCheck = true;
                    break;
            }
        }
        assertTrue(groupRoleCheck);
        assertTrue(trustRoleCheck);

        // next without members option

        roles = zclt.getRoles(domName, false, null, null);
        assertNotNull(roles);
        assertNotNull(roles.getList());

        groupRoleCheck = false;
        trustRoleCheck = false;
        for (Role role : roles.getList()) {
            switch (role.getName()) {
                case "roles-members:role.trust-role":
                    assertEquals(role.getTrust(), "trusted-domain");
                    assertNull(role.getMembers());
                    trustRoleCheck = true;
                    break;
                case "roles-members:role.group-role":
                    assertNull(role.getTrust());
                    assertNull(role.getMembers());
                    groupRoleCheck = true;
                    break;
            }
        }
        assertTrue(groupRoleCheck);
        assertTrue(trustRoleCheck);
    }

    @Test
    public void testGetGroups() throws Exception {

        String domName  = "group-members";

        Group groupRoleWithMembers = new Group();
        groupRoleWithMembers.setName(domName + ":group.group-role");
        List<GroupMember> members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1"));
        members.add(new GroupMember().setMemberName("coretech.service"));
        groupRoleWithMembers.setGroupMembers(members);

        Group groupRoleWithoutMembers = new Group();
        groupRoleWithoutMembers.setName(domName + ":group.group-role");

        List<Group> retListWithMembers = new ArrayList<>();
        retListWithMembers.add(groupRoleWithMembers);
        Groups retGroupsWithMembers = new Groups().setList(retListWithMembers);

        List<Group> retListWithoutMembers = new ArrayList<>();
        retListWithoutMembers.add(groupRoleWithoutMembers);
        Groups retGroupsWithoutMembers = new Groups().setList(retListWithoutMembers);

        Mockito.doReturn(retGroupsWithMembers).when(mockZMS).getGroups(domName, true, null, null);
        Mockito.doReturn(retGroupsWithoutMembers).when(mockZMS).getGroups(domName, false, null, null);

        // first request with members option set

        Groups groups = zclt.getGroups(domName, true, null, null);
        assertNotNull(groups);
        assertNotNull(groups.getList());

        boolean groupCheck = false;
        for (Group group : groups.getList()) {
            if (group.getName().equals("group-members:group.group-role")) {
                assertNotNull(group.getGroupMembers());
                assertEquals(group.getGroupMembers().size(), 2);
                assertTrue(group.getGroupMembers().stream().map(GroupMember::getMemberName).collect(Collectors.toList()).contains("user.user1"));
                assertTrue(group.getGroupMembers().stream().map(GroupMember::getMemberName).collect(Collectors.toList()).contains("coretech.service"));
                groupCheck = true;
            }
        }
        assertTrue(groupCheck);

        // next without members option

        groups = zclt.getGroups(domName, false, null, null);
        assertNotNull(groups);
        assertNotNull(groups.getList());

        groupCheck = false;
        for (Group group : groups.getList()) {
            if (group.getName().equals("group-members:group.group-role")) {
                assertNull(group.getGroupMembers());
                groupCheck = true;
            }
        }
        assertTrue(groupCheck);
    }

    @Test
    public void testPutTenantResourceGroupRoles() throws Exception {

        String tenantDomain  = "tenant";
        String providerDomain = "coretech";
        String providerService = "storage";
        String resourceGroup = "hockey";
        TenantResourceGroupRoles tenantRoles = new TenantResourceGroupRoles();
        tenantRoles.setTenant(tenantDomain).setDomain(providerDomain).setService(providerService)
            .setResourceGroup(resourceGroup);

        List<TenantRoleAction> roleActions = new ArrayList<>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        tenantRoles.setRoles(roleActions);
        Mockito.doReturn(null)
            .when(mockZMS).putTenantResourceGroupRoles(providerDomain, providerService, tenantDomain,
                    resourceGroup, auditRef, tenantRoles);

        try {
            zclt.putTenantResourceGroupRoles(providerDomain, providerService,
                    tenantDomain, resourceGroup, auditRef, tenantRoles);
        } catch (Exception exc) {
            fail();
        }
    }

    @Test
    public void testDeleteTenantResourceGroupRoles() throws Exception {

        String tenantDomain  = "tenant";
        String providerDomain = "coretech";
        String providerService = "storage";
        String resourceGroup = "hockey";
        TenantResourceGroupRoles tenantRoles = new TenantResourceGroupRoles();
        tenantRoles.setTenant(tenantDomain).setDomain(providerDomain).setService(providerService)
            .setResourceGroup(resourceGroup);

        Mockito.doReturn(null)
            .when(mockZMS).deleteTenantResourceGroupRoles(providerDomain, providerService, tenantDomain,
                    resourceGroup, auditRef);

        try {
            zclt.deleteTenantResourceGroupRoles(providerDomain, providerService, tenantDomain,
                    resourceGroup, auditRef);
        } catch (Exception exc) {
            fail();
        }
    }

    @Test
    public void testGetTenantResourceGroupRoles() throws Exception {

        String tenantDomain  = "tenant";
        String providerDomain = "coretech";
        String providerService = "storage";
        String resourceGroup = "hockey";
        TenantResourceGroupRoles tenantRoles = new TenantResourceGroupRoles();
        tenantRoles.setTenant(tenantDomain).setDomain(providerDomain).setService(providerService)
            .setResourceGroup(resourceGroup);

        List<TenantRoleAction> roleActions = new ArrayList<>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        tenantRoles.setRoles(roleActions);
        Mockito.doReturn(tenantRoles)
            .when(mockZMS).getTenantResourceGroupRoles(providerDomain,
                    providerService, tenantDomain, resourceGroup);

        TenantResourceGroupRoles retRoles = null;
        try {
            retRoles = zclt.getTenantResourceGroupRoles(providerDomain,
                    providerService, tenantDomain, resourceGroup);
        } catch (Exception exc) {
            fail();
        }

        assertNotNull(retRoles);
        assertEquals(tenantDomain, retRoles.getTenant());
        assertEquals(providerDomain, retRoles.getDomain());
        assertEquals(providerService, retRoles.getService());
        assertEquals(resourceGroup, retRoles.getResourceGroup());

        // try to get unknown resource group that would return null

        try {
            retRoles = zclt.getTenantResourceGroupRoles(providerDomain,
                    providerService, tenantDomain, "baseball");
        } catch (Exception exc) {
            fail();
        }

        assertNull(retRoles);
    }

    @Test
    public void testPutProviderResourceGroupRoles() throws Exception {

        String tenantDomain  = "tenant";
        String providerDomain = "coretech";
        String providerService = "storage";
        String resourceGroup = "hockey";
        ProviderResourceGroupRoles provRoles = new ProviderResourceGroupRoles();
        provRoles.setTenant(tenantDomain).setDomain(providerDomain)
            .setService(providerService).setResourceGroup(resourceGroup);

        List<TenantRoleAction> roleActions = new ArrayList<>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        provRoles.setRoles(roleActions);
        Mockito.doReturn(null)
            .when(mockZMS).putProviderResourceGroupRoles(tenantDomain, providerDomain, providerService,
                    resourceGroup, auditRef, provRoles);

        try {
            zclt.putProviderResourceGroupRoles(tenantDomain, providerDomain, providerService,
                    resourceGroup, auditRef, provRoles);
        } catch (Exception exc) {
            fail();
        }
    }

    @Test
    public void testDeleteProviderResourceGroupRoles() throws Exception {

        String tenantDomain  = "tenant";
        String providerDomain = "coretech";
        String providerService = "storage";
        String resourceGroup = "hockey";
        ProviderResourceGroupRoles provRoles = new ProviderResourceGroupRoles();
        provRoles.setTenant(tenantDomain).setDomain(providerDomain)
            .setService(providerService).setResourceGroup(resourceGroup);

        Mockito.doReturn(null)
            .when(mockZMS).deleteProviderResourceGroupRoles(tenantDomain, providerDomain, providerService,
                    resourceGroup, auditRef);

        try {
            zclt.deleteProviderResourceGroupRoles(tenantDomain, providerDomain, providerService,
                    resourceGroup, auditRef);
        } catch (Exception exc) {
            fail();
        }
    }

    @Test
    public void testGetProviderResourceGroupRoles() throws Exception {

        String tenantDomain  = "tenant";
        String providerDomain = "coretech";
        String providerService = "storage";
        String resourceGroup = "hockey";
        ProviderResourceGroupRoles provRoles = new ProviderResourceGroupRoles();
        provRoles.setTenant(tenantDomain).setDomain(providerDomain)
            .setService(providerService).setResourceGroup(resourceGroup);

        List<TenantRoleAction> roleActions = new ArrayList<>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        provRoles.setRoles(roleActions);
        Mockito.doReturn(provRoles)
            .when(mockZMS).getProviderResourceGroupRoles(tenantDomain, providerDomain, providerService, resourceGroup);

        ProviderResourceGroupRoles retRoles = null;
        try {
            retRoles = zclt.getProviderResourceGroupRoles(tenantDomain, providerDomain, providerService, resourceGroup);
        } catch (Exception exc) {
            fail();
        }

        assertNotNull(retRoles);
        assertEquals(tenantDomain, retRoles.getTenant());
        assertEquals(providerDomain, retRoles.getDomain());
        assertEquals(providerService, retRoles.getService());
        assertEquals(resourceGroup, retRoles.getResourceGroup());

        // try to get unknown resource group that would return null

        try {
            retRoles = zclt.getProviderResourceGroupRoles(tenantDomain, providerDomain, providerService, "baseball");
        } catch (Exception exc) {
            fail();
        }

        assertNull(retRoles);
    }

    @Test
    public void testGetTemplate() throws Exception {

        Template template = new Template();
        Role role = new Role().setName("role1").setTrust("trust-domain");
        List<Role> roleList = new ArrayList<>();
        roleList.add(role);
        template.setRoles(roleList);
        Policy policy = new Policy().setName("policy1");
        List<Policy> policyList = new ArrayList<>();
        policyList.add(policy);
        template.setPolicies(policyList);

        Mockito.doReturn(template).when(mockZMS).getTemplate("vipng");

        Template solTemplate = zclt.getTemplate("vipng");
        assertNotNull(solTemplate);
        List<Role> solRoles = solTemplate.getRoles();
        assertNotNull(solRoles);
        assertEquals(1, solRoles.size());
        assertEquals("role1", solRoles.get(0).getName());
        assertEquals("trust-domain", solRoles.get(0).getTrust());

        List<Policy> solPolicies = solTemplate.getPolicies();
        assertNotNull(solPolicies);
        assertEquals(1, solPolicies.size());
        assertEquals("policy1", solPolicies.get(0).getName());
    }

    @Test
    public void testGetServerTemplateList() throws Exception {
        ServerTemplateList templateList = new ServerTemplateList();
        List<String> names = new ArrayList<>();
        names.add("vipng");
        names.add("mh2");
        templateList.setTemplateNames(names);

        Mockito.doReturn(templateList).when(mockZMS).getServerTemplateList();

        ServerTemplateList solTemplateList = zclt.getServerTemplateList();
        assertNotNull(solTemplateList);
        assertEquals(2, solTemplateList.getTemplateNames().size());
        assertTrue(solTemplateList.getTemplateNames().contains("mh2"));
        assertTrue(solTemplateList.getTemplateNames().contains("vipng"));
    }

    @Test
    public void testGetDomainTemplateList() throws Exception {
        DomainTemplateList templateList = new DomainTemplateList();
        List<String> names = new ArrayList<>();
        names.add("vipng");
        names.add("mh2");
        templateList.setTemplateNames(names);

        Mockito.doReturn(templateList).when(mockZMS).getDomainTemplateList("iaas.athenz");

        DomainTemplateList domTemplateList = zclt.getDomainTemplateList("iaas.athenz");
        assertNotNull(domTemplateList);
        assertEquals(2, domTemplateList.getTemplateNames().size());
        assertTrue(domTemplateList.getTemplateNames().contains("mh2"));
        assertTrue(domTemplateList.getTemplateNames().contains("vipng"));
    }

    @Test
    public void testGetPrincipal() throws URISyntaxException, IOException {

        ServicePrincipal svcPrincipal = new ServicePrincipal().setDomain("coretech").setService("storage");
        Mockito.doReturn(svcPrincipal).when(mockZMS).getServicePrincipal();

        Principal principal = zclt.getPrincipal("v=U1;d=coretech;n=storage;s=signature");
        assertNotNull(principal);
        assertEquals("storage", principal.getName());
        assertEquals("coretech", principal.getDomain());
    }

    @Test
    public void testDomainListByAccount() throws Exception {

        DomainList domList = new DomainList();
        List<String> domains = new ArrayList<>();
        domains.add("dom1");
        domList.setNames(domains);

        DomainList domEmptyList = new DomainList();

        Mockito.doReturn(domList).when(mockZMS).getDomainList(null, null, null, null,
                "1234", null, null, null, null, null, null, null, null, null, null);
        Mockito.doReturn(domEmptyList).when(mockZMS).getDomainList(null, null, null, null,
                "1235", null, null, null, null, null, null, null, null, null, null);

        DomainList domainList = zclt.getDomainList(null, null, null, null, "1234", null, null);
        assertNotNull(domainList);
        assertTrue(domainList.getNames().contains("dom1"));

        domainList = zclt.getDomainList(null, null, null, null, "1235", null, null);
        assertNotNull(domainList);
        assertNull(domainList.getNames());
    }

    @Test
    public void testDomainListByProductId() throws Exception {

        DomainList domList = new DomainList();
        List<String> domains = new ArrayList<>();
        domains.add("dom1");
        domList.setNames(domains);

        DomainList domEmptyList = new DomainList();

        Mockito.doReturn(domList).when(mockZMS).getDomainList(null, null, null, null, null,
                101, null, null, null, null, null, null, null, null, null);
        Mockito.doReturn(domEmptyList).when(mockZMS).getDomainList(null, null, null, null, null,
                102, null, null, null, null, null, null, null, null, null);

        DomainList domainList = zclt.getDomainList(null, null, null, null, null, 101, null);
        assertNotNull(domainList);
        assertTrue(domainList.getNames().contains("dom1"));

        domainList = zclt.getDomainList(null, null, null, null, null, 102, null);
        assertNotNull(domainList);
        assertNull(domainList.getNames());
    }

    @Test
    public void testDomainListByRole() throws Exception {

        DomainList domList = new DomainList();
        List<String> domains = new ArrayList<>();
        domains.add("dom1");
        domList.setNames(domains);

        DomainList domEmptyList = new DomainList();

        Mockito.doReturn(domList).when(mockZMS).getDomainList(null, null, null, null, null,
                null, "user.user1", "admin", null, null, null, null, null, null, null);
        Mockito.doReturn(domEmptyList).when(mockZMS).getDomainList(null, null, null, null, null,
                null, "user.user2", "admin", null, null, null, null, null, null, null);

        DomainList domainList = zclt.getDomainList("user.user1", "admin");
        assertNotNull(domainList);
        assertTrue(domainList.getNames().contains("dom1"));

        domainList = zclt.getDomainList("user.user2", "admin");
        assertNotNull(domainList);
        assertNull(domainList.getNames());
    }

    @Test
    public void testEntityList() throws URISyntaxException, IOException {

        String domName  = "johnnies-place";
        List<String> names = new ArrayList<>();
        names.add("entity1");
        names.add("entity2");
        EntityList entList = new EntityList().setNames(names);

        Mockito.doReturn(entList).when(mockZMS).getEntityList(domName);

        EntityList list = zclt.getEntityList(domName);
        assertNotNull(list);
        List<String> ents = list.getNames();
        assertEquals(ents.size(), 2);
        assertTrue(ents.contains("entity1"));
        assertTrue(ents.contains("entity2"));
    }

    @Test
    public void testGetResourceAccessList() throws Exception {

        ResourceAccessList rsrcEmptyList = new ResourceAccessList();

        ResourceAccessList rsrcList = new ResourceAccessList();

        ResourceAccess rsrcAccess = new ResourceAccess();
        rsrcAccess.setPrincipal("user.user");
        Assertion assertion = new Assertion().setAction("update").setRole("athenz:role.role1").setResource("athenz:resource1");
        List<Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);
        rsrcAccess.setAssertions(assertions);

        List<ResourceAccess> resources = new ArrayList<>();
        resources.add(rsrcAccess);

        rsrcList.setResources(resources);

        Mockito.doReturn(rsrcList).when(mockZMS).getResourceAccessList("user.user", "update");
        Mockito.doReturn(rsrcEmptyList).when(mockZMS).getResourceAccessList("user.user1", "create");

        ResourceAccessList rsrcAccessList = zclt.getResourceAccessList("user.user", "update");
        assertNotNull(rsrcAccessList);
        assertEquals(rsrcAccessList.getResources().size(), 1);

        rsrcAccess = rsrcAccessList.getResources().get(0);
        assertEquals(rsrcAccess.getPrincipal(), "user.user");

        rsrcAccessList = zclt.getResourceAccessList("user.user1", "create");
        assertNotNull(rsrcAccessList);
        assertNull(rsrcAccessList.getResources());
    }

    @Test
    public void testGetPolicies() throws Exception {

        final String domName  = "get-policies";

        Policy policyWithAssertions = new Policy();
        policyWithAssertions.setName(domName + ":policy.assert-policy");
        policyWithAssertions.setModified(Timestamp.fromCurrentTime());
        List<Assertion> assertions = new ArrayList<>();
        Assertion assertion = new Assertion()
                .setAction("update")
                .setEffect(AssertionEffect.ALLOW)
                .setId((long) 101)
                .setResource(domName + ":*")
                .setRole("admin");
        assertions.add(assertion);
        policyWithAssertions.setAssertions(assertions);

        Policy policyWithOutAssertions = new Policy();
        policyWithOutAssertions.setName(domName + ":policy.no-assert-policy");
        policyWithOutAssertions.setModified(Timestamp.fromCurrentTime());

        List<Policy> retListWithAssertions = new ArrayList<>();
        retListWithAssertions.add(policyWithAssertions);
        Policies retPoliciesWithAssertions = new Policies().setList(retListWithAssertions);

        List<Policy> retListWithOutAssertions = new ArrayList<>();
        retListWithOutAssertions.add(policyWithOutAssertions);
        Policies retPoliciesWithOutAssertions = new Policies().setList(retListWithOutAssertions);

        Mockito.doReturn(retPoliciesWithAssertions).when(mockZMS).getPolicies(domName, true, false, null, null);
        Mockito.doReturn(retPoliciesWithOutAssertions).when(mockZMS).getPolicies(domName, false, false, null, null);

        // first request with assertions option set

        Policies policies = zclt.getPolicies(domName, true);
        assertNotNull(policies);
        assertNotNull(policies.getList());

        boolean policyCheck = false;
        for (Policy policy : policies.getList()) {
            if ("get-policies:policy.assert-policy".equals(policy.getName())) {
                assertNotNull(policy.getModified());
                List<Assertion> testAssertions = policy.getAssertions();
                assertNotNull(testAssertions);
                assertEquals(testAssertions.size(), 1);
                assertEquals(testAssertions.get(0).getAction(), "update");
                policyCheck = true;
            }
        }
        assertTrue(policyCheck);

        // next without assertions option

        policies = zclt.getPolicies(domName, false);
        assertNotNull(policies);
        assertNotNull(policies.getList());

        policyCheck = false;
        for (Policy policy : policies.getList()) {
            if ("get-policies:policy.no-assert-policy".equals(policy.getName())) {
                assertNotNull(policy.getModified());
                assertNull(policy.getAssertions());
                policyCheck = true;
            }
        }
        assertTrue(policyCheck);
    }

    @Test
    public void testGetPolicyVersions() throws Exception {

        final String domName  = "get-policy-versions";
        String policyName = domName + ":policy.test-policy";

        Policy policyWithAssertions = new Policy();
        policyWithAssertions.setName(policyName);
        policyWithAssertions.setVersion("0");
        policyWithAssertions.setActive(true);
        policyWithAssertions.setModified(Timestamp.fromCurrentTime());
        List<Assertion> assertions = new ArrayList<>();
        Assertion assertion = new Assertion()
                .setAction("update")
                .setEffect(AssertionEffect.ALLOW)
                .setId((long) 101)
                .setResource(domName + ":*")
                .setRole("admin");
        assertions.add(assertion);
        policyWithAssertions.setAssertions(assertions);

        Policy policyWithOutAssertions = new Policy();
        policyWithOutAssertions.setName(policyName);
        policyWithOutAssertions.setVersion("no-assertions");
        policyWithAssertions.setActive(false);
        policyWithOutAssertions.setModified(Timestamp.fromCurrentTime());

        List<Policy> retList = new ArrayList<>();
        retList.add(policyWithAssertions);
        retList.add(policyWithOutAssertions);
        Policies retPoliciesWithAssertions = new Policies().setList(retList);

        Mockito.doReturn(retPoliciesWithAssertions).when(mockZMS).getPolicies(domName, true, true, null, null);

        Policies policies = zclt.getPolicies(domName, true, true);
        assertNotNull(policies);
        assertNotNull(policies.getList());

        boolean policyCheck1 = false;
        boolean policyCheck2 = false;
        for (Policy policy : policies.getList()) {
            if (policy.getName().equals(policyName) && policy.getVersion().equals("0")) {
                assertNotNull(policy.getModified());
                List<Assertion> testAssertions = policy.getAssertions();
                assertNotNull(testAssertions);
                assertEquals(testAssertions.size(), 1);
                assertEquals(testAssertions.get(0).getAction(), "update");
                policyCheck1 = true;
            }
            if (policy.getName().equals(policyName) && policy.getVersion().equals("no-assertions")) {
                assertNotNull(policy.getModified());
                List<Assertion> testAssertions = policy.getAssertions();
                assertNull(testAssertions);
                policyCheck2 = true;
            }
        }
        assertTrue(policyCheck1);
        assertTrue(policyCheck2);
    }

    @Test
    public void testGetServices() throws Exception {

        final String domName  = "get-services";

        ServiceIdentity serviceWithKeysHosts = new ServiceIdentity();
        serviceWithKeysHosts.setName(domName + ".service-key-host")
            .setGroup("users")
            .setExecutable("/usr/bin/jetty")
            .setModified(Timestamp.fromCurrentTime())
            .setUser("root");
        List<PublicKeyEntry> publicKeys = new ArrayList<>();
        PublicKeyEntry publicKey = new PublicKeyEntry().setId("0").setKey("key");
        publicKeys.add(publicKey);
        serviceWithKeysHosts.setPublicKeys(publicKeys);

        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        serviceWithKeysHosts.setHosts(hosts);

        ServiceIdentity serviceWithKeysOnly = new ServiceIdentity();
        serviceWithKeysOnly.setName(domName + ".service-key-only")
            .setGroup("users")
            .setExecutable("/usr/bin/jetty")
            .setModified(Timestamp.fromCurrentTime())
            .setUser("root")
            .setPublicKeys(publicKeys);

        ServiceIdentity serviceWithHostsOnly = new ServiceIdentity();
        serviceWithHostsOnly.setName(domName + ".service-host-only")
            .setGroup("users")
            .setExecutable("/usr/bin/jetty")
            .setModified(Timestamp.fromCurrentTime())
            .setUser("root")
            .setHosts(hosts);

        TagValueList tagValues1 = new TagValueList();
        TagValueList tagValues2 = new TagValueList();
        tagValues1.setList(Arrays.asList("value1", "value2", "value3"));
        tagValues2.setList(Arrays.asList("value4", "value5"));
        Map<String, TagValueList> tags = new HashMap<>();
        tags.putIfAbsent("key1", tagValues1);
        tags.putIfAbsent("key2", tagValues2);

        ServiceIdentity serviceWithTagsOnly = new ServiceIdentity();
        serviceWithTagsOnly.setName(domName + ".service-tags-only")
                .setGroup("users")
                .setExecutable("/usr/bin/jetty")
                .setModified(Timestamp.fromCurrentTime())
                .setUser("root")
                .setTags(tags);



        List<ServiceIdentity> retListWithKeysHosts = new ArrayList<>();
        retListWithKeysHosts.add(serviceWithKeysHosts);
        ServiceIdentities retServicesWithKeysHosts = new ServiceIdentities().setList(retListWithKeysHosts);

        List<ServiceIdentity> retListWithKeysOnly = new ArrayList<>();
        retListWithKeysOnly.add(serviceWithKeysOnly);
        ServiceIdentities retServicesWithKeysOnly = new ServiceIdentities().setList(retListWithKeysOnly);

        List<ServiceIdentity> retListWithHostsOnly = new ArrayList<>();
        retListWithHostsOnly.add(serviceWithHostsOnly);
        ServiceIdentities retServicesWithHostsOnly = new ServiceIdentities().setList(retListWithHostsOnly);

        List<ServiceIdentity> retListWithTagsOnly = new ArrayList<>();
        retListWithTagsOnly.add(serviceWithTagsOnly);
        ServiceIdentities retServicesWithTagsOnly = new ServiceIdentities().setList(retListWithTagsOnly);

        Mockito.doReturn(retServicesWithKeysHosts).when(mockZMS).getServiceIdentities(domName, true, true, null, null);
        Mockito.doReturn(retServicesWithKeysOnly).when(mockZMS).getServiceIdentities(domName, true, false, null ,null);
        Mockito.doReturn(retServicesWithHostsOnly).when(mockZMS).getServiceIdentities(domName, false, true, null, null);
        Mockito.doReturn(retServicesWithTagsOnly).when(mockZMS).getServiceIdentities(domName, false, false, "key1",  null);

        // first request with keys and hosts option set

        ServiceIdentities services = zclt.getServiceIdentities(domName, true, true, null ,null);
        assertNotNull(services);
        assertNotNull(services.getList());

        boolean serviceCheck = false;
        for (ServiceIdentity service : services.getList()) {
            if ("get-services.service-key-host".equals(service.getName())) {
                assertNotNull(service.getModified());
                List<PublicKeyEntry> testPublicKeys = service.getPublicKeys();
                assertNotNull(testPublicKeys);
                assertEquals(testPublicKeys.size(), 1);
                assertEquals(testPublicKeys.get(0).getId(), "0");
                assertEquals(testPublicKeys.get(0).getKey(), "key");
                List<String> testHosts = service.getHosts();
                assertNotNull(testHosts);
                assertEquals(testHosts.size(), 1);
                assertEquals(testHosts.get(0), "host1");
                serviceCheck = true;
            }
        }
        assertTrue(serviceCheck);

        // next with only key option

        services = zclt.getServiceIdentities(domName, true, false, null, null);
        assertNotNull(services);
        assertNotNull(services.getList());

        serviceCheck = false;
        for (ServiceIdentity service : services.getList()) {
            if ("get-services.service-key-only".equals(service.getName())) {
                assertNotNull(service.getModified());
                List<PublicKeyEntry> testPublicKeys = service.getPublicKeys();
                assertNotNull(testPublicKeys);
                assertEquals(testPublicKeys.size(), 1);
                assertEquals(testPublicKeys.get(0).getId(), "0");
                assertEquals(testPublicKeys.get(0).getKey(), "key");
                assertNull(service.getHosts());
                serviceCheck = true;
            }
        }
        assertTrue(serviceCheck);

        // next with only host option

        services = zclt.getServiceIdentities(domName, false, true);
        assertNotNull(services);
        assertNotNull(services.getList());

        serviceCheck = false;
        for (ServiceIdentity service : services.getList()) {
            if ("get-services.service-host-only".equals(service.getName())) {
                assertNotNull(service.getModified());
                assertNull(service.getPublicKeys());
                List<String> testHosts = service.getHosts();
                assertNotNull(testHosts);
                assertEquals(testHosts.size(), 1);
                assertEquals(testHosts.get(0), "host1");
                serviceCheck = true;
            }
        }
        assertTrue(serviceCheck);

        services = zclt.getServiceIdentities(domName, false, false, "key1", null);
        assertNotNull(services);
        assertNotNull(services.getList());

        serviceCheck = false;
        for (ServiceIdentity service : services.getList()) {
            if ("get-services.service-tags-only".equals(service.getName())) {
                assertNotNull(service.getModified());
                assertNull(service.getPublicKeys());
                assertNull(service.getHosts());
                Map<String, TagValueList> testTags = service.getTags();
                assertNotNull(testTags);
                assertEquals(testTags.size(), 2);
                assertEquals(testTags.get("key1").getList(), Arrays.asList("value1", "value2", "value3"));
                assertEquals(testTags.get("key2").getList(), Arrays.asList("value4", "value5"));
                serviceCheck = true;
            }
        }
        assertTrue(serviceCheck);
    }

    @Test
    public void testGetAssertion() throws Exception {

        final String domName = "get-assertion";
        Assertion assertion = new Assertion()
                .setAction("update")
                .setEffect(AssertionEffect.ALLOW)
                .setId((long) 101)
                .setResource(domName + ":*")
                .setRole("admin");

        Mockito.doReturn(assertion).when(mockZMS).getAssertion(domName, "policy1", 101L);
        Mockito.doThrow(new ResourceException(404)).when(mockZMS).getAssertion(domName, "policy1", 202L);

        // first invalid test cases

        // unknown policy name
        Assertion testAssertion = zclt.getAssertion(domName, "policy2", 101L);
        assertNull(testAssertion);

        // unknown domain name

        testAssertion = zclt.getAssertion("unknown", "policy1", 101L);
        assertNull(testAssertion);

        // unknown assertion id

        testAssertion = zclt.getAssertion(domName, "policy1", 102L);
        assertNull(testAssertion);

        // exception unit test

        try {
            zclt.getAssertion(domName, "policy1", 202L);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }

        // now valid case

        testAssertion = zclt.getAssertion(domName, "policy1", 101L);
        assertNotNull(testAssertion);
        assertEquals(assertion.getAction(), "update");
        assertEquals((long) assertion.getId(), 101);
    }

    @Test
    public void testDeleteAssertion() throws Exception {

        final String domName = "delete-assertion";

        Mockito.doReturn(null).when(mockZMS).deleteAssertion(domName, "policy1", 101L, auditRef, null);
        Mockito.doThrow(new ResourceException(403)).when(mockZMS).deleteAssertion(domName, "policy1", 202L,
                auditRef, null);

        Mockito.doReturn(null).when(mockZMS).deleteAssertionPolicyVersion(domName, "policy1", "new-version",
                101L, auditRef, null);
        Mockito.doThrow(new ResourceException(403)).when(mockZMS).deleteAssertionPolicyVersion(domName, "policy1",
                "new-version",202L, auditRef, null);

        // first valid case should complete successfully

        zclt.deleteAssertion(domName, "policy1", 101L, auditRef);
        zclt.deleteAssertion(domName, "policy1", "new-version", 101L, auditRef);

        // now this should throw an exception

        try {
            zclt.deleteAssertion(domName, "policy1", 202L, auditRef);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            zclt.deleteAssertion(domName, "policy1", "new-version", 202L, auditRef);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutAssertion() throws Exception {

        final String domName = "put-assertion";
        Assertion assertion = new Assertion()
                .setAction("update")
                .setEffect(AssertionEffect.ALLOW)
                .setResource(domName + ":*")
                .setRole("admin");

        Assertion retAssertion = new Assertion()
                .setAction("update")
                .setEffect(AssertionEffect.ALLOW)
                .setId((long) 101)
                .setResource(domName + ":*")
                .setRole("admin");

        Mockito.doReturn(retAssertion).when(mockZMS).putAssertion(domName, "policy1",
                auditRef, null, assertion);
        Mockito.doThrow(new ResourceException(403)).when(mockZMS).putAssertion(domName, "policy2",
                auditRef, null, assertion);
        Mockito.doReturn(retAssertion).when(mockZMS).putAssertionPolicyVersion(domName, "policy1",
                "new-version", auditRef, null, assertion);
        Mockito.doThrow(new ResourceException(403)).when(mockZMS).putAssertionPolicyVersion(domName,
                "policy2", "new-version", auditRef, null, assertion);
        // first valid case should complete successfully

        Assertion checkAssertion = zclt.putAssertion(domName, "policy1", auditRef, assertion);
        assertEquals(checkAssertion.getId(), Long.valueOf(101));

        checkAssertion = zclt.client.putAssertionPolicyVersion(domName, "policy1", "new-version",
                auditRef, null, assertion);
        assertEquals(checkAssertion.getId(), Long.valueOf(101));

        // now this should throw an exception

        try {
            zclt.putAssertion(domName, "policy2", auditRef, assertion);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            zclt.putAssertionPolicyVersion(domName, "policy2", "new-version", auditRef, null, assertion);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }
    
}

