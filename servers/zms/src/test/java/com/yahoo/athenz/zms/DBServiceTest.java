/*
 * Copyright 2016 Yahoo Inc.
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

import com.yahoo.athenz.zms.audit.MockAuditReferenceValidatorImpl;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.common.server.audit.AuditReferenceValidator;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.*;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zms.DBService.DataCache;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.file.FileConnection;
import com.yahoo.athenz.zms.store.file.FileObjectStore;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Struct;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

@SuppressWarnings("SameParameterValue")
public class DBServiceTest {
    
    @Mock private FileConnection mockFileConn;
    @Mock private ObjectStore mockObjStore;
    
    private ZMSImpl zms             = null;
    private String adminUser        = null;
    private String pubKeyK1         = null;
    private String pubKeyK2         = null;
    private final String auditRef   = "audittest";

    // typically used when creating and deleting domains with all the tests
    //
    @Mock private RsrcCtxWrapper mockDomRsrcCtx;
    @Mock private com.yahoo.athenz.common.server.rest.ResourceContext mockDomRestRsrcCtx;

    private static final String MOCKCLIENTADDR = "10.11.12.13";
    @Mock private HttpServletRequest mockServletRequest;

    private static final String ZMS_DATA_STORE_PATH = "/tmp/zms_core_unit_tests/zms_root";
    private static final String ZMS_DATA_QUOTA_PATH = "/tmp/zms_core_unit_tests/zms_quota";

    private static final Struct TABLE_PROVIDER_ROLE_ACTIONS = new Struct()
            .with("admin", "*").with("writer", "WRITE").with("reader", "READ");
    
    private static final int BASE_PRODUCT_ID = 500000000; // these product ids will lie in 500 million range
    private static final java.util.Random domainProductId = new java.security.SecureRandom();
    private static synchronized int getRandomProductId() {
        return BASE_PRODUCT_ID + domainProductId.nextInt(99999999);
    }

    @Mock private NotificationManager mockNotificationManager;

    @BeforeClass
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        System.setProperty(ZMSImplTest.ZMS_PROP_PUBLIC_KEY, "src/test/resources/zms_public.pem");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/zms_private.pem");
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN, "user.testadminuser");

        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        Mockito.when(mockServletRequest.isSecure()).thenReturn(true);
        
        System.setProperty(ZMSConsts.ZMS_PROP_FILE_NAME, "src/test/resources/zms.properties");
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_REF_CHECK_OBJECTS,
                "role,policy,service,domain,entity,tenancy,template");
        initializeZms();
    }

    private ZMSImpl zmsInit() {
        
        // we want to make sure we start we clean dir structure
        
        FileConnection.deleteDirectory(new File(ZMS_DATA_STORE_PATH));
        FileConnection.deleteDirectory(new File(ZMS_DATA_QUOTA_PATH));

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();

        final Principal rsrcPrince = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        ((SimplePrincipal) rsrcPrince).setUnsignedCreds("v=U1;d=user;n=user1");
        
        Mockito.when(mockDomRestRsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockDomRestRsrcCtx.principal()).thenReturn(rsrcPrince);
        Mockito.when(mockDomRsrcCtx.context()).thenReturn(mockDomRestRsrcCtx);
        Mockito.when(mockDomRsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockDomRsrcCtx.principal()).thenReturn(rsrcPrince);

        adminUser = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN);

        // enable product id support
        System.setProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "true");
        System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, "src/test/resources/solution_templates.json");

        System.setProperty(ZMSConsts.ZMS_PROP_FILE_STORE_PATH, "/tmp/zms_core_unit_tests/");
        System.clearProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE);
        System.clearProperty(ZMSConsts.ZMS_PROP_JDBC_RO_STORE);

        return new ZMSImpl();
    }
    
    private Entity createEntityObject(String entityName) {

        Entity entity = new Entity();
        entity.setName(entityName);

        Struct value = new Struct();
        value.put("Key1", "Value1");
        entity.setValue(value);

        return entity;
    }
    
    private Role createRoleObject(String domainName, String roleName,
            String trust, String member1, String member2) {

        List<RoleMember> members = new ArrayList<>();
        if (member1 != null) {
            members.add(new RoleMember().setMemberName(member1).setActive(true).setApproved(true));
        }
        if (member2 != null) {
            members.add(new RoleMember().setMemberName(member2).setActive(true).setApproved(true));
        }
        return createRoleObject(domainName, roleName, trust, members);
    }

    private Role createRoleObject(String domainName, String roleName,
            String trust, List<RoleMember> members) {
        
        Role role = new Role();
        role.setName(ZMSUtils.roleResourceName(domainName, roleName));
        role.setRoleMembers(members);
        if (trust != null) {
            role.setTrust(trust);
        }
        
        return role;
    }
    
    private Policy createPolicyObject(String domainName, String policyName) {
        return createPolicyObject(domainName, policyName, "role1", true, "*",
                domainName + ":*", AssertionEffect.ALLOW);
    }
    
    private Policy createPolicyObject(String domainName, String policyName,
            String roleName, boolean generateRoleName, String action, 
            String resource, AssertionEffect effect) {

        Policy policy = new Policy();
        policy.setName(ZMSUtils.policyResourceName(domainName, policyName));

        Assertion assertion = new Assertion();
        assertion.setAction(action);
        assertion.setEffect(effect);
        assertion.setResource(resource);
        if (generateRoleName) {
            assertion.setRole(ZMSUtils.roleResourceName(domainName, roleName));
        } else {
            assertion.setRole(roleName);
        }

        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion);

        policy.setAssertions(assertList);
        return policy;
    }
    
    private ServiceIdentity createServiceObject(String domainName,
            String serviceName, String endPoint, String executable,
            String user, String group, String host) {

        ServiceIdentity service = new ServiceIdentity();
        service.setExecutable(executable);
        service.setName(ZMSUtils.serviceResourceName(domainName, serviceName));
        
        List<PublicKeyEntry> publicKeyList = new ArrayList<>();
        PublicKeyEntry publicKeyEntry1 = new PublicKeyEntry();
        publicKeyEntry1.setKey(pubKeyK1);
        publicKeyEntry1.setId("1");
        publicKeyList.add(publicKeyEntry1);
        PublicKeyEntry publicKeyEntry2 = new PublicKeyEntry();
        publicKeyEntry2.setKey(pubKeyK2);
        publicKeyEntry2.setId("2");
        publicKeyList.add(publicKeyEntry2);
        service.setPublicKeys(publicKeyList);
        
        service.setUser(user);
        service.setGroup(group);
        
        if (endPoint != null) {
            service.setProviderEndpoint(endPoint);
        }
        
        List<String> hosts = new ArrayList<>();
        hosts.add(host);
        service.setHosts(hosts);
        
        return service;
    }
    
    private void initializeZms() throws IOException {

        Path path = Paths.get("./src/test/resources/zms_public_k1.pem");
        pubKeyK1 = Crypto.ybase64((new String(Files.readAllBytes(path))).getBytes());

        path = Paths.get("./src/test/resources/zms_public_k2.pem");
        pubKeyK2 = Crypto.ybase64(new String(Files.readAllBytes(path)).getBytes());

        zms = zmsInit();
        zms.notificationManager = mockNotificationManager;
    }

    @AfterClass
    public void shutdown() {
        FileConnection.deleteDirectory(new File(ZMS_DATA_STORE_PATH));
        System.clearProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT);
    }
    
    private TopLevelDomain createTopLevelDomainObject(String name, String description,
            String org, String admin, boolean enabled, boolean auditEnabled) {

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setAuditEnabled(auditEnabled);
        dom.setEnabled(enabled);
        dom.setYpmId(getRandomProductId());

        List<String> admins = new ArrayList<>();
        admins.add(admin);
        dom.setAdminUsers(admins);

        return dom;
    }
    
    private TopLevelDomain createTopLevelDomainObject(String name,
            String description, String org, String admin) {
        return createTopLevelDomainObject(name, description, org, admin, true, false);
    }
    
    @Test
    public void testCheckDomainAuditEnabledFlagTrueRefValid() {
        
        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledFlagTrueRefValid";
        String principal = "testprincipal";
        zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
    }

    @Test
    public void testGetResourceAccessList() {
        try {
            // currently in the filestore that we're using for our unit
            // we don't have an implementation for this method
            zms.dbService.getResourceAccessList("principal", "UPDATE");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }
    
    private SubDomain createSubDomainObject(String name, String parent,
            String description, String org, String admin) {

        SubDomain dom = new SubDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setParent(parent);

        List<String> admins = new ArrayList<>();
        admins.add(admin);
        dom.setAdminUsers(admins);

        return dom;
    }
    
    @Test
    public void testCheckDomainAuditEnabledFlagTrueRefNull() {
        
        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String caller = "testCheckDomainAuditEnabledFlagTrueRefNull";
        String principal = "testprincipal";
        try {
            zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, null, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Audit reference required"));
        }
    }

    @Test
    public void testCheckDomainAuditEnabledFlagTrueRefEmpty() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck = "";
        String caller = "testCheckDomainAuditEnabledFlagTrueRefEmpty";
        String principal = "testprincipal";
        try {
            zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Audit reference required"));
        }
    }

    @Test
    public void testCheckDomainAuditEnabledFlagFalseRefValid() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledFlagFalseRefValid";
        String principal = "testprincipal";
        zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
    }

    @Test
    public void testCheckDomainAuditEnabledFlagFalseRefNull() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String caller = "testCheckDomainAuditEnabledFlagFalseRefNull";
        String principal = "testprincipal";
        zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, null, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
    }

    private void checkRoleMember(final List<String> checkList, List<RoleMember> members) {
        boolean found = false;
        for (String roleMemberName: checkList) {
            for (RoleMember roleMember: members) {
                if (roleMember.getMemberName().equals(roleMemberName)){
                    found = true;
                }
            }
            if (!found) {
                fail("Member " + roleMemberName + " not found");
            }
        }
    }
    
    @Test
    public void testCheckDomainAuditEnabledFlagFalseRefEmpty() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck = "";
        String caller = "testCheckDomainAuditEnabledFlagFalseRefEmpty";
        String principal = "testprincipal";
        zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
    }
    
    @Test
    public void testCheckDomainAuditEnabledInvalidDomain() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledDefault";
        String principal = "testprincipal";
        try {
            zms.dbService.checkDomainAuditEnabled(mockFileConn, "unknown_domain", auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testCheckDomainAuditEnabledRefValid() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);

        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledFlagTrueRefValid";
        String principal = "testprincipal";

        zms.dbService.auditReferenceValidator = Mockito.mock(AuditReferenceValidator.class);
        Mockito.when(zms.dbService.auditReferenceValidator.validateReference(auditCheck, principal, caller)).thenReturn(true);

        zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);

        zms.dbService.auditReferenceValidator = null;
    }

    @Test
    public void testCheckDomainAuditEnabledRefFail() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);

        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledFlagTrueRefValid";
        String principal = "testprincipal";

        zms.dbService.auditReferenceValidator = Mockito.mock(AuditReferenceValidator.class);
        Mockito.when(zms.dbService.auditReferenceValidator.validateReference(auditCheck, principal, caller)).thenReturn(false);

        try {
            zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zms.dbService.auditReferenceValidator = null;
    }

    @Test
    public void testUpdateTemplateRoleNoMembers() {
        Role role = new Role().setName("_domain_:role.readers");
        Role newRole = zms.dbService.updateTemplateRole(role, "athenz", null);
        assertEquals("athenz:role.readers", newRole.getName());
        assertEquals(0, newRole.getRoleMembers().size());
    }
    
    @Test
    public void testUpdateTemplateRoleWithTrust() {
        Role role = new Role().setName("_domain_:role.readers").setTrust("trustdomain");
        Role newRole = zms.dbService.updateTemplateRole(role, "athenz", null);
        assertEquals("athenz:role.readers", newRole.getName());
        assertEquals("trustdomain", newRole.getTrust());
        assertEquals(0, newRole.getRoleMembers().size());
    }
    
    @Test
    public void testUpdateTemplateRoleWithMembers() {
        Role role = new Role().setName("_domain_:role.readers");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1"));
        members.add(new RoleMember().setMemberName("user.user2"));
        members.add(new RoleMember().setMemberName("_domain_.user3"));
        role.setRoleMembers(members);
        
        Role newRole = zms.dbService.updateTemplateRole(role, "athenz", null);
        assertEquals("athenz:role.readers", newRole.getName());
        List<RoleMember> newMembers = newRole.getRoleMembers();
        assertEquals(3, newMembers.size());
        
        List<String> checkList = new ArrayList<>();
        checkList.add("user.user1");
        checkList.add("user.user2");
        checkList.add("athenz.user3");
        checkRoleMember(checkList, newMembers);
    }
    
    @Test
    public void testUpdateTemplateRoleWithMembersWithParams() {
        Role role = new Role().setName("_domain_:role._service___api_readers");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1"));
        members.add(new RoleMember().setMemberName("user._service_"));
        members.add(new RoleMember().setMemberName("_domain_.user3"));
        role.setRoleMembers(members);
        
        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("service").setValue("storage"));
        params.add(new TemplateParam().setName("api").setValue("java"));
        params.add(new TemplateParam().setName("name").setValue("notfound"));
        Role newRole = zms.dbService.updateTemplateRole(role, "athenz", params);
        assertEquals("athenz:role.storage_javareaders", newRole.getName());
        List<RoleMember> newMembers = newRole.getRoleMembers();
        assertEquals(3, newMembers.size());
        
        List<String> checkList = new ArrayList<>();
        checkList.add("user.user1");
        checkList.add("user.storage");
        checkList.add("athenz.user3");
        checkRoleMember(checkList, newMembers);
    }
    
    @Test
    public void testUpdateTemplatePolicy() {
        Policy policy = createPolicyObject("_domain_", "policy1",
                "role1", true, "read", "_domain_:*", AssertionEffect.ALLOW);
        
        Policy newPolicy = zms.dbService.updateTemplatePolicy(policy, "athenz", null);
        
        assertEquals("athenz:policy.policy1", newPolicy.getName());

        List<Assertion> assertions = newPolicy.getAssertions();
        assertEquals(1, assertions.size());
        Assertion assertion = assertions.get(0);
        assertEquals("athenz:role.role1", assertion.getRole());
        assertEquals("athenz:*", assertion.getResource());
        assertEquals("read", assertion.getAction());
        assertEquals(AssertionEffect.ALLOW, assertion.getEffect());
    }
    
    @Test
    public void testUpdateTemplatePolicyWithParams() {
        Policy policy = createPolicyObject("_domain_", "_service___api_policy1",
                "_api_-role1", true, "read", "_domain_:_api___service__*", AssertionEffect.ALLOW);
        
        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("service").setValue("storage"));
        params.add(new TemplateParam().setName("api").setValue("java"));
        params.add(new TemplateParam().setName("name").setValue("notfound"));
        Policy newPolicy = zms.dbService.updateTemplatePolicy(policy, "athenz", params);
        
        assertEquals("athenz:policy.storage_javapolicy1", newPolicy.getName());

        List<Assertion> assertions = newPolicy.getAssertions();
        assertEquals(1, assertions.size());
        Assertion assertion = assertions.get(0);
        assertEquals("athenz:role.java-role1", assertion.getRole());
        assertEquals("athenz:java_storage_*", assertion.getResource());
        assertEquals("read", assertion.getAction());
        assertEquals(AssertionEffect.ALLOW, assertion.getEffect());
    }
    
    @Test
    public void testUpdateTemplatePolicyNoAssertions() {
        Policy policy = new Policy().setName("_domain_:policy.policy1");
        Policy newPolicy = zms.dbService.updateTemplatePolicy(policy, "athenz", null);
        
        assertEquals("athenz:policy.policy1", newPolicy.getName());
        List<Assertion> assertions = newPolicy.getAssertions();
        assertEquals(0, assertions.size());
    }
    
    @Test
    public void testUpdateTemplatePolicyAssertionNoRewrite() {
        Policy policy = createPolicyObject("_domain_", "policy1",
                "coretech:role.role1", false, "read", "coretech:*", AssertionEffect.ALLOW);
        
        Policy newPolicy = zms.dbService.updateTemplatePolicy(policy, "athenz", null);
        
        assertEquals("athenz:policy.policy1", newPolicy.getName());

        List<Assertion> assertions = newPolicy.getAssertions();
        assertEquals(1, assertions.size());
        Assertion assertion = assertions.get(0);
        assertEquals("coretech:role.role1", assertion.getRole());
        assertEquals("coretech:*", assertion.getResource());
        assertEquals("read", assertion.getAction());
        assertEquals(AssertionEffect.ALLOW, assertion.getEffect());
    }

    @Test
    public void testUpdateTemplateServiceIdentity() {

        ServiceIdentity service = createServiceObject("_domain_",
                "_service___api_-backend", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("service").setValue("storage"));
        params.add(new TemplateParam().setName("api").setValue("java"));
        params.add(new TemplateParam().setName("name").setValue("notfound"));

        ServiceIdentity newService = zms.dbService.updateTemplateServiceIdentity(service,
                "athenz", params);

        assertEquals("athenz.storage_java-backend", newService.getName());
    }

    @Test
    public void testIsTenantRolePrefixMatchNoPrefixMatch() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.role1",
                "coretech2.role.", null, "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchResGroupNullTenant() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.res_group.reader",
                "coretech.storage.", "reader", "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchResGroupMultipleComponents() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.res_group.group1.group2.group3.reader",
                "coretech.storage.", "group1.group2.group3", "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchResGroupSingleComponent() {
        assertTrue(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.res_group.group1.access",
                "coretech.storage.res_group.group1.", "group1", "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchResGroupSubstring() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.res_group.group1.group2.access",
                "coretech.storage.res_group1.group1.", "group1", "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchSubdomainCheckExists() {
        
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain("tenant.sub");
        
        // since subdomain exists - we're assuming is not a tenant role
        
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.sub.reader",
                "coretech.storage.", null, "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchSubdomainCheckDoesNotExist() {
        
        Mockito.doReturn(null).when(mockFileConn).getDomain("tenant.sub");
        
        // subdomain does not exist thus this is a tenant role
        
        assertTrue(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.sub.reader",
                "coretech.storage.", null, "tenant"));
    }

    @Test
    public void testIsTrustRoleForTenantPrefixNoMatch() {
        
        assertFalse(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech2.storage.tenant.", null, "athenz"));
    }
    
    @Test
    public void testIsTrustRoleForTenantNoRole() {
        
        Mockito.doReturn(null).when(mockFileConn).getRole("sports", "coretech.storage.tenant.admin");

        assertFalse(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", null, "athenz"));
    }
    
    @Test
    public void testIsTrustRoleForTenantNoRoleTrust() {
        
        Role role = new Role().setName(ZMSUtils.roleResourceName("sports",  "coretech.storage.tenant.admin"));
        Mockito.doReturn(role).when(mockFileConn).getRole("sports", "coretech.storage.tenant.admin");
        
        assertFalse(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", null, "athenz"));
    }
    
    @Test
    public void testIsTrustRoleForTenantRoleTrustMatch() {
        
        Role role = new Role().setName(ZMSUtils.roleResourceName("sports",  "coretech.storage.tenant.admin"))
                .setTrust("athenz");
        Mockito.doReturn(role).when(mockFileConn).getRole("sports", "coretech.storage.tenant.admin");
        
        assertTrue(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", null, "athenz"));
    }
    
    @Test
    public void testIsTrustRoleForTenantRoleTrustNoMatch() {
        
        Role role = new Role().setName(ZMSUtils.roleResourceName("sports",  "coretech.storage.tenant.admin"))
                .setTrust("athenz2");
        Mockito.doReturn(role).when(mockFileConn).getRole("sports", "coretech.storage.tenant.admin");
        
        assertFalse(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", null, "athenz"));
    }
    
    @Test
    public void testExecutePutPolicyCreate() {

        String domainName = "testreplacepolicycreatedomain";
        String policyName = "policy1";
        
        TopLevelDomain dom = createTopLevelDomainObject(domainName, null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Policy policy = createPolicyObject(domainName, policyName);
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName, policy,
                auditRef, "testReplacePolicyCreate");

        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes);
        assertEquals(policyRes.getName(), domainName + ":policy." + policyName);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutPolicyExisting() {

        String domainName = "testreplacepolicycreatedomain";
        String policyName = "policy1";
        
        TopLevelDomain dom = createTopLevelDomainObject(domainName, null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Policy policy = createPolicyObject(domainName, policyName);
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName, policy,
                auditRef, "testExecutePutPolicyExisting");

        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes);
        assertEquals(policyRes.getName(), domainName + ":policy." + policyName);
        List<Assertion> asserts = policyRes.getAssertions();
        int origAssertCnt = (asserts == null) ? 0 : asserts.size();

        // replace the existing policy with a modified version
        
        Assertion assertion = new Assertion();
        assertion.setAction("test").setEffect(AssertionEffect.ALLOW).setResource("tests");
        asserts = policy.getAssertions();
        asserts.add(assertion);
        policy = policy.setAssertions(asserts);

        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName, policy,
                auditRef, "testExecutePutPolicyExisting");

        Policy policyRes2 = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes2);
        asserts = policyRes2.getAssertions();
        assertTrue(asserts.size() > origAssertCnt);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutPolicyMissingAuditRef() {
        // create a new policy without an auditref
        
        String domain = "testreplacepolicymissingauditref";
        TopLevelDomain dom = createTopLevelDomainObject(
            domain, null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Policy policy = createPolicyObject(domain, "policy1");
        try {
            zms.dbService.executePutPolicy(mockDomRsrcCtx, domain, "policy1", policy,
                    null, "testExecutePutPolicyMissingAuditRef");
            fail("requesterror not thrown by replacePolicy.");
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }
    
    @Test
    public void testExecuteDeleteEntity() {

        String domainName = "delentitydom1";
        String entityName = "entity1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Entity entity1 = createEntityObject(entityName);
        zms.putEntity(mockDomRsrcCtx, domainName, entityName, auditRef, entity1);

        Entity entityRes = zms.getEntity(mockDomRsrcCtx, domainName, entityName);
        assertNotNull(entityRes);

        zms.dbService.executeDeleteEntity(mockDomRsrcCtx, domainName, entityName, auditRef, "deleteEntity");

        try {
            zms.getEntity(mockDomRsrcCtx, domainName, entityName);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecuteDeleteMembership() {

        String domainName = "mbrdeldom1";
        String roleName = "role1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);
        zms.dbService.executeDeleteMembership(mockDomRsrcCtx, domainName, roleName,
                "user.joe", auditRef, "deleteMembership");

        Role role = zms.getRole(mockDomRsrcCtx, domainName, roleName, true, false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 1);

        for (RoleMember member: members) {
            if (member.getMemberName().equals("user.joe")) {
                fail("user.joe could not be deleted");
            }
        }
        List<String> checkList = new ArrayList<>();
        checkList.add("user.jane");
        checkRoleMember(checkList, members);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecuteDeletePolicy() {

        String domainName = "policydeldom1";
        String policyName = "policy1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject(domainName, policyName);
        zms.putPolicy(mockDomRsrcCtx, domainName, policyName, auditRef, policy1);

        Policy policyRes1 = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes1);

        zms.dbService.executeDeletePolicy(mockDomRsrcCtx, domainName, policyName,
                auditRef, "deletePolicy");

        // we need to get an exception here
        try {
            zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecuteDeletePublicKeyEntry() {
        
        String domainName = "servicedelpubkeydom1";
        String serviceName = "service1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, service);

        zms.dbService.executeDeletePublicKeyEntry(mockDomRsrcCtx, domainName, serviceName,
                "1", auditRef, "deletePublicKeyEntry");

        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);

        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        boolean found = false;
        for (PublicKeyEntry entry : keyList) {
            if (entry.getId().equals("1")) {
                found = true;
            }
        }
        assertFalse(found);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecuteDeletePublicKeyEntryLastKeyAllowed() {
        
        String domainName = "servicedelpubkeydom1";
        String serviceName = "service1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, service);

        try {
            zms.dbService.executeDeletePublicKeyEntry(mockDomRsrcCtx, domainName, serviceName,
                    "1", auditRef, "deletePublicKeyEntry");

            zms.dbService.executeDeletePublicKeyEntry(mockDomRsrcCtx, domainName, serviceName,
                    "2", auditRef, "deletePublicKeyEntry");
        } catch (Exception e) {
            fail();
        }

        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);
        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        if (keyList != null) {
            assertEquals(keyList.size(), 0);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecuteDeleteRole() {

        String domainName = "delroledom1";
        String roleName = "role1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);

        RoleList roleList = zms.getRoleList(mockDomRsrcCtx, domainName, null, null);
        assertNotNull(roleList);

        // our role count is +1 because of the admin role
        assertEquals(roleList.getNames().size(), 2);

        zms.dbService.executeDeleteRole(mockDomRsrcCtx, domainName, roleName, auditRef, "deleteRole");

        roleList = zms.getRoleList(mockDomRsrcCtx, domainName, null, null);
        assertNotNull(roleList);

        // our role count is +1 because of the admin role
        assertEquals(roleList.getNames().size(), 1);

        assertFalse(roleList.getNames().contains(roleName));
        assertTrue(roleList.getNames().contains("admin"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecuteDeleteServiceIdentity() {

        String domainName = "servicedeldom1";
        String serviceName = "service1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service1 = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, service1);

        ServiceIdentity serviceRes1 = zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);
        assertNotNull(serviceRes1);

        zms.dbService.executeDeleteServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                auditRef, "deleteServiceIdentity");

        // this should throw a not found exception
        try {
            zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecutePutEntity() {

        String domainName = "createentitydom1";
        String entityName = "entity1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Entity entity1 = createEntityObject(entityName);
        zms.dbService.executePutEntity(mockDomRsrcCtx, domainName, entityName,
                entity1, auditRef, "putEntity");

        Entity entity2 = zms.getEntity(mockDomRsrcCtx, domainName, entityName);
        assertNotNull(entity2);
        assertEquals(entity2.getName(), entityName);

        Struct value = entity2.getValue();
        assertEquals("Value1", value.getString("Key1"));
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecutePutEntityUpdate() {

        String domainName = "createentitydom1-mod";
        String entityName = "entity1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Entity entity1 = createEntityObject(entityName);
        zms.dbService.executePutEntity(mockDomRsrcCtx, domainName, entityName,
                entity1, auditRef, "putEntity");

        Struct value = new Struct();
        value.put("Key2", "Value2");
        entity1.setValue(value);
        
        zms.dbService.executePutEntity(mockDomRsrcCtx, domainName, entityName,
                entity1, auditRef, "putEntity");
        
        Entity entity2 = zms.getEntity(mockDomRsrcCtx, domainName, entityName);
        assertNotNull(entity2);
        assertEquals(entity2.getName(), entityName);
        value = entity2.getValue();
        assertEquals("Value2", value.getString("Key2"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecutePutDomainMeta() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MetaDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Domain resDom1 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom1);
        assertEquals("Test Domain1", resDom1.getDescription());
        assertEquals("testorg", resDom1.getOrg());
        assertTrue(resDom1.getEnabled());
        assertFalse(resDom1.getAuditEnabled());
        assertNull(resDom1.getTokenExpiryMins());
        assertNull(resDom1.getMemberExpiryDays());
        assertNull(resDom1.getServiceExpiryDays());
        assertNull(resDom1.getRoleCertExpiryMins());
        assertNull(resDom1.getServiceCertExpiryMins());
        
        // update meta with values for account and product ids
        
        DomainMeta meta = new DomainMeta().setDescription("Test2 Domain").setOrg("NewOrg")
                .setEnabled(true).setAuditEnabled(false).setAccount("12345").setYpmId(1001)
                .setCertDnsDomain("athenz1.cloud").setMemberExpiryDays(10).setTokenExpiryMins(20)
                .setServiceExpiryDays(45);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, null, false, auditRef, "putDomainMeta");
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, "productid", true, auditRef, "putDomainMeta");
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, "account", true, auditRef, "putDomainMeta");
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, "certdnsdomain", true, auditRef, "putDomainMeta");
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, "org", true, auditRef, "putDomainMeta");

        Domain resDom2 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom2);
        assertEquals("Test2 Domain", resDom2.getDescription());
        assertEquals("NewOrg", resDom2.getOrg());
        assertTrue(resDom2.getEnabled());
        assertFalse(resDom2.getAuditEnabled());
        assertEquals(Integer.valueOf(1001), resDom2.getYpmId());
        assertEquals("12345", resDom2.getAccount());
        assertEquals(resDom2.getCertDnsDomain(), "athenz1.cloud");
        assertEquals(Integer.valueOf(20), resDom2.getTokenExpiryMins());
        assertEquals(Integer.valueOf(10), resDom2.getMemberExpiryDays());
        assertEquals(Integer.valueOf(45), resDom2.getServiceExpiryDays());
        assertNull(resDom2.getRoleCertExpiryMins());
        assertNull(resDom2.getServiceCertExpiryMins());

        // now update without account and product ids
        
        meta = new DomainMeta().setDescription("Test2 Domain-New").setOrg("NewOrg-New")
                .setEnabled(true).setAuditEnabled(false).setRoleCertExpiryMins(30)
                .setServiceCertExpiryMins(40).setSignAlgorithm("rsa")
                .setServiceExpiryDays(45);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, null, false, auditRef, "putDomainMeta");
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, "org", true, auditRef, "putDomainMeta");

        Domain resDom3 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom3);
        assertEquals("Test2 Domain-New", resDom3.getDescription());
        assertEquals("NewOrg-New", resDom3.getOrg());
        assertTrue(resDom3.getEnabled());
        assertFalse(resDom3.getAuditEnabled());
        assertEquals(Integer.valueOf(1001), resDom3.getYpmId());
        assertEquals("12345", resDom3.getAccount());
        assertEquals(resDom3.getCertDnsDomain(), "athenz1.cloud");
        assertEquals(Integer.valueOf(20), resDom3.getTokenExpiryMins());
        assertEquals(Integer.valueOf(10), resDom3.getMemberExpiryDays());
        assertEquals(Integer.valueOf(45), resDom3.getServiceExpiryDays());
        assertEquals(Integer.valueOf(30), resDom3.getRoleCertExpiryMins());
        assertEquals(Integer.valueOf(40), resDom3.getServiceCertExpiryMins());
        assertEquals(resDom3.getSignAlgorithm(), "rsa");

        meta = new DomainMeta().setDescription("Test2 Domain-New").setOrg("NewOrg-New")
                .setEnabled(true).setAuditEnabled(false).setRoleCertExpiryMins(300)
                .setServiceCertExpiryMins(400).setTokenExpiryMins(500)
                .setSignAlgorithm("ec").setServiceExpiryDays(20);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, null, false, auditRef, "putDomainMeta");

        Domain resDom4 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom4);
        assertEquals("Test2 Domain-New", resDom4.getDescription());
        assertEquals("NewOrg-New", resDom4.getOrg());
        assertTrue(resDom4.getEnabled());
        assertFalse(resDom4.getAuditEnabled());
        assertEquals(Integer.valueOf(1001), resDom4.getYpmId());
        assertEquals("12345", resDom4.getAccount());
        assertEquals(resDom4.getCertDnsDomain(), "athenz1.cloud");
        assertEquals(Integer.valueOf(500), resDom4.getTokenExpiryMins());
        assertEquals(Integer.valueOf(10), resDom4.getMemberExpiryDays());
        assertEquals(Integer.valueOf(20), resDom4.getServiceExpiryDays());
        assertEquals(Integer.valueOf(300), resDom4.getRoleCertExpiryMins());
        assertEquals(Integer.valueOf(400), resDom4.getServiceCertExpiryMins());
        assertEquals(resDom4.getSignAlgorithm(), "ec");

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MetaDom1", auditRef);
    }

    @Test
    public void testExecutePutDomainMetaRetryException() {

        String domainName = "metadom1retry";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        DomainMeta meta = new DomainMeta().setDescription("Test2 Domain").setOrg("NewOrg")
                .setEnabled(true).setAuditEnabled(false).setAccount("12345").setYpmId(1001);

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.updateDomain(any()))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domainName, meta,
                    null, false, auditRef, "testExecutePutDomainMetaRetryException");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutMembership() {

        String domainName = "mgradddom1";
        String roleName = "role1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);
        
        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe"), auditRef, "putMembership");
        
        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("coretech.storage"), auditRef, "putMembership");

        Role role = zms.getRole(mockDomRsrcCtx, domainName, roleName, false, false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 4);

        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkList.add("coretech.storage");
        checkRoleMember(checkList, members);
        
        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutMembershipInvalidRoleFailure() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.insertRoleMember(anyString(), anyString(), any(RoleMember.class),
                anyString(), anyString())).thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.getRole(domainName, roleName)).thenReturn(null);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                    new RoleMember().setMemberName("user.doe"), auditRef, "putMembership");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutMembershipFailure() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.insertRoleMember(anyString(), anyString(), any(RoleMember.class),
                anyString(), anyString())).thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Role role = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        Mockito.when(mockFileConn.getRole(domainName, roleName)).thenReturn(role);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                    new RoleMember().setMemberName("user.doe"), auditRef, "putMembership");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutMembershipRetryFailure() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.insertRoleMember(anyString(), anyString(), any(RoleMember.class),
                anyString(), anyString())).thenThrow(new ResourceException(ResourceException.CONFLICT));
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Role role = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        Mockito.when(mockFileConn.getRole(domainName, roleName)).thenReturn(role);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                    new RoleMember().setMemberName("user.doe"), auditRef, "putMembership");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutMembershipTrustRole() {

        String domainName = "putmbrtrustrole";
        String roleName = "role1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        Role role1 = createRoleObject(domainName, roleName, "sys.auth",
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);
        
        try {
            zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                    new RoleMember().setMemberName("user.doe"), auditRef, "putMembership");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecutePutPolicy() {

        String domainName = "policyadddom1";
        String policyName = "policy1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject(domainName, policyName);
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName,
                policy1, auditRef, "putPolicy");

        Policy policyRes2 = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), domainName + ":policy." + policyName);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecutePutPolicyInvalidDomain() {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyAddDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject("PolicyAddDom1", "Policy1");
        
        try {
            zms.dbService.executePutPolicy(mockDomRsrcCtx, "PolicyAddDom1Invalid", "Policy1",
                    policy1, auditRef, "putPolicy");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyAddDom1", auditRef);
    }
    
    @Test
    public void testExecutePutPublicKeyEntry() {
        
        String domainName = "servicepubpubkeydom1";
        String serviceName = "service1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey(pubKeyK2);
        
        zms.dbService.executePutPublicKeyEntry(mockDomRsrcCtx, domainName, serviceName,
                keyEntry, auditRef, "putPublicKeyEntry");
        
        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);
        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        boolean foundKey1 = false;
        boolean foundKey2 = false;
        boolean foundKeyZONE1 = false;
        for (PublicKeyEntry entry : keyList) {
            switch (entry.getId()) {
                case "1":
                    foundKey1 = true;
                    break;
                case "2":
                    foundKey2 = true;
                    break;
                case "zone1":
                    foundKeyZONE1 = true;
                    break;
            }
        }
        assertTrue(foundKey1);
        assertTrue(foundKey2);
        assertTrue(foundKeyZONE1);
        
        PublicKeyEntry entry = zms.getPublicKeyEntry(mockDomRsrcCtx, domainName, serviceName, "zone1");
        assertNotNull(entry);
        assertEquals(entry.getId(), "zone1");
        assertEquals(entry.getKey(), pubKeyK2);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecuteDeleteServiceIdentityFailure() {

        String domainName = "servicedelete1";
        String serviceName = "service1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deleteServiceIdentity(domainName, serviceName)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeleteServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                    auditRef, "deleteServiceIdentity");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteServiceIdentityFailureRetry() {

        String domainName = "servicedelete1";
        String serviceName = "service1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deleteServiceIdentity(domainName, serviceName))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeleteServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                    auditRef, "deleteServiceIdentity");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteEntityFailure() {

        String domainName = "entitydelete1";
        String entityName = "entity1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deleteEntity(domainName, entityName)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeleteEntity(mockDomRsrcCtx, domainName, entityName,
                    auditRef, "deleteEntity");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteEntityFailureRetry() {

        String domainName = "entitydelete1";
        String entityName = "entity1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deleteEntity(domainName, entityName))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeleteEntity(mockDomRsrcCtx, domainName, entityName,
                    auditRef, "deleteEntity");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteRoleFailure() {

        String domainName = "roledelete1";
        String roleName = "role1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deleteRole(domainName, roleName)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeleteRole(mockDomRsrcCtx, domainName, roleName,
                    auditRef, "deleteRole");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteRoleFailureRetry() {

        String domainName = "roledelete1";
        String roleName = "role1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deleteRole(domainName, roleName))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeleteRole(mockDomRsrcCtx, domainName, roleName,
                    auditRef, "deleteRole");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePolicyFailure() {

        String domainName = "policyDelet1";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deletePolicy(domainName, policyName)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeletePolicy(mockDomRsrcCtx, domainName, policyName,
                    auditRef, "deletePolicy");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePolicyFailureRetry() {

        String domainName = "policyDelet1";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deletePolicy(domainName, policyName))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeletePolicy(mockDomRsrcCtx, domainName, policyName,
                    auditRef, "deletePolicy");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutPublicKeyEntryFailureRetry() {

        String domainName = "servicepubpubkeydom1";
        String serviceName = "service1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        PublicKeyEntry keyEntry = new PublicKeyEntry().setId("0").setKey("key");
        Mockito.when(mockFileConn.getPublicKeyEntry(domainName, serviceName, "0", false)).thenReturn(keyEntry);
        Mockito.when(mockFileConn.updatePublicKeyEntry(domainName, serviceName, keyEntry))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutPublicKeyEntry(mockDomRsrcCtx, domainName, serviceName,
                    keyEntry, auditRef, "putPublicKeyEntry");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePublicKeyEntryFailureRetry() {

        String domainName = "servicepubpubkeydom1";
        String serviceName = "service1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deletePublicKeyEntry(domainName, serviceName, "0"))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeletePublicKeyEntry(mockDomRsrcCtx, domainName, serviceName,
                    "0", auditRef, "deletePublicKeyEntry");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutPublicKeyEntryFailure() {

        String domainName = "servicepubpubkeydom1";
        String serviceName = "service1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        PublicKeyEntry keyEntry = new PublicKeyEntry().setId("0").setKey("key");
        Mockito.when(mockFileConn.getPublicKeyEntry(domainName, serviceName, "0", false)).thenReturn(keyEntry);
        Mockito.when(mockFileConn.updatePublicKeyEntry(domainName, serviceName, keyEntry)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutPublicKeyEntry(mockDomRsrcCtx, domainName, serviceName,
                    keyEntry, auditRef, "putPublicKeyEntry");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.INTERNAL_SERVER_ERROR, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutRole() {

        String domainName = "executeputroledom1";
        String roleName = "role1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole");

        Role role3 = zms.getRole(mockDomRsrcCtx, domainName, roleName, false, false, false);
        assertNotNull(role3);
        assertEquals(role3.getName(), domainName + ":role." + roleName);
        assertNull(role3.getTrust());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutRoleFailure() {

        String domainName = "executeputroledom1";
        String roleName = "role1";

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");

        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.insertRole(anyString(), any(Role.class)))
                .thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutRoleRetryFailure() {

        String domainName = "executeputroledom1";
        String roleName = "role1";

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");

        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.insertRole(anyString(), any(Role.class)))
                .thenThrow(new ResourceException(ResourceException.CONFLICT));
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutRoleInvalidDomain() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ExecutePutRoleInvalidDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("ExecutePutRoleInvalidDom1", "Role1", null,
                "user.joe", "user.jane");
        
        try {
            zms.dbService.executePutRole(mockDomRsrcCtx, "ExecutePutRoleInvalidDom2",
                    "Role1", role1, auditRef, "putRole");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ExecutePutRoleInvalidDom1", auditRef);
    }
    
    @Test
    public void testExecutePutServiceIdentity() {

        String domainName = "serviceadddom1";
        String serviceName = "service1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                service, auditRef, "putServiceIdentity");

        ServiceIdentity serviceRes2 = zms.getServiceIdentity(mockDomRsrcCtx, domainName,
                serviceName);
        assertNotNull(serviceRes2);
        assertEquals(serviceRes2.getName(), domainName + "." + serviceName);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutServiceIdentityFailure() {

        String domainName = "serviceadddom1";
        String serviceName = "service1";

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.insertServiceIdentity(anyString(), any(ServiceIdentity.class)))
                .thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName, service,
                    auditRef, "putServiceIdentity");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutServiceIdentityRetryException() {

        String domainName = "serviceadddom1";
        String serviceName = "service1";

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.insertServiceIdentity(domainName, service))
            .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));
        
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;
        
        try {
            zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                    service, auditRef, "putServiceIdentity");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }
        
        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutServiceIdentitySystemMetaFailureInvalidDomain() {

        String domainName = "serviceadddom1";
        String serviceName = "service1";

        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(null);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta();
        meta.setProviderEndpoint("https://localhost");
        try {
            zms.dbService.executePutServiceIdentitySystemMeta(mockDomRsrcCtx, domainName, serviceName, meta,
                    "providerendpoint", true, auditRef, "putServiceIdentitySystemMeta");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutServiceIdentitySystemMetaFailureRetry() {

        String domainName = "serviceadddom1";
        String serviceName = "service1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        ServiceIdentity service = new ServiceIdentity().setProviderEndpoint("https://localhost");
        Mockito.when(mockFileConn.getServiceIdentity(domainName, serviceName)).thenReturn(service);
        Mockito.when(mockFileConn.updateServiceIdentity(domainName, service))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta();
        meta.setProviderEndpoint("https://localhost");
        try {
            zms.dbService.executePutServiceIdentitySystemMeta(mockDomRsrcCtx, domainName, serviceName, meta,
                    "providerendpoint", true, auditRef, "putServiceIdentitySystemMeta");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutServiceIdentityModifyHost() {

        String domainName = "serviceadddom1-modhost";
        String serviceName = "service1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                service, auditRef, "putServiceIdentity");

        service.getHosts().add("host2");
        service.getHosts().add("host3");
        service.getHosts().remove("host1");

        zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                service, auditRef, "putServiceIdentity");
        
        ServiceIdentity serviceRes2 = zms.getServiceIdentity(mockDomRsrcCtx, domainName,
                serviceName);
        assertNotNull(serviceRes2);
        assertEquals(serviceRes2.getName(), domainName + "." + serviceName);
        assertEquals(2, service.getHosts().size());
        assertTrue(service.getHosts().contains("host2"));
        assertTrue(service.getHosts().contains("host3"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecutePutServiceIdentityInvalidDomain() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceAddDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        try {
            zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, "ServiceAddDom1Invalid",
                    "Service1", service, auditRef, "putServiceIdentity");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceAddDom1", auditRef);
    }
    
    @Test
    public void testExecutePutTenantRoles() {
        
        String tenantDomain = "tenantadminpolicy";
        String providerDomain = "coretech";
        String providerService = "storage";

        // create domain for tenant
        
        TopLevelDomain dom1 = createTopLevelDomainObject(tenantDomain,
                "Test Tenant Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        // create domain for provider
        
        TopLevelDomain domProv = createTopLevelDomainObject(providerDomain,
                "Test Provider Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, domProv);

        // create service identity for providerDomain.providerService
        
        ServiceIdentity service = createServiceObject(
                providerDomain, providerService, "http://localhost:8090/tableprovider",
                "/usr/bin/java", "root", "users", "localhost");

        zms.putServiceIdentity(mockDomRsrcCtx, providerDomain, providerService, auditRef, service);

        Tenancy tenant = new Tenancy();
        tenant.setDomain(tenantDomain);
        tenant.setService("coretech.storage");
        
        zms.putTenancy(mockDomRsrcCtx, tenantDomain, "coretech.storage", auditRef, tenant);
        
        List<TenantRoleAction> roleActions = new ArrayList<>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }

        zms.dbService.executePutTenantRoles(mockDomRsrcCtx, providerDomain, providerService,
                tenantDomain, null, roleActions, auditRef, "putTenantRoles");

        zms.deleteTenancy(mockDomRsrcCtx, tenantDomain, "coretech.storage", auditRef);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
    }
    
    private void verifyPolicies(String domainName) {
        
        List<String> names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        // this should be our own policy that we created previously
        Policy policy = zms.dbService.getPolicy(domainName, "vip_admin");
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        
        // The updated policy will have two assertions, one from the original, and the other from template application.
        // The original assertion is {    role: "solutiontemplate-withpolicy:role.role1",    action: "*",    effect: "ALLOW",    resource: "*"}
        // Newly added one is {    resource: "solutiontemplate-withpolicy:vip*",    role: "solutiontemplate-withpolicy:role.vip_admin",    action: "*"}
        assertEquals(2, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0); // this is the original assertion
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.role1", assertion.getRole());
        assertEquals("solutiontemplate-withpolicy:*", assertion.getResource());
        
        Assertion assertionAdded = policy.getAssertions().get(1); // this is the added assertion
        assertEquals("*", assertionAdded.getAction());
        assertEquals(domainName + ":role.vip_admin", assertionAdded.getRole());
        assertEquals("solutiontemplate-withpolicy:vip*", assertionAdded.getResource());
    }
    
    @Test
    public void testApplySolutionTemplateDomainExistingPolicies() {
        
        String caller = "testApplySolutionTemplateDomainExistingPolicies";
        String domainName = "solutiontemplate-withpolicy";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // we are going to create one of the policies that's also in
        // the template - this should not change
        
        Policy policy1 = createPolicyObject(domainName, "vip_admin");
        zms.putPolicy(mockDomRsrcCtx, domainName, "vip_admin", auditRef, policy1);
        
        // apply the template
        
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());
        
        // verify that our policy collections includes the policies defined in the template
        
        verifyPolicies(domainName);
        
        // Try applying the template again. This time, there should be no changes.
        
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        verifyPolicies(domainName);
        
        // the rest should be identical what's in the template
        
        Policy policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin");
        assertEquals(domainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        // remove the vipng template

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng", 
                auditRef, caller);
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove vipng again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng", 
                auditRef, caller);
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testApplySolutionTemplateMultipleTemplates() {
        
        String caller = "testApplySolutionTemplateMultipleTemplates";
        String domainName = "solutiontemplate-multi";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // apply the template
        
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the roles defined in template
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());
        
        // verify that our policy collections includes the policies defined in the template
        
        names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Policy policy = zms.dbService.getPolicy(domainName, "vip_admin");
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());
        
        policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin");
        assertEquals(domainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        // add another template
        templates = new ArrayList<>();
        templates.add("platforms");
        domainTemplate.setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(2, domainTemplateList.getTemplateNames().size());
        
        names = zms.dbService.listRoles(domainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        names = zms.dbService.listPolicies(domainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deploy"));

        // remove the vipng template
        
        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng",
                auditRef, caller);

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        names = zms.dbService.listRoles(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deployer"));

        names = zms.dbService.listPolicies(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deploy"));

        // remove the platforms template
        
        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "platforms",
                auditRef, caller);

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(0, domainTemplateList.getTemplateNames().size());
        
        names = zms.dbService.listRoles(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        names = zms.dbService.listPolicies(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    
    @Test
    public void testApplySolutionTemplateWithService() {
        
        String domainName = "solutiontemplate-service";
        String caller = "testApplySolutionTemplateDomainWithService";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // apply the template
        
        List<String> templates = new ArrayList<>();
        templates.add("templateWithService");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        // verify that our policy collections includes the policies defined in the template
        
        names = zms.dbService.listPolicies(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        
        //verify that our service collections includes the services defined in the template
        
        names = zms.dbService.listServiceIdentities(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("testService"));
        // Try applying the template again. This time, there should be no changes.
        
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        names = zms.dbService.listPolicies(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        
        // remove the templateWithService template

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "templateWithService", 
                auditRef, caller);
        
        assertNull(zms.dbService.getServiceIdentity(domainName, "testService", false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove templateWithService again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "templateWithService", 
                auditRef, caller);
        
        assertNull(zms.dbService.getServiceIdentity(domainName, "testService", false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testApplySolutionTemplateWithMultipleServices() {
        
        String domainName = "solutiontemplate-multiservice";
        String caller = "testApplySolutionTemplateWithMultipleServices";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // apply the template
        
        List<String> templates = new ArrayList<>();
        templates.add("templateWithMultipleServices");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        // verify that our policy collections includes the policies defined in the template
        
        names = zms.dbService.listPolicies(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        
        //verify that our service collections includes the services defined in the template
        
        names = zms.dbService.listServiceIdentities(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("testService"));
        assertTrue(names.contains("testService2"));
        // Try applying the template again. This time, there should be no changes.
        
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        names = zms.dbService.listPolicies(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        
        // remove the templateWithService template

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "templateWithMultipleServices", 
                auditRef, caller);
        
        assertNull(zms.dbService.getServiceIdentity(domainName, "testService", false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove templateWithService again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "templateWithMultipleServices", 
                auditRef, caller);
        
        assertNull(zms.dbService.getServiceIdentity(domainName, "testService", false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    
    @Test
    public void testApplySolutionTemplateWithServiceWithKey() {
        
        String domainName = "solutiontemplate-servicekey";
        String caller = "testApplySolutionTemplateWithServiceWithKey";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // apply the template
        
        List<String> templates = new ArrayList<>();
        templates.add("templateWithServiceWithKey");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        // verify that our policy collections includes the policies defined in the template
        
        names = zms.dbService.listPolicies(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        
        //verify that our service collections includes the services defined in the template
        
        names = zms.dbService.listServiceIdentities(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("testService3"));
        // Try applying the template again. This time, there should be no changes.
        
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        names = zms.dbService.listPolicies(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        
        //trying to check for the keys
        ServiceIdentity serviceIdentity = zms.dbService.getServiceIdentity(domainName, "testService3", false);
        assertEquals(1, serviceIdentity.getPublicKeys().size());
        assertEquals("0", serviceIdentity.getPublicKeys().get(0).getId());
        
        // remove the templateWithService template

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "templateWithServiceWithKey", 
                auditRef, caller);
        
        assertNull(zms.dbService.getServiceIdentity(domainName, "testService3", false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove templateWithService again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "templateWithServiceWithKey", 
                auditRef, caller);
        
        assertNull(zms.dbService.getServiceIdentity(domainName, "testService3", false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testApplySolutionTemplateEmptyDomain() {
        
        String domainName = "solutiontemplate-ok";
        String caller = "testApplySolutionTemplateDomainExistingPolicies";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // apply the template
        
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());
        
        // verify that our policy collections includes the policies defined in the template
        
        names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        // Try applying the template again. This time, there should be no changes.
        
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        // the rest should be identical what's in the template
        
        Policy policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin");
        assertEquals(domainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        // remove the vipng template

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng", 
                auditRef, caller);
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove vipng again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng", 
                auditRef, caller);
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testApplySolutionTemplateMultipleTimes() {
        
        String caller = "testApplySolutionTemplateMultipleTimes";
        String domainName = "solutiontemplate-multiple";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // apply the template
        
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        // apply the template again - nothing should change

        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());
        
        // verify that our policy collections includes the policies defined in the template
        
        names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Policy policy = zms.dbService.getPolicy(domainName, "vip_admin");
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());
        
        policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin");
        assertEquals(domainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());
        
        // remove the vipng template

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng", 
                auditRef, caller);
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testApplySolutionTemplateExistingRoles() {
        
        String caller = "testApplySolutionTemplateExistingRoles";
        String domainName = "solutiontemplate-withrole";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // we are going to create one of the roles that's also in
        // the template - this should not change
        
        Role role1 = createRoleObject(domainName, "vip_admin", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "vip_admin", auditRef, role1);
        
        // apply the template
        
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        // apply the template again - nothing should change

        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        // this should be our own role that we created previously
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertEquals(2, role.getRoleMembers().size());
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkRoleMember(checkList, role.getRoleMembers());
        
        // the rest should be whatever we had in the template
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());
        
        // the rest should be whatever we had in the template
        
        names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Policy policy = zms.dbService.getPolicy(domainName, "vip_admin");
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());
        
        policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin");
        assertEquals(domainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        // remove the vipng template

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng", 
                auditRef, caller);
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testSetupTenantAdminPolicy() {
        
        String caller = "testSetupTenantAdminPolicy";
        String tenantDomain = "tenantadminpolicy";
        String providerDomain = "coretech";
        String providerService = "storage";

        // create domain for tenant
        
        TopLevelDomain dom1 = createTopLevelDomainObject(tenantDomain,
                "Test Tenant Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        // create domain for provider
        
        TopLevelDomain domProv = createTopLevelDomainObject(providerDomain,
                "Test Provider Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, domProv);

        // create service identity for providerDomain.providerService
        
        ServiceIdentity service = createServiceObject(
                providerDomain, providerService, "http://localhost:8090/tableprovider",
                "/usr/bin/java", "root", "users", "localhost");

        zms.putServiceIdentity(mockDomRsrcCtx, providerDomain, providerService, auditRef, service);
        
        // let's create the tenant admin policy
        
        zms.dbService.setupTenantAdminPolicy(tenantDomain, providerDomain,
                providerService, auditRef, caller);
        
        // the admin policy must be called
        
        String policyName = "tenancy.coretech.storage.admin";
        Policy policy = zms.dbService.getPolicy(tenantDomain, policyName);
        assertNotNull(policy);

        List<Assertion> assertList = policy.getAssertions();
        assertNotNull(assertList);
        assertEquals(3, assertList.size());
        boolean domainAdminRoleCheck = false;
        boolean tenantAdminRoleCheck = false;
        boolean tenantUpdateCheck = false;
        for (Assertion obj : assertList) {
            assertEquals(AssertionEffect.ALLOW, obj.getEffect());
            if (obj.getRole().equals("tenantadminpolicy:role.admin")) {
                assertEquals(obj.getResource(), "coretech:role.storage.tenant.tenantadminpolicy.admin");
                assertEquals(obj.getAction(), "assume_role");
                domainAdminRoleCheck = true;
            } else if (obj.getRole().equals("tenantadminpolicy:role.tenancy.coretech.storage.admin")) {
                if (obj.getAction().equals("assume_role")) {
                    assertEquals(obj.getResource(), "coretech:role.storage.tenant.tenantadminpolicy.admin");
                    tenantAdminRoleCheck = true;
                } else if (obj.getAction().equals("update")) {
                    assertEquals("tenantadminpolicy:tenancy.coretech.storage", obj.getResource());
                    tenantUpdateCheck = true;
                }
            }
        }
        assertTrue(domainAdminRoleCheck);
        assertTrue(tenantAdminRoleCheck);
        assertTrue(tenantUpdateCheck);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
    }
    
    @Test
    public void testInvalidDBServiceConfig() {
    
        System.setProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_COUNT, "-100");
        System.setProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_SLEEP_TIME, "-1000");
        System.setProperty(ZMSConsts.ZMS_PROP_STORE_OP_TIMEOUT, "-100");

        ZMSConfig zmsConfig = new ZMSConfig();
        zmsConfig.setUserDomain("user");
        DBService dbService = new DBService(null, null, zmsConfig, null);
        assertEquals(120, dbService.defaultRetryCount);
        assertEquals(250, dbService.retrySleepTime);
        assertEquals(60, dbService.defaultOpTimeout);

        System.clearProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_COUNT);
        System.clearProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_SLEEP_TIME);
        System.clearProperty(ZMSConsts.ZMS_PROP_STORE_OP_TIMEOUT);
    }
    
    @Test
    public void testShouldRetryOperation() {
        
        FileObjectStore store = new FileObjectStore(new File("."), new File("."));
        ZMSConfig zmsConfig = new ZMSConfig();
        zmsConfig.setUserDomain("user");
        DBService dbService = new DBService(store, null, zmsConfig, null);
        
        // regardless of exception, count of 0 or 1 returns false
        
        assertFalse(dbService.shouldRetryOperation(null, 0));
        assertFalse(dbService.shouldRetryOperation(null, 1));

        // conflict returns true
        
        ResourceException exc = new ResourceException(ResourceException.CONFLICT, "unit-test");
        assertTrue(dbService.shouldRetryOperation(exc, 2));
        
        // gone - read/only mode returns true
        
        exc = new ResourceException(ResourceException.GONE, "unit-test");
        assertTrue(dbService.shouldRetryOperation(exc, 2));

        // all others return false
        
        exc = new ResourceException(ResourceException.BAD_REQUEST, "unit-test");
        assertFalse(dbService.shouldRetryOperation(exc, 2));

        exc = new ResourceException(ResourceException.FORBIDDEN, "unit-test");
        assertFalse(dbService.shouldRetryOperation(exc, 2));
        
        exc = new ResourceException(ResourceException.INTERNAL_SERVER_ERROR, "unit-test");
        assertFalse(dbService.shouldRetryOperation(exc, 2));
        
        exc = new ResourceException(ResourceException.NOT_FOUND, "unit-test");
        assertFalse(dbService.shouldRetryOperation(exc, 2));
    }
    
    @Test
    public void testLookupDomainByAccount() {
        
        String domainName = "lookupdomainaccount";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setAccount("1234");
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        DomainList list = zms.dbService.lookupDomainByAccount("1234");
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);

        list = zms.dbService.lookupDomainById("1234", 0);
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);
        
        list = zms.dbService.lookupDomainByAccount("1235");
        assertNull(list.getNames());

        list = zms.dbService.lookupDomainById("1235", 0);
        assertNull(list.getNames());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testLookupDomainByProductId() {
        
        String domainName = "lookupdomainbyproductid";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setYpmId(101);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        DomainList list = zms.dbService.lookupDomainByProductId(101);
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);

        list = zms.dbService.lookupDomainById(null, 101);
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);
        
        list = zms.dbService.lookupDomainByProductId(102);
        assertNull(list.getNames());

        list = zms.dbService.lookupDomainById(null, 102);
        assertNull(list.getNames());
        
        list = zms.dbService.lookupDomainByProductId(0);
        assertNull(list.getNames());
        
        list = zms.dbService.lookupDomainById(null, 0);
        assertNull(list.getNames());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testLookupDomainByRole() {
        
        String domainName = "lookupdomainrole";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setYpmId(199);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        DomainList list = zms.dbService.lookupDomainByRole(adminUser, "admin");
        assertNotNull(list.getNames());
        assertTrue(list.getNames().contains(domainName));

        List<String> doms = zms.dbService.listDomains(null, 0);
        
        // all domains have admin role
        
        list = zms.dbService.lookupDomainByRole(null, "admin");
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), doms.size());
        
        // null role/member gives us the full set
        
        list = zms.dbService.lookupDomainByRole(null, null);
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), doms.size());
        
        // unknown role and member in the system
        
        list = zms.dbService.lookupDomainByRole(adminUser, "unknown_role");
        assertEquals(list.getNames().size(), 0);
        
        list = zms.dbService.lookupDomainByRole("unkwown-user", "admin");
        assertEquals(list.getNames().size(), 0);
        
        // lets add a role for joe and jane
        
        Role role1 = createRoleObject(domainName, "list-role", null,
                "user.joe", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "list-role",
                role1, auditRef, "putRole");
        
        list = zms.dbService.lookupDomainByRole("user.joe", "list-role");
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);
        
        list = zms.dbService.lookupDomainByRole(adminUser, "list-role");
        assertEquals(list.getNames().size(), 0);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetPrincipalName() {
        
        Principal principal = SimplePrincipal.create("user", "user1", "creds", null);
        RsrcCtxWrapper rsrcCtx = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        assertEquals(zms.dbService.getPrincipalName(rsrcCtx), "user.user1");
        
        assertNull(zms.dbService.getPrincipalName(null));
        
        RsrcCtxWrapper rsrcCtx2 = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(rsrcCtx2.principal()).thenReturn(null);
        assertNull(zms.dbService.getPrincipalName(rsrcCtx2));
    }
    
    @Test
    public void testAuditLogPublicKeyEntry() {
        StringBuilder auditDetails = new StringBuilder();
        assertFalse(zms.dbService.auditLogPublicKeyEntry(auditDetails, "keyId", true));
        assertEquals("{\"id\": \"keyId\"}", auditDetails.toString());
        
        auditDetails.setLength(0);
        assertFalse(zms.dbService.auditLogPublicKeyEntry(auditDetails, "keyId", false));
        assertEquals(",{\"id\": \"keyId\"}", auditDetails.toString());
    }
    
    @Test
    public void testApplySolutionTemplateNullTemplate() {
        StringBuilder auditDetails = new StringBuilder();
        assertTrue(zms.dbService.addSolutionTemplate(null, null, "template1",
                null, null, null, auditDetails));
        assertEquals("{\"name\": \"template1\"}", auditDetails.toString());
        
        auditDetails.setLength(0);
        assertTrue(zms.dbService.deleteSolutionTemplate(null, null, "template1",
                null, auditDetails));
        assertEquals("{\"name\": \"template1\"}", auditDetails.toString());
    }

    @Test
    public void testIsTrustRole() {
        
        // null role
        assertFalse(zms.dbService.isTrustRole(null));
        
        // null trust
        Role role = new Role().setName("domain1:role.role1").setTrust(null);
        assertFalse(zms.dbService.isTrustRole(role));

        // empty trust
        role = new Role().setName("domain1:role.role1").setTrust("");
        assertFalse(zms.dbService.isTrustRole(role));
        
        // with trust
        role = new Role().setName("domain1:role.role1").setTrust("domain2");
        assertTrue(zms.dbService.isTrustRole(role));
    }
    
    @Test
    public void testGetDelegatedRoleNoExpand() {

        String domainName = "rolenoexpand";
        String roleName = "role1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, "sys.auth",
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);
        
        Role role = zms.dbService.getRole(domainName, roleName, false, false, false);
        assertNotNull(role);
        assertEquals(role.getTrust(), "sys.auth");
        assertNull(role.getRoleMembers());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetDelegatedRoleExpand() {

        String domainName1 = "role-expand1";
        String domainName2 = "role-expand2";

        String roleName = "role1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        Role role1 = createRoleObject(domainName1, roleName, domainName2,
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName1, roleName, auditRef, role1);
        
        Role role2a = createRoleObject(domainName2, "role2a", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2a", auditRef, role2a);
        
        Role role2b = createRoleObject(domainName2, "role2b", null,
                "user.joe", "user.doe");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2b", auditRef, role2b);
        
        Policy policy = createPolicyObject(domainName2, "policy",
                domainName2 + ":role.role2a", false, "assume_role", domainName1 + ":role." + roleName,
                AssertionEffect.ALLOW);
        
        Assertion assertion = new Assertion();
        assertion.setAction("assume_role");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role." + roleName);
        assertion.setRole(domainName2 + ":role.role2b");
        policy.getAssertions().add(assertion);
        zms.putPolicy(mockDomRsrcCtx, domainName2, "policy", auditRef, policy);
        
        Role role = zms.dbService.getRole(domainName1, roleName, false, true, false);
        assertNotNull(role);
        assertEquals(role.getTrust(), domainName2);
        List<RoleMember> members = role.getRoleMembers();
        assertEquals(3, members.size());
        
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkRoleMember(checkList, members);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName1, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName2, auditRef);
    }
    
    @Test
    public void testGetDelegatedRoleMembersInvalidDomain() {

        ObjectStoreConnection conn = zms.dbService.store.getConnection(true, false);
        assertNull(zms.dbService.getDelegatedRoleMembers(conn, "dom1", "dom1", "role1"));
        assertNull(zms.dbService.getDelegatedRoleMembers(conn, "dom1", "invalid-domain", "role1"));
    }
    
    @Test
    public void testGetDelegatedRoleMembers() {

        String domainName1 = "role-expand1";
        String domainName2 = "role-expand2";

        String roleName = "role1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        Role role1 = createRoleObject(domainName1, roleName, domainName2,
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName1, roleName, auditRef, role1);
        
        Role role2a = createRoleObject(domainName2, "role2a", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2a", auditRef, role2a);
        
        Role role2b = createRoleObject(domainName2, "role2b", null,
                "user.joe", "user.doe");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2b", auditRef, role2b);
        
        Role role2c = createRoleObject(domainName2, "role2c", "sys.auth",
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName2, "role2c", auditRef, role2c);
        
        Role role2d = createRoleObject(domainName2, "role2d", null,
                "user.user1", "user.user2");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2d", auditRef, role2d);
        
        Role role2e = createRoleObject(domainName2, "role2e", null,
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName2, "role2e", auditRef, role2e);
        
        Policy policy = createPolicyObject(domainName2, "policy",
                domainName2 + ":role.role2a", false, "assume_role", domainName1 + ":role." + roleName,
                AssertionEffect.ALLOW);
        
        Assertion assertion = new Assertion();
        assertion.setAction("assume_role");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role." + roleName);
        assertion.setRole(domainName2 + ":role.role2b");
        policy.getAssertions().add(assertion);
        zms.putPolicy(mockDomRsrcCtx, domainName2, "policy", auditRef, policy);
        
        policy = new Policy().setName(domainName2 + ":policy.policy2");
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName2, "policy2", policy, auditRef, "putPolicy");

        ObjectStoreConnection conn = zms.dbService.store.getConnection(true, false);
        List<RoleMember> members = zms.dbService.getDelegatedRoleMembers(conn, domainName1, domainName2, roleName);
        assertEquals(3, members.size());
        
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkRoleMember(checkList, members);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName1, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName2, auditRef);
    }
    
    @Test
    public void testGetPublicKeyFromCache() {
        
        final String domainName1 = "getcachepublickey";
        final String domainName2 = "getcachepublickey2";
        AthenzDomain athenzDomain1 = new AthenzDomain(domainName1);
        
        ServiceIdentity service1 = createServiceObject(domainName1,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        
        ServiceIdentity service2 = createServiceObject(domainName1,
                "service2", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        
        ServiceIdentity service3 = new ServiceIdentity();
        service3.setName(ZMSUtils.serviceResourceName(domainName1, "service3"));
        
        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service1);
        services.add(service2);
        services.add(service3);
        athenzDomain1.setServices(services);
        DataCache dataCache1 = new DataCache(athenzDomain1, 101);

        AthenzDomain athenzDomain2 = new AthenzDomain(domainName2);
        DataCache dataCache2 = new DataCache(athenzDomain2, 101);

        zms.dbService.cacheStore.put(domainName1, dataCache1);
        zms.dbService.cacheStore.put(domainName2, dataCache2);
        
        PublicKeyEntry key = zms.dbService.getPublicKeyFromCache(domainName1, "service1", "1");
        assertNotNull(key);
        
        key = zms.dbService.getPublicKeyFromCache(domainName1, "service1", "2");
        assertNotNull(key);

        key = zms.dbService.getPublicKeyFromCache(domainName1, "service2", "1");
        assertNotNull(key);
        
        key = zms.dbService.getPublicKeyFromCache(domainName1, "service2", "2");
        assertNotNull(key);
        
        key = zms.dbService.getPublicKeyFromCache(domainName1, "service1", "3");
        assertNull(key);
        
        key = zms.dbService.getPublicKeyFromCache(domainName1, "service2", "3");
        assertNull(key);
        
        key = zms.dbService.getPublicKeyFromCache(domainName1, "service3", "1");
        assertNull(key);
        
        key = zms.dbService.getPublicKeyFromCache(domainName1, "service4", "1");
        assertNull(key);
        
        key = zms.dbService.getPublicKeyFromCache(domainName1, "service5", "2");
        assertNull(key);
        
        key = zms.dbService.getPublicKeyFromCache(domainName2, "service1", "1");
        assertNull(key);
        
        key = zms.dbService.getPublicKeyFromCache(domainName2, "service2", "1");
        assertNull(key);
    }
    
    @Test
    public void testListPrincipalsUsersOnly() {
        
        String domainName = "listusers1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("listusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        TopLevelDomain dom3 = createTopLevelDomainObject("listuserweather",
                "Test Domain3", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom3);
        
        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, role1);
        
        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "listusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "listuserweather.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, role3);
        
        Role role4 = createRoleObject("listusersports", "role4", null,
                "user.ana", "user.janie");
        zms.putRole(mockDomRsrcCtx, "listusersports", "role4", auditRef, role4);
        
        List<String> users = zms.dbService.listPrincipals("user", true);
        assertEquals(users.size(), 5);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.joe"));
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listusersports", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listuserweather", auditRef);
    }
    
    @Test
    public void testListPrincipalsAll() {
        
        String domainName = "listusers1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("listusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        TopLevelDomain dom3 = createTopLevelDomainObject("listuserweather",
                "Test Domain3", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom3);
        
        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, role1);
        
        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "listusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "listuserweather.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, role3);
        
        Role role4 = createRoleObject("listusersports", "role4", null,
                "user.ana", "user.janie");
        zms.putRole(mockDomRsrcCtx, "listusersports", "role4", auditRef, role4);
        
        Role role5 = createRoleObject("listusersports", "role5", null,
                null, null);
        zms.putRole(mockDomRsrcCtx, "listusersports", "role5", auditRef, role5);
        
        List<String> users = zms.dbService.listPrincipals(null, false);
        assertEquals(users.size(), 7);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.joe"));
        assertTrue(users.contains("listusersports.jane"));
        assertTrue(users.contains("listuserweather.jane"));
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listusersports", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listuserweather", auditRef);
    }
    
    @Test
    public void testListPrincipalsSubdomains() {
        
        String domainName = "listusers1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("listusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("api", "listusersports",
                "Test SubDomain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "listusersports", auditRef, subDom2);
        
        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, role1);
        
        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "listusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, role2);
        
        Role role3 = createRoleObject("listusersports", "role3", null,
                "user.ana", "listusersports.api.service");
        zms.putRole(mockDomRsrcCtx, "listusersports", "role3", auditRef, role3);
        
        List<String> users = zms.dbService.listPrincipals(null, false);
        assertEquals(users.size(), 6);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.joe"));
        assertTrue(users.contains("listusersports.jane"));
        assertTrue(users.contains("listusersports.api.service"));
        
        users = zms.dbService.listPrincipals(null, true);
        assertEquals(users.size(), 5);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.joe"));
        assertTrue(users.contains("listusersports.jane"));
        
        users = zms.dbService.listPrincipals("listusersports", false);
        assertEquals(users.size(), 2);
        assertTrue(users.contains("listusersports.jane"));
        assertTrue(users.contains("listusersports.api.service"));
        
        assertTrue(users.contains("listusersports.jane"));
        
        users = zms.dbService.listPrincipals("listusersports", true);
        assertEquals(users.size(), 1);
        assertTrue(users.contains("listusersports.jane"));
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "listusersports", "api", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listusersports", auditRef);
    }
    
    @Test
    public void testExecuteDeleteUser() {
        
        String domainName = "deleteuser1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("deleteusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        TopLevelDomain dom3 = createTopLevelDomainObject("deleteuserweather",
                "Test Domain3", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom3);
        
        SubDomain subDom1 = createSubDomainObject("jack", "user",
                "Test SubDomain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "user", auditRef, subDom1);
        
        SubDomain subDom2 = createSubDomainObject("jane", "user",
                "Test SubDomain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "user", auditRef, subDom2);
        
        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, role1);
        
        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "deleteusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "deleteuserweather.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, role3);
        
        Role role4 = createRoleObject("deleteusersports", "role4", null,
                "user.ana", "user.janie");
        zms.putRole(mockDomRsrcCtx, "deleteusersports", "role4", auditRef, role4);
        
        Role role5 = createRoleObject("deleteusersports", "role5", null,
                "user.jack.service", "user.jane.storage");
        zms.putRole(mockDomRsrcCtx, "deleteusersports", "role5", auditRef, role5);
        
        List<String> users = zms.dbService.listPrincipals("user", true);
        assertEquals(users.size(), 5);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.joe"));
        
        zms.dbService.executeDeleteUser(mockDomRsrcCtx, "user.jack", "user.jack", auditRef, "testExecuteDeleteUser");
        
        users = zms.dbService.listPrincipals("user", true);
        assertEquals(users.size(), 4);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.joe"));
        assertFalse(users.contains("user.jack"));
        
        Role testRole = zms.dbService.getRole("deleteusersports", "role5", false, false, false);
        assertEquals(testRole.getRoleMembers().size(), 1);
        RoleMember roleMember = testRole.getRoleMembers().get(0);
        assertEquals(roleMember.getMemberName(), "user.jane.storage");
        
        try {
            zms.getDomain(mockDomRsrcCtx, "user.jack");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user", "jane", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "deleteusersports", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "deleteuserweather", auditRef);
    }
    
    @Test
    public void testExecuteDeleteUserSubdomains() {
        
        String domainName = "deleteuser1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("deleteusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom1 = createSubDomainObject("jack", "user",
                "Test SubDomain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "user", auditRef, subDom1);
        
        SubDomain subDom2 = createSubDomainObject("sub1", "user.jack",
                "Test SubDomain21", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "user.jack", auditRef, subDom2);
        
        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.jack.sub1.service");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, role1);
        
        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "deleteusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "user.jack.sub1.api");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, role3);
        
        List<String> users = zms.dbService.listPrincipals("user", false);
        assertEquals(users.size(), 5);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.jack.sub1.service"));
        assertTrue(users.contains("user.jack.sub1.api"));
        assertTrue(users.contains("user.joe"));
        
        zms.dbService.executeDeleteUser(mockDomRsrcCtx, "user.jack", "user.jack", auditRef, "testExecuteDeleteUser");
        
        users = zms.dbService.listPrincipals("user", false);
        assertEquals(users.size(), 2);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.joe"));
        
        try {
            zms.getDomain(mockDomRsrcCtx, "user.jack");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        
        try {
            zms.getDomain(mockDomRsrcCtx, "user.jack.sub1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "deleteusersports", auditRef);
    }

    @Test
    public void testExecuteDeleteDomainRoleMember() {

        String domainName = "deletedomainrolemember1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, "role1", null,
                "user.jack", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, role1);

        Role role2 = createRoleObject(domainName, "role2", null,
                "user.janie", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, role3);

        Role role4 = createRoleObject(domainName, "role4", null,
                "user.jack", null);
        zms.putRole(mockDomRsrcCtx, domainName, "role4", auditRef, role4);

        Role role5 = createRoleObject(domainName, "role5", null,
                "user.jack-service", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role5", auditRef, role5);

        DomainRoleMembers domainRoleMembers = zms.getDomainRoleMembers(mockDomRsrcCtx, domainName);
        assertEquals(domainName, domainRoleMembers.getDomainName());

        List<DomainRoleMember> members = domainRoleMembers.getMembers();
        assertNotNull(members);
        assertEquals(5, members.size());
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack", "role1", "role3", "role4");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.janie", "role1", "role2");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jane", "role2", "role3", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack-service", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, adminUser, "admin");

        // this should be no-op with unknown user

        zms.dbService.executeDeleteDomainRoleMember(mockDomRsrcCtx, domainName, "user.unknown", auditRef,
                "testExecuteDeleteDomainRoleMember");

        domainRoleMembers = zms.getDomainRoleMembers(mockDomRsrcCtx, domainName);
        members = domainRoleMembers.getMembers();
        assertNotNull(members);
        assertEquals(5, members.size());
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack", "role1", "role3", "role4");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.janie", "role1", "role2");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jane", "role2", "role3", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack-service", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, adminUser, "admin");

        // now remove a known user

        zms.dbService.executeDeleteDomainRoleMember(mockDomRsrcCtx, domainName, "user.jack", auditRef,
                "testExecuteDeleteDomainRoleMember");

        domainRoleMembers = zms.getDomainRoleMembers(mockDomRsrcCtx, domainName);
        assertEquals(domainName, domainRoleMembers.getDomainName());

        members = domainRoleMembers.getMembers();
        assertNotNull(members);
        assertEquals(4, members.size());
        ZMSTestUtils.verifyDomainRoleMember(members, "user.janie", "role1", "role2");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jane", "role2", "role3", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack-service", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, adminUser, "admin");

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecuteDeleteDomainRoleMemberRetryException() {

        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.listPrincipalRoles("dom1", "user.joe"))
                .thenThrow(new ResourceException(410));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 3;

        try {
            zms.dbService.executeDeleteDomainRoleMember(mockDomRsrcCtx, "dom1", "user.joe", adminUser, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(410, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testRemovePrincipalFromDomainRolesExceptions() {

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.listPrincipalRoles("dom1", "user.joe"))
                .thenThrow(new ResourceException(404))
                .thenThrow(new ResourceException(501));

        // handle exceptions accordingly

        try {
            zms.dbService.removePrincipalFromDomainRoles(conn, "dom1", "user.joe", adminUser, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }

        try {
            zms.dbService.removePrincipalFromDomainRoles(conn, "dom1", "user.joe", adminUser, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(501, ex.getCode());
        }
    }

    @Test
    public void testRemovePrincipalFromDomainRolesDeleteUserException() {

        List<PrincipalRole> roles = new ArrayList<>();
        PrincipalRole role1 = new PrincipalRole();
        role1.setDomainName("dom1");
        role1.setRoleName("role1");
        roles.add(role1);
        PrincipalRole role2 = new PrincipalRole();
        role2.setDomainName("dom1");
        role2.setRoleName("role2");
        roles.add(role2);

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.listPrincipalRoles("dom1", "user.joe")).thenReturn(roles);
        Mockito.when(conn.deleteRoleMember("dom1", "role1", "user.joe", adminUser, "unittest"))
                .thenReturn(true);
        Mockito.when(conn.deleteRoleMember("dom1", "role2", "user.joe", adminUser, "unittest"))
                .thenThrow(new ResourceException(501));

        // we should handle the exception without any errors

        zms.dbService.removePrincipalFromDomainRoles(conn, "dom1", "user.joe", adminUser, "unittest");
    }

    @Test
    public void testRemovePrincipalFromAllRolesExceptions() {

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.listPrincipalRoles(null, "user.joe"))
                .thenThrow(new ResourceException(404))
                .thenThrow(new ResourceException(501));

        // no exception if store returns 404

        zms.dbService.removePrincipalFromAllRoles(conn, "user.joe", adminUser, "unittest");

        // with next we should throw the exception so we should catch it

        try {
            zms.dbService.removePrincipalFromAllRoles(conn, "user.joe", adminUser, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(501, ex.getCode());
        }
    }

    @Test
    public void testExecuteDeleteUserRetryException() {

        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.listDomains("home.joe.", 0))
                .thenThrow(new ResourceException(409));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 3;

        try {
            zms.dbService.executeDeleteUser(mockDomRsrcCtx, "joe", "home.joe", adminUser, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(409, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testRemovePrincipalFromAllRolesDeleteUserException() {

        List<PrincipalRole> roles = new ArrayList<>();
        PrincipalRole role1 = new PrincipalRole();
        role1.setDomainName("dom1");
        role1.setRoleName("role1");
        roles.add(role1);
        PrincipalRole role2 = new PrincipalRole();
        role2.setDomainName("dom1");
        role2.setRoleName("role2");
        roles.add(role2);

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.listPrincipalRoles(null, "user.joe")).thenReturn(roles);
        Mockito.when(conn.deleteRoleMember("dom1", "role1", "user.joe", adminUser, "unittest"))
                .thenReturn(true);
        Mockito.when(conn.deleteRoleMember("dom1", "role2", "user.joe", adminUser, "unittest"))
                .thenThrow(new ResourceException(501));

        // we should handle the exception without any errors

        zms.dbService.removePrincipalFromAllRoles(conn, "user.joe", adminUser, "unittest");
    }

    @Test
    public void testExecutePutQuotaFailureRetry() {

        String domainName = "putquota";

        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Quota quota = new Quota();
        Mockito.when(mockFileConn.insertQuota(domainName, quota))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutQuota(mockDomRsrcCtx, domainName, quota,
                    auditRef, "putQuota");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteQuotaFailureRetry() {

        String domainName = "putquota";

        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.deleteQuota(domainName))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeleteQuota(mockDomRsrcCtx, domainName, auditRef, "deleteQuota");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutQuotaInsert() {

        String domainName = "executeputquotainsert";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Quota quota = new Quota().setName(domainName)
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);
        
        zms.dbService.executePutQuota(mockDomRsrcCtx, domainName, quota,
                auditRef, "testExecutePutQuotaInsert");

        // now retrieve the quota using zms interface
        
        Quota quotaCheck = zms.getQuota(mockDomRsrcCtx, domainName);
        assertNotNull(quotaCheck);
        assertEquals(quotaCheck.getAssertion(), 10);
        assertEquals(quotaCheck.getRole(), 14);
        assertEquals(quotaCheck.getPolicy(), 12);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecutePutQuotaUpdate() {

        String domainName = "executeputquotaupdate";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Quota quota = new Quota().setName(domainName)
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);
        
        zms.dbService.executePutQuota(mockDomRsrcCtx, domainName, quota,
                auditRef, "testExecutePutQuotaUpdate");

        // now update the quota and apply the change again
        
        quota.setAssertion(100);
        quota.setRole(104);
        
        zms.dbService.executePutQuota(mockDomRsrcCtx, domainName, quota,
                auditRef, "testExecutePutQuotaUpdate");
        
        // now retrieve the quota using zms interface
        
        Quota quotaCheck = zms.getQuota(mockDomRsrcCtx, domainName);
        assertNotNull(quotaCheck);
        assertEquals(quotaCheck.getAssertion(), 100);
        assertEquals(quotaCheck.getRole(), 104);
        assertEquals(quotaCheck.getPolicy(), 12);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecuteDeleteQuota() {

        String domainName = "executedeletequota";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Quota quota = new Quota().setName(domainName)
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);
        
        zms.dbService.executePutQuota(mockDomRsrcCtx, domainName, quota,
                auditRef, "testExecuteDeleteQuota");

        Quota quotaCheck = zms.getQuota(mockDomRsrcCtx, domainName);
        assertNotNull(quotaCheck);
        assertEquals(domainName, quotaCheck.getName());
        assertEquals(quotaCheck.getAssertion(), 10);
        assertEquals(quotaCheck.getRole(), 14);
        assertEquals(quotaCheck.getPolicy(), 12);
        
        // now delete the quota
        
        zms.dbService.executeDeleteQuota(mockDomRsrcCtx, domainName, auditRef,
                "testExecuteDeleteQuota");
        
        // now we'll get the default quota
        
        quotaCheck = zms.getQuota(mockDomRsrcCtx, domainName);

        assertEquals("server-default", quotaCheck.getName());
        assertEquals(quotaCheck.getAssertion(), 100);
        assertEquals(quotaCheck.getRole(), 1000);
        assertEquals(quotaCheck.getPolicy(), 1000);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testExecuteDeleteQuotaException() {

        String domainName = "executedeletequotaexception";
        
        // delete the quota for nonexistent domain
        
        try {
            zms.dbService.executeDeleteQuota(mockDomRsrcCtx, domainName, auditRef,
                    "testExecuteDeleteQuota");
            fail();
        } catch (ResourceException ignored) {
        }
    }
    
    @Test
    public void testValidResourceToDelete() {
        assertFalse(zms.dbService.validResourceGroupObjectToDelete("role.name", "roles."));
        assertFalse(zms.dbService.validResourceGroupObjectToDelete("role.name", "role.name."));
        assertFalse(zms.dbService.validResourceGroupObjectToDelete("role.name.test.name", "role.name."));
        assertTrue(zms.dbService.validResourceGroupObjectToDelete("role.name.test", "role.name."));
    }

    @Test
    public void testUpdateSystemMetaFields() {

        Domain domain = new Domain();
        DomainMeta meta = new DomainMeta()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud");
        zms.dbService.updateSystemMetaFields(domain, "account", true, meta);
        assertEquals(domain.getAccount(), "acct");
        zms.dbService.updateSystemMetaFields(domain, "productid", true, meta);
        assertEquals(domain.getYpmId().intValue(), 1234);
        zms.dbService.updateSystemMetaFields(domain, "certdnsdomain", true, meta);
        assertEquals(domain.getCertDnsDomain(), "athenz.cloud");
        try {
            zms.dbService.updateSystemMetaFields(domain, "unknown", true, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // test setting from null to valid values with no delete set

        Domain domain1 = new Domain();
        DomainMeta meta1 = new DomainMeta()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud");
        zms.dbService.updateSystemMetaFields(domain1, "account", false, meta1);
        assertEquals(domain1.getAccount(), "acct");
        zms.dbService.updateSystemMetaFields(domain1, "productid", false, meta1);
        assertEquals(domain1.getYpmId().intValue(), 1234);
        zms.dbService.updateSystemMetaFields(domain1, "certdnsdomain", false, meta1);
        assertEquals(domain1.getCertDnsDomain(), "athenz.cloud");

        // setting from set values should be all rejected

        Domain domain2 = new Domain()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud");
        DomainMeta meta2 = new DomainMeta()
                .setAccount("acct-new")
                .setYpmId(1235)
                .setCertDnsDomain("athenz.cloud.new");

        // setting from the old value to new value with
        // no delete flag should be rejected

        try {
            zms.dbService.updateSystemMetaFields(domain2, "account", false, meta2);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("reset system meta attribute"));
        }

        try {
            zms.dbService.updateSystemMetaFields(domain2, "productid", false, meta2);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("reset system meta attribute"));
        }

        try {
            zms.dbService.updateSystemMetaFields(domain2, "certdnsdomain", false, meta2);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("reset system meta attribute"));
        }

        // setting from set value to the same value should be allowed

        Domain domain3 = new Domain()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud");
        DomainMeta meta3 = new DomainMeta()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud");
        zms.dbService.updateSystemMetaFields(domain3, "account", false, meta3);
        assertEquals(domain3.getAccount(), "acct");
        zms.dbService.updateSystemMetaFields(domain3, "productid", false, meta3);
        assertEquals(domain3.getYpmId().intValue(), 1234);
        zms.dbService.updateSystemMetaFields(domain3, "certdnsdomain", false, meta3);
        assertEquals(domain3.getCertDnsDomain(), "athenz.cloud");
    }

    @Test
    public void testDeleteSystemMetaAllowed() {

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, null, null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, null, "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, null, ""));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "old", null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "old", "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "old", ""));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "", null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "", "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "", ""));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, null, null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, null, "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, null, ""));

        assertFalse(zms.dbService.isDeleteSystemMetaAllowed(false, "old", null));
        assertFalse(zms.dbService.isDeleteSystemMetaAllowed(false, "old", "new"));
        assertFalse(zms.dbService.isDeleteSystemMetaAllowed(false, "old", ""));

        assertFalse(zms.dbService.isDeleteSystemMetaAllowed(false, "", null));
        assertFalse(zms.dbService.isDeleteSystemMetaAllowed(false, "", "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, "", ""));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, "test", "test"));
    }

    @Test
    public void testUpdateRoleSystemMetaFields() {
        Role role = new Role();
        RoleSystemMeta meta = new RoleSystemMeta()
                .setAuditEnabled(true);
        zms.dbService.updateRoleSystemMetaFields(role, "auditenabled", true, meta);
        assertTrue(role.getAuditEnabled());
        try {
            zms.dbService.updateRoleSystemMetaFields(role, "unknown", true, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testUpdateServiceIdentitySystemMetaFields() {
        ServiceIdentity service = new ServiceIdentity();
        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta()
                .setProviderEndpoint("https://localhost");
        zms.dbService.updateServiceIdentitySystemMetaFields(service, "providerendpoint", true, meta);
        assertEquals(service.getProviderEndpoint(), "https://localhost");
        try {
            zms.dbService.updateServiceIdentitySystemMetaFields(service, "unknown", true, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testAuditLogRoleSystemMeta() {
        StringBuilder auditDetails = new StringBuilder();
        Role role = new Role().setName("dom1:role.role1").setAuditEnabled(true);
        zms.dbService.auditLogRoleSystemMeta(auditDetails, role, "role1");
        assertEquals("{\"name\": \"role1\", \"auditEnabled\": \"true\"}", auditDetails.toString());
    }

    @Test
    public void testExecutePutRoleSystemMeta() {

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject("MetaDom1", "test desc", "testOrg", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role = createRoleObject("MetaDom1", "MetaRole1", null, "user.john", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, "MetaDom1", "MetaRole1", role, "test", "putrole");

        RoleSystemMeta rsm = new RoleSystemMeta();
        rsm.setAuditEnabled(true);

        try {
            zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, "MetaDom1", "MetaRole1",
                    rsm,"auditenabled", true, auditRef, "putrolesystemmeta");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, "MetaDom1", auditRef, "deletedomain");

        Domain dom2 = new Domain()
                .setName("MetaDom2")
                .setAuditEnabled(true)
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud");


        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject("MetaDom2", "test desc", "testOrg", true,
                "", 1234, "", 0), admins, null, auditRef);
        DomainMeta meta2 = new DomainMeta()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud");
        zms.dbService.updateSystemMetaFields(dom2, "auditenabled", false, meta2);
        Role role2 = createRoleObject("MetaDom2", "MetaRole2", null, "user.john", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, "MetaDom2", "MetaRole2",role2, "test", "putrole");
        RoleSystemMeta rsm2 = new RoleSystemMeta();
        rsm2.setAuditEnabled(true);
        zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, "MetaDom2", "MetaRole2",
                rsm2,"auditenabled", true, auditRef, "putrolesystemmeta");
        Role resRole2 = zms.dbService.getRole("MetaDom2", "MetaRole2", false, true, false);

        assertTrue(resRole2.getAuditEnabled());

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, "MetaDom2", auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleSystemMetaRetry() {

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject("MetaDom1", "test desc", "testOrg", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role = createRoleObject("MetaDom1", "MetaRole1", null, "user.john", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, "MetaDom1", "MetaRole1", role, "test", "putrole");

        RoleSystemMeta rsm = new RoleSystemMeta();
        rsm.setAuditEnabled(true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        zms.dbService.defaultRetryCount = 2;
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockFileConn);
        ResourceException rex = new ResourceException(409);
        Domain d = new Domain().setName("MetaDom1").setAuditEnabled(true);
        Mockito.when(mockFileConn.getDomain(anyString())).thenReturn(d);
        Mockito.when(mockFileConn.getRole(anyString(), anyString())).thenReturn(role);
        Mockito.when(mockFileConn.updateRole(anyString(), any(Role.class))).thenThrow(rex);

        try {
            zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, "MetaDom1", "MetaRole1", rsm,
                    "auditenabled", true, auditRef, "putrolesystemmeta");
            fail();
        }catch (ResourceException r) {
            assertEquals(r.getCode(), 409);
            assertTrue(r.getMessage().contains("Conflict"));
        }
        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = 120;

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, "MetaDom1", auditRef, "deletedomain");
    }

    @Test
    public void testProcessRoleInsert() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Role role = new Role().setName("newRole").setAuditEnabled(true).setSelfServe(true);
        StringBuilder auditDetails = new StringBuilder("testAudit");
        zms.dbService.processRole(conn, null, "auditedDomain", "testRole1",
                role, adminUser, auditRef, false, auditDetails);
        assertFalse(role.getAuditEnabled());
        assertTrue(role.getSelfServe());
    }

    @Test
    public void testProcessRoleUpdate() {

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Role originalRole = new Role().setName("originalRole").setAuditEnabled(false);
        Role role = new Role().setName("newRole").setAuditEnabled(true);
        StringBuilder auditDetails = new StringBuilder("testAudit");
        zms.dbService.processRole(conn, originalRole, "auditedDomain", "newRole",
                role, adminUser, auditRef, false, auditDetails);
        assertFalse(role.getAuditEnabled()); // original role does not have auditEnabled

        originalRole.setAuditEnabled(true);
        Role role2 = new Role().setName("newRole2").setAuditEnabled(false);
        zms.dbService.processRole(conn, originalRole, "auditedDomain", "newRole2",
                role2, adminUser, auditRef, false, auditDetails);
        assertTrue(role2.getAuditEnabled()); // original role has auditEnabled

        Role role3 = new Role().setName("newRole3").setAuditEnabled(false).setSelfServe(true);
        zms.dbService.processRole(conn, originalRole, "auditedDomain", "newRole3",
                role3, adminUser, auditRef, false, auditDetails);
        assertTrue(role3.getSelfServe());

        Role role4 = new Role().setName("newRole4").setAuditEnabled(false).setSelfServe(false);
        zms.dbService.processRole(conn, originalRole, "auditedDomain", "newRole4",
                role4, adminUser, auditRef, false, auditDetails);
        assertFalse(role4.getSelfServe());
    }

    @Test
    public void testUpdateRoleMetaFields() {
        Role role = new Role();
        RoleMeta meta = new RoleMeta().setSelfServe(true)
                .setReviewEnabled(true).setNotifyRoles("role1");
        zms.dbService.updateRoleMetaFields(role, meta);
        assertTrue(role.getSelfServe());
        assertTrue(role.getReviewEnabled());
        assertEquals(role.getNotifyRoles(), "role1");

        meta = new RoleMeta().setReviewEnabled(false);
        zms.dbService.updateRoleMetaFields(role, meta);

        assertTrue(role.getSelfServe());
        assertFalse(role.getReviewEnabled());
        assertEquals(role.getNotifyRoles(), "role1");

        meta = new RoleMeta().setNotifyRoles("role2");
        zms.dbService.updateRoleMetaFields(role, meta);

        assertTrue(role.getSelfServe());
        assertFalse(role.getReviewEnabled());
        assertEquals(role.getNotifyRoles(), "role2");
    }

    @Test
    public void testAuditLogRoleMeta() {
        StringBuilder auditDetails = new StringBuilder();
        Role role = new Role().setName("dom1:role.role1").setSelfServe(true).setReviewEnabled(false);
        zms.dbService.auditLogRoleMeta(auditDetails, role, "role1");
        assertEquals("{\"name\": \"role1\", \"selfServe\": \"true\", \"memberExpiryDays\": \"null\","
                + " \"serviceExpiryDays\": \"null\", \"tokenExpiryMins\": \"null\","
                + " \"certExpiryMins\": \"null\", \"reviewEnabled\": \"false\","
                + " \"notifyRoles\": \"null\"}", auditDetails.toString());
    }

    @Test
    public void testExecutePutRoleMeta() {

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject("MetaDom1", "test desc", "testOrg", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role = createRoleObject("MetaDom1", "MetaRole1", null, "user.john", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, "MetaDom1", "MetaRole1", role, "test", "putrole");

        RoleMeta rm = new RoleMeta();
        rm.setSelfServe(true);

        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, "MetaDom1", "MetaRole1",
                rm, auditRef, "putrolemeta");

        Role resRole1 = zms.dbService.getRole("MetaDom1", "MetaRole1", false, true, false);
        assertTrue(resRole1.getSelfServe());

        rm = new RoleMeta();
        rm.setSelfServe(true);
        rm.setMemberExpiryDays(10);
        rm.setServiceExpiryDays(15);
        rm.setTokenExpiryMins(20);
        rm.setReviewEnabled(true);
        rm.setNotifyRoles("role1,role2");

        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, "MetaDom1", "MetaRole1",
                rm, auditRef, "putrolemeta");
        resRole1 = zms.dbService.getRole("MetaDom1", "MetaRole1", false, true, false);
        assertTrue(resRole1.getSelfServe());
        assertNull(resRole1.getCertExpiryMins());
        assertEquals(resRole1.getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(resRole1.getServiceExpiryDays(), Integer.valueOf(15));
        assertEquals(resRole1.getTokenExpiryMins(), Integer.valueOf(20));
        assertTrue(resRole1.getReviewEnabled());
        assertEquals(resRole1.getNotifyRoles(), "role1,role2");

        rm = new RoleMeta();
        rm.setSelfServe(false);
        rm.setCertExpiryMins(10);
        rm.setTokenExpiryMins(25);
        rm.setServiceExpiryDays(15);
        rm.setSignAlgorithm("rsa");
        rm.setReviewEnabled(false);

        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, "MetaDom1", "MetaRole1",
                rm, auditRef, "putrolemeta");
        resRole1 = zms.dbService.getRole("MetaDom1", "MetaRole1", false, true, false);
        assertFalse(resRole1.getSelfServe());
        assertEquals(resRole1.getCertExpiryMins(), Integer.valueOf(10));
        assertEquals(resRole1.getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(resRole1.getServiceExpiryDays(), Integer.valueOf(15));
        assertEquals(resRole1.getTokenExpiryMins(), Integer.valueOf(25));
        assertEquals(resRole1.getSignAlgorithm(), "rsa");
        assertFalse(resRole1.getReviewEnabled());
        assertEquals(resRole1.getNotifyRoles(), "role1,role2");

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, "MetaDom1", auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleMetaRetry() {

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject("MetaDom1", "test desc", "testOrg", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role = createRoleObject("MetaDom1", "MetaRole1", null, "user.john", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, "MetaDom1", "MetaRole1", role, "test", "putrole");

        RoleMeta rm = new RoleMeta();
        rm.setSelfServe(true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        zms.dbService.defaultRetryCount = 2;
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockFileConn);
        ResourceException rex = new ResourceException(409);
        Mockito.when(mockFileConn.getRole(anyString(), anyString())).thenReturn(role);
        Mockito.when(mockFileConn.updateRole(anyString(), any(Role.class))).thenThrow(rex);

        try {
            zms.dbService.executePutRoleMeta(mockDomRsrcCtx, "MetaDom1", "MetaRole1", rm, auditRef, "putrolemeta");
            fail();
        }catch (ResourceException r) {
            assertEquals(r.getCode(), 409);
            assertTrue(r.getMessage().contains("Conflict"));
        }
        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = 120;
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, "MetaDom1", auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleMetaFail() {

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);
        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject("MetaDom1", "test desc", "testOrg", false,
                "", 1234, "", 0), admins, null, auditRef);

        RoleMeta rm = new RoleMeta();
        rm.setSelfServe(true);
        try {
            zms.dbService.executePutRoleMeta(mockDomRsrcCtx, "MetaDom1", "MetaRole1",
                    rm, auditRef, "putrolemeta");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, "MetaDom1", auditRef, "deletedomain");
    }

    @Test
    public void testCheckRoleAuditEnabledFlagTrueRefNull() {

        String domainName = "audit-test-domain-name";
        String roleName = "testrole";
        Role role = new Role().setAuditEnabled(true);
        Mockito.doReturn(role).when(mockFileConn).getRole(domainName, roleName);

        String caller = "testCheckRoleAuditEnabledFlagTrueRefNull";
        String principal = "testprincipal";
        try {
            zms.dbService.checkRoleAuditEnabled(mockFileConn, role, null, caller, principal);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Audit reference required"));
        }
    }

    @Test
    public void testCheckRoleAuditEnabledFlagTrueRefEmpty() {

        String domainName = "audit-test-domain-name";
        String roleName = "testrole";
        Role role = new Role().setAuditEnabled(true);
        Mockito.doReturn(role).when(mockFileConn).getRole(domainName, roleName);

        String auditCheck = "";  // empty string
        String caller = "testCheckRoleAuditEnabledFlagTrueRefEmpty";
        String principal = "testprincipal";
        try {
            zms.dbService.checkRoleAuditEnabled(mockFileConn, role, auditCheck, caller, principal);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Audit reference required"));
        }
    }

    @Test
    public void testCheckRoleAuditEnabledFlagFalseRefValid() {

        String domainName = "audit-test-domain-name";
        String roleName = "testrole";
        Role role = new Role().setAuditEnabled(false);
        Mockito.doReturn(role).when(mockFileConn).getRole(domainName, roleName);

        String auditCheck = "testaudit";
        String caller = "testCheckRoleAuditEnabledFlagFalseRefValid";
        String principal = "testprincipal";
        zms.dbService.checkRoleAuditEnabled(mockFileConn, role, auditCheck, caller, principal);
    }

    @Test
    public void testCheckRoleAuditEnabledFlagFalseRefNull() {

        String domainName = "audit-test-domain-name";
        String roleName = "testrole";
        Role role = new Role().setAuditEnabled(false);
        Mockito.doReturn(role).when(mockFileConn).getRole(domainName, roleName);

        String caller = "testCheckRoleAuditEnabledFlagFalseRefNull";
        String principal = "testprincipal";
        zms.dbService.checkRoleAuditEnabled(mockFileConn, role, null, caller, principal);
    }

    @Test
    public void testCheckRoleAuditEnabledFlagTrueRefValidationFail() {

        String domainName = "audit-test-domain-name";
        String roleName = "testrole";
        Role role = new Role().setAuditEnabled(true);
        Mockito.doReturn(role).when(mockFileConn).getRole(domainName, roleName);

        zms.dbService.auditReferenceValidator = new MockAuditReferenceValidatorImpl();

        String caller = "testCheckRoleAuditEnabledFlagTrueRefValidationFail";
        String principal = "testprincipal";
        try {
            zms.dbService.checkRoleAuditEnabled(mockFileConn, role, "auditref", caller, principal);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Audit reference validation failed "));
        }
        zms.dbService.auditReferenceValidator = null;
    }

    @Test
    public void testCheckRoleAuditEnabledFlagTrueValidatorNull() {

        String domainName = "audit-test-domain-name";
        String roleName = "testrole";
        Role role = new Role().setAuditEnabled(true);
        Mockito.doReturn(role).when(mockFileConn).getRole(domainName, roleName);

        zms.dbService.auditReferenceValidator = null;

        String caller = "testCheckRoleAuditEnabledFlagTrueValidatorNull";
        String principal = "testprincipal";
        zms.dbService.checkRoleAuditEnabled(mockFileConn, role, "auditref", caller, principal);
    }

    @Test
    public void testExecutePutMembershipDecision() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setApproved(false), auditRef, "putMembership");

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob").setApproved(false), auditRef, "putMembership");

        zms.dbService.executePutMembershipDecision(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setApproved(true), auditRef, "putMembershipDecision");

        zms.dbService.executePutMembershipDecision(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob").setApproved(false), auditRef, "putMembershipDecision");

        Role role = zms.getRole(mockDomRsrcCtx, domainName, roleName, false, false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 3);

        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkRoleMember(checkList, members);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutMembershipDecisionFail() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership");

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob").setActive(false).setApproved(false),
                    auditRef, "putMembership");

        try {
            zms.dbService.executePutMembershipDecision(mockDomRsrcCtx, domainName, "invalid",
                new RoleMember().setMemberName("user.doe").setActive(true).setApproved(true),
                    auditRef, "putMembershipDecision");
            fail();
        }catch (ResourceException r) {
            assertEquals(r.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutRoleAuditEnabled() {

        String domainName = "executeputroledom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        DomainMeta meta2 = new DomainMeta()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud")
                .setAuditEnabled(true);
        Domain d1 = zms.dbService.getDomain(domainName, false);
        zms.dbService.updateSystemMetaFields(d1, "auditenabled", false, meta2);

        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domainName, meta2, "auditenabled", false, auditRef, "");

        Role role1 = createRoleObject(domainName, roleName, null,"user.joe", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole");

        RoleSystemMeta meta = new RoleSystemMeta().setAuditEnabled(true);
        zms.dbService.updateRoleSystemMetaFields(role1, "auditenabled", true, meta);

        zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, domainName, roleName, meta, "auditenabled", true, auditRef, "");

        Role role3 = zms.dbService.getRole(domainName, roleName, false, false, false);
        assertNotNull(role3);
        assertTrue(role3.getAuditEnabled());

        List<RoleMember> newMembers = new ArrayList<>();
        RoleMember rm1 = new RoleMember().setMemberName("user.john").setActive(true).setApproved(true);
        newMembers.add(rm1);
        role1.setRoleMembers(newMembers);
        try {
            zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 400);
        }
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutMembershipDecisionBadRequest() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,"Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,"user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership");

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob").setActive(false).setApproved(false),
                    auditRef, "putMembership");

        RoleMember roleMem = new RoleMember().setMemberName("user.doe").setActive(true).setApproved(true);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getRole(domainName, roleName)).thenReturn(role1);
        Mockito.when(mockFileConn.confirmRoleMember(anyString(), anyString(), any(), anyString(),
                anyString())).thenReturn(false);
        try {
            zms.dbService.executePutMembershipDecision(mockDomRsrcCtx, domainName, roleName,
                    roleMem, auditRef, "putMembershipDecision");
            fail();
        } catch (ResourceException r) {
            assertEquals(r.getCode(), 400);
            assertTrue(r.getMessage().contains("unable to apply role membership"));
        }
        zms.dbService.store = saveStore;
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutMembershipDecisionWithExpiry() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setApproved(false), auditRef, "putMembership");

        Date currentDate = new Date();
        LocalDateTime localDateTime = currentDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        localDateTime = localDateTime.plusDays(7);

        RoleMember member = new RoleMember().setMemberName("user.doe").setApproved(true)
                .setExpiration(Timestamp.fromMillis(Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant()).getTime()));
        zms.dbService.executePutMembershipDecision(mockDomRsrcCtx, domainName, roleName, member, auditRef, "putMembershipDecision");

        Role role = zms.getRole(mockDomRsrcCtx, domainName, roleName, false, false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 3);

        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkRoleMember(checkList, members);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutMembershipDecisionRetry() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,"Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,"user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership");

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob").setActive(false).setApproved(false),
                    auditRef, "putMembership");

        RoleMember roleMem = new RoleMember().setMemberName("user.doe").setActive(true).setApproved(true);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        zms.dbService.defaultRetryCount = 2;
        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        ResourceException rex = new ResourceException(409);
        Mockito.when(mockFileConn.confirmRoleMember(anyString(), anyString(), any(), anyString(),
                anyString())).thenThrow(rex);
        try {
            zms.dbService.executePutMembershipDecision(mockDomRsrcCtx, domainName, roleName,
                    roleMem, auditRef, "putMembershipDecision");
            fail();
        }catch (ResourceException r) {
            assertEquals(r.getCode(), 409);
            assertTrue(r.getMessage().contains("Conflict"));
        }
        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = 120;
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testGetPendingDomainRoleMembersListEmptyMap() {
        DomainRoleMembership domainRoleMembership = zms.dbService.getPendingDomainRoleMembers("user.user1");
        assertNotNull(domainRoleMembership);
        assertTrue(domainRoleMembership.getDomainRoleMembersList().isEmpty());
    }

    @Test
    public void testGetRolePending() {
        String domainName = "mgradddom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,"Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        Role role1 = createRoleObject(domainName, roleName, null,"user.joe", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "testGetRolePending");
        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership");

        Role role = zms.dbService.getRole(domainName, roleName, false, false, true);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 3);

        role = zms.dbService.getRole(domainName, roleName, false, false, false);
        assertNotNull(role);
        members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 2);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutDomainMetaForbidden() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MetaDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Domain resDom1 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom1);
        assertEquals("Test Domain1", resDom1.getDescription());
        assertEquals("testorg", resDom1.getOrg());
        assertTrue(resDom1.getEnabled());
        assertFalse(resDom1.getAuditEnabled());

        // update meta with values for account and product ids

        DomainMeta meta = new DomainMeta().setDescription("Test2 Domain").setOrg("NewOrg")
                .setEnabled(true).setAuditEnabled(false).setAccount("12345").setYpmId(1001)
                .setCertDnsDomain("athenz1.cloud");
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, null, false, auditRef, "putDomainMeta");
        try {
            zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, "org", false, auditRef, "putDomainMeta");
            fail();
        }catch (ResourceException re) {
            assertEquals(re.getCode(), 403);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MetaDom1", auditRef);
    }

    @Test
    public void testGetPendingMembershipNotifications() {

        TopLevelDomain dom1 = createTopLevelDomainObject("dom1", "Test Domain1", "testorg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);
        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject("dom2", "test dom2", "testorg", true,
                "acct", 1234, "", 0), admins, null, auditRef);

        DomainMeta meta2 = new DomainMeta()
                .setAccount("acct")
                .setYpmId(1234)
                .setOrg("testorg")
                .setAuditEnabled(true)
                .setCertDnsDomain("athenz.cloud");

        Domain domres2 = new Domain()
                .setName("dom2")
                .setAuditEnabled(true)
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud");

        zms.dbService.updateSystemMetaFields(domres2, "auditenabled", false, meta2);
        Role role2 = createRoleObject("dom2", "role2", null, "user.john", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, "dom2", "role2", role2, "test", "putrole");
        RoleSystemMeta rsm2 = new RoleSystemMeta();
        rsm2.setAuditEnabled(true);
        zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, "dom2", "role2",
                rsm2,"auditenabled", true, auditRef, "putrolesystemmeta");

        zms.dbService.executePutMembership(mockDomRsrcCtx, "dom2", "role2",
                new RoleMember().setMemberName("user.poe").setActive(false).setApproved(false),
                    auditRef, "putMembership");

        Role role1 = createRoleObject("dom1", "role1", null,"user.joe", "user.jane");
        role1.setSelfServe(true);
        zms.dbService.executePutRole(mockDomRsrcCtx, "dom1", "role1", role1, auditRef,
                "testGetPendingMembershipNotifications");
        zms.dbService.executePutMembership(mockDomRsrcCtx, "dom1", "role1",
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership");

        Role auditApproverRole = createRoleObject("sys.auth.audit.org", "testorg",
                null, "user.boe", adminUser);
        zms.dbService.executePutRole(mockDomRsrcCtx, "sys.auth.audit.org", "testorg",
                auditApproverRole, "test", "putrole");

        Set<String> recipientRoles = zms.dbService.getPendingMembershipApproverRoles();

        assertNotNull(recipientRoles);
        assertTrue(recipientRoles.contains("dom1:role.admin"));
        assertTrue(recipientRoles.contains("sys.auth.audit.org:role.testorg"));

        zms.dbService.executeDeleteRole(mockDomRsrcCtx, "sys.auth.audit.org", "testorg", "cleanup", "unitttest");
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "dom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "dom2", auditRef);
    }

    @Test
    public void testGetPendingMembershipNotificationsEdge() {

        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        recipients.add("unix.moe");
        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.updatePendingRoleMembersNotificationTimestamp(anyString(), anyLong())).thenReturn(true);
        Mockito.when(mockFileConn.getPendingMembershipApproverRoles(anyString(), anyLong())).thenReturn(recipients);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Set<String> recipientsRes = zms.dbService.getPendingMembershipApproverRoles();

        assertNotNull(recipientsRes);
        assertTrue(recipientsRes.contains("user.joe"));

        zms.dbService.store = saveStore;
    }

    @Test
    public void testGetPendingMembershipNotificationsTimestampUpdateFailed() {

        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.updatePendingRoleMembersNotificationTimestamp(anyString(), anyLong())).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        Set<String> recipientsRes = zms.dbService.getPendingMembershipApproverRoles();
        assertNull(recipientsRes);
        zms.dbService.store = saveStore;
    }

    @Test
    public void testProcessExpiredPendingMembers() {

        Map<String, List<DomainRoleMember>> memberList = new LinkedHashMap<>();

        DomainRoleMember domainRoleMember1 = new DomainRoleMember();
        domainRoleMember1.setMemberName("user.user1");
        List<MemberRole> memberRoles1 = new ArrayList<>();
        memberRoles1.add(new MemberRole().setRoleName("role1"));
        domainRoleMember1.setMemberRoles(memberRoles1);

        DomainRoleMember domainRoleMember2 = new DomainRoleMember();
        domainRoleMember2.setMemberName("user.user2");
        List<MemberRole> memberRoles2 = new ArrayList<>();
        memberRoles2.add(new MemberRole().setRoleName("role1"));
        domainRoleMember2.setMemberRoles(memberRoles2);

        List<DomainRoleMember> domainRoleMembers = new ArrayList<>();
        domainRoleMembers.add(domainRoleMember1);
        domainRoleMembers.add(domainRoleMember2);
        memberList.put("dom1", domainRoleMembers);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getExpiredPendingDomainRoleMembers(30)).thenReturn(memberList);
        Mockito.when(mockFileConn.deletePendingRoleMember("dom1", "role1", "user.user1", "sys.auth.monitor",
                "Expired - auto reject")).thenReturn(true);
        Mockito.when(mockFileConn.deletePendingRoleMember("dom1", "role1", "user.user2", "sys.auth.monitor",
                "Expired - auto reject")).thenReturn(false);

        zms.dbService.processExpiredPendingMembers(30, "sys.auth.monitor");
        zms.dbService.store = saveStore;
    }

    @Test
    public void testGetExpiredPendingDomainRoleMembers() {

        String domainName = "expirependingdomain";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);

        // we're creating one with current time

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe")
                        .setApproved(false)
                        .setRequestTime(Timestamp.fromCurrentTime()),
                auditRef, "putMembership");

        // second one is over 31 days old

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob")
                        .setApproved(false)
                        .setRequestTime(Timestamp.fromMillis(TimeUnit.MILLISECONDS.convert(31, TimeUnit.DAYS))),
                auditRef, "putMembership");

        // we should have 2 regular and 2 pending users

        Role role = zms.dbService.getRole(domainName, roleName, false, false, true);
        assertEquals(role.getRoleMembers().size(), 4);

        // now let's expire our entries

        zms.dbService.processExpiredPendingMembers(30, "sys.auth.monitor");

        // we should get back only three members since one is expired

        role = zms.dbService.getRole(domainName, roleName, false, false, true);
        assertEquals(role.getRoleMembers().size(), 3);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testExecutePutRoleMetaExpirationUpdate() {

        final String domainName = "role-meta-expiry";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true));
        role.getRoleMembers().add(new RoleMember().setMemberName("sys.tim").setExpiration(timExpiry).setApproved(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role, "test", "putrole");

        RoleMeta rm = new RoleMeta();
        rm.setMemberExpiryDays(40);
        rm.setServiceExpiryDays(40);

        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, "role1",
                rm, auditRef, "putrolemeta");

        Role resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        // verify all users have an expiry of close to 40 days except tim who will maintain
        // his 10 day expiry value

        long ext40Millis = TimeUnit.MILLISECONDS.convert(40, TimeUnit.DAYS);

        int membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(roleMember.getExpiration().millis() > System.currentTimeMillis() + ext40Millis - 5000 &&
                            roleMember.getExpiration().millis() < System.currentTimeMillis() + ext40Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                case "sys.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

        // now reduce limit to 20 days

        rm.setMemberExpiryDays(20);
        rm.setServiceExpiryDays(20);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, "role1",
                rm, auditRef, "putrolemeta");

        resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        // verify all users have an expiry of close to 20 days except tim who will maintain
        // his 10 day expiry value

        long ext20Millis = TimeUnit.MILLISECONDS.convert(20, TimeUnit.DAYS);

        membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(roleMember.getExpiration().millis() > System.currentTimeMillis() + ext20Millis - 5000 &&
                            roleMember.getExpiration().millis() < System.currentTimeMillis() + ext20Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                case "sys.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

        // now set it back to 40 but nothing will change

        rm.setMemberExpiryDays(40);
        rm.setServiceExpiryDays(40);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, "role1",
                rm, auditRef, "putrolemeta");

        resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        // verify all users have an expiry of close to 20 days except tim who will maintain
        // his 10 day expiry value

        membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(roleMember.getExpiration().millis() > System.currentTimeMillis() + ext20Millis - 5000 &&
                            roleMember.getExpiration().millis() < System.currentTimeMillis() + ext20Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                case "sys.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

        // now set the service down to 5 days.

        rm.setServiceExpiryDays(5);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, "role1",
                rm, auditRef, "putrolemeta");

        resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        long ext5Millis = TimeUnit.MILLISECONDS.convert(5, TimeUnit.DAYS);

        // verify all users have their previous values except service tim who will now have
        // a new 5 day expiry value

        membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(roleMember.getExpiration().millis() > System.currentTimeMillis() + ext20Millis - 5000 &&
                            roleMember.getExpiration().millis() < System.currentTimeMillis() + ext20Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
                case "sys.tim":
                    assertTrue(roleMember.getExpiration().millis() > System.currentTimeMillis() + ext5Millis - 5000 &&
                            roleMember.getExpiration().millis() < System.currentTimeMillis() + ext5Millis + 5000);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testUpdateRoleMembersExpirationFailures() {

        final String domainName = "role-meta-expiry";

        Role originalRole = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        originalRole.setMemberExpiryDays(10);

        Role updateRole = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        updateRole.setMemberExpiryDays(5);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                    Mockito.any(), Mockito.anyString()))
                .thenReturn(false)
                .thenThrow(new IllegalArgumentException());

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenThrow(new IllegalArgumentException());

        zms.dbService.updateRoleMembersExpiration(mockDomRsrcCtx, mockConn, domainName, "role1", originalRole,
                updateRole, auditRef, "testUpdateRoleMembersExpirationFailures");
    }

    @Test
    public void testUpdateRoleMembersExpirationTrust() {

        final String domainName = "role-meta-expiry";

        // in this test case we're going to set the expiry days to 0 so we
        // get an exception when accessed but we should never get there
        // since our role is set as trust

        Role role = createRoleObject(domainName, "role1", "coretech", null, null);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString()))
                .thenReturn(true);

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenThrow(new IllegalArgumentException());

        zms.dbService.updateRoleMembersExpiration(mockDomRsrcCtx, mockConn, domainName, "role1", role,
                role, auditRef, "testUpdateRoleMembersExpirationTrust");
    }

    @Test
    public void testUpdateRoleMembersExpirationNoRoleMembers() {

        final String domainName = "role-meta-expiry";

        // in this test case we're going to set the expiry days to 0 so we
        // get an exception when accessed but we should never get there
        // since our role is set as trust

        Role role = createRoleObject(domainName, "role1", null, null, null);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString()))
                .thenReturn(true);

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenThrow(new IllegalArgumentException());

        zms.dbService.updateRoleMembersExpiration(mockDomRsrcCtx, mockConn, domainName, "role1", role,
                role, auditRef, "testUpdateRoleMembersExpirationNoRoleMembers");
    }

    @Test
    public void testExecutePutDomainMetaExpirationUpdate() {

        final String domainName = "domain-meta-expiry";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole");

        Role role2 = createRoleObject(domainName, "role2", null, "user.john", "user.jane");
        role2.getRoleMembers().get(0).setExpiration(timExpiry);
        role2.getRoleMembers().get(1).setExpiration(timExpiry);
        role2.setMemberExpiryDays(15);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2", role2, "test", "putrole");

        Role role3 = createRoleObject(domainName, "role3", "coretech", null, null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3", role3, "test", "putrole");

        DomainMeta meta = new DomainMeta().setMemberExpiryDays(40);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domainName, meta, null, false, auditRef, "putDomainMeta");

        Role resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        // verify all users have an expiry of close to 40 days except tim who will maintain
        // his 10 day expiry value

        long ext40Millis = TimeUnit.MILLISECONDS.convert(40, TimeUnit.DAYS);

        int membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(roleMember.getExpiration().millis() > System.currentTimeMillis() + ext40Millis - 5000 &&
                            roleMember.getExpiration().millis() < System.currentTimeMillis() + ext40Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);

        // verify that all users in role2 have not changed since the role already
        // has an expiration

        Role resRole2 = zms.dbService.getRole(domainName, "role2", false, true, false);

        membersChecked = 0;
        for (RoleMember roleMember : resRole2.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 2);

        // now reduce limit to 5 days

        meta.setMemberExpiryDays(5);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domainName, meta, null, false, auditRef, "putDomainMeta");

        resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        // verify all users have an expiry of 5 days

        long ext5Millis = TimeUnit.MILLISECONDS.convert(5, TimeUnit.DAYS);

        membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                case "user.tim":
                    assertTrue(roleMember.getExpiration().millis() > System.currentTimeMillis() + ext5Millis - 5000 &&
                            roleMember.getExpiration().millis() < System.currentTimeMillis() + ext5Millis + 5000);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);

        // verify that all users in role2 have not changed since the role already
        // has an expiration

        resRole2 = zms.dbService.getRole(domainName, "role2", false, true, false);

        membersChecked = 0;
        for (RoleMember roleMember : resRole2.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 2);

        // now set it back to 40 but nothing will change

        meta.setMemberExpiryDays(40);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domainName, meta, null, false, auditRef, "putDomainMeta");

        resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                case "user.tim":
                    assertTrue(roleMember.getExpiration().millis() > System.currentTimeMillis() + ext5Millis - 5000 &&
                            roleMember.getExpiration().millis() < System.currentTimeMillis() + ext5Millis + 5000);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);

        // verify that all users in role2 have not changed since the role already
        // has an expiration

        resRole2 = zms.dbService.getRole(domainName, "role2", false, true, false);

        membersChecked = 0;
        for (RoleMember roleMember : resRole2.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 2);

        // verify our trust role

        Role resRole3 = zms.dbService.getRole(domainName, "role3", false, true, false);
        assertEquals(resRole3.getTrust(), "coretech");
        assertNull(resRole3.getRoleMembers());

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void updateDomainMembersExpirationNoChanges() {

        final String domainName = "domain-meta-expiry";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().get(0).setExpiration(timExpiry);
        role1.getRoleMembers().get(1).setExpiration(timExpiry);
        role1.setMemberExpiryDays(15);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole");

        Role role2 = createRoleObject(domainName, "role2", null, null, null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2", role2, "test", "putrole");

        RoleMeta rm = new RoleMeta().setMemberExpiryDays(10);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, "admin",
                rm, auditRef, "putrolemeta");

        // we're going to set the meta but there will be no changes
        // since the both roles have values set.

        DomainMeta meta = new DomainMeta().setMemberExpiryDays(5);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domainName, meta, null, false, auditRef, "putDomainMeta");

        // verify that all users in role1 have not changed since the role already
        // has an expiration

        Role resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        int membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 2);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testUpdateDomainMembersExpirationFailure() {

        Domain domain = new Domain().setName("test1").setMemberExpiryDays(100).setModified(Timestamp.fromCurrentTime());
        Domain updateDomain = new Domain().setName("test1").setMemberExpiryDays(50);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);

        // we're going to make sure to throw an exception here
        // since this should never be called

        AthenzDomain athenzDomain = new AthenzDomain("test1");
        athenzDomain.setDomain(domain);
        Mockito.when(mockConn.getAthenzDomain("test1")).thenReturn(athenzDomain);
        Mockito.when(mockConn.updateDomainModTimestamp("test1")).thenThrow(new IllegalArgumentException());

        zms.dbService.updateDomainMembersExpiration(mockDomRsrcCtx, mockConn, domain, updateDomain, auditRef,
                "testUpdateMdomainMembersExpirationFailure");
    }

    @Test
    public void testUpdateDomainMembersExpirationObjectStoreFailure() {

        final String domainName = "domain-meta-expiry";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Domain domain = new Domain().setName(domainName).setMemberExpiryDays(100)
                .setModified(Timestamp.fromCurrentTime());
        Domain updateDomain = new Domain().setName(domainName).setMemberExpiryDays(50);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        AthenzDomain athenzDomain = new AthenzDomain(domainName);
        athenzDomain.setDomain(domain);
        Mockito.when(mockConn.getAthenzDomain(domainName)).thenReturn(athenzDomain);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(false);

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenThrow(new IllegalArgumentException());

        zms.dbService.updateDomainMembersExpiration(mockDomRsrcCtx, mockConn, domain, updateDomain, auditRef,
                "testUpdateDomainMembersExpirationFailure");

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testMemberExpiryDayReduced() {

        assertFalse(zms.dbService.memberExpiryDaysReduced(null, null));
        assertFalse(zms.dbService.memberExpiryDaysReduced(10, null));
        assertFalse(zms.dbService.memberExpiryDaysReduced(0, null));
        assertFalse(zms.dbService.memberExpiryDaysReduced(-1, null));

        assertFalse(zms.dbService.memberExpiryDaysReduced(null, 0));
        assertFalse(zms.dbService.memberExpiryDaysReduced(10, 0));
        assertFalse(zms.dbService.memberExpiryDaysReduced(0, 0));
        assertFalse(zms.dbService.memberExpiryDaysReduced(-1, 0));

        assertFalse(zms.dbService.memberExpiryDaysReduced(null, -1));
        assertFalse(zms.dbService.memberExpiryDaysReduced(10, -1));
        assertFalse(zms.dbService.memberExpiryDaysReduced(0, -1));
        assertFalse(zms.dbService.memberExpiryDaysReduced(-1, -1));

        assertTrue(zms.dbService.memberExpiryDaysReduced(null, 10));
        assertTrue(zms.dbService.memberExpiryDaysReduced(0, 10));
        assertTrue(zms.dbService.memberExpiryDaysReduced(-1, 10));

        assertFalse(zms.dbService.memberExpiryDaysReduced(5, 10));
        assertTrue(zms.dbService.memberExpiryDaysReduced(10, 5));
    }

    @Test
    public void testGetServicePublicKeyEntryServiceUnavailable() {

        final String domainName = "test1";
        final String serviceName = "service1";
        final String keyId = "0";

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(true, false)).thenReturn(mockConn);
        Mockito.when(mockConn.getPublicKeyEntry(domainName, serviceName, keyId, false))
                .thenThrow(new ResourceException(ResourceException.SERVICE_UNAVAILABLE));

        try {
            zms.dbService.getServicePublicKeyEntry(domainName, serviceName, keyId, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
        }
        zms.dbService.store = saveStore;
    }

    @Test
    public void testAuditLogRoleMember() {

        StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        RoleMember rm = new RoleMember().setMemberName("user.joe");
        zms.dbService.auditLogRoleMember(auditDetails, rm, true);
        assertEquals(auditDetails.toString(), "{\"member\": \"user.joe\", \"approved\": true}");

        auditDetails.setLength(0);
        RoleMember rm2 = new RoleMember().setMemberName("user.joe").setApproved(true);
        zms.dbService.auditLogRoleMember(auditDetails, rm2, true);
        assertEquals(auditDetails.toString(), "{\"member\": \"user.joe\", \"approved\": true}");

        auditDetails.setLength(0);
        RoleMember rm3 = new RoleMember().setMemberName("user.joe").setApproved(false);
        zms.dbService.auditLogRoleMember(auditDetails, rm3, true);
        assertEquals(auditDetails.toString(), "{\"member\": \"user.joe\", \"approved\": false}");

        auditDetails.setLength(0);
        RoleMember rm4 = new RoleMember().setMemberName("user.joe")
                .setApproved(false).setExpiration(Timestamp.fromMillis(1000));
        zms.dbService.auditLogRoleMember(auditDetails, rm4, true);
        assertEquals(auditDetails.toString(), "{\"member\": \"user.joe\", \"expiration\": \"1970-01-01T00:00:01.000Z\", \"approved\": false}");
    }

    @Test
    public void testGetRoleExpiryMembers() {

        final String domainName1 = "role-expiry-members1";
        final String domainName2 = "role-expiry-members2";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName1, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role = createRoleObject(domainName1, "role1", null, "user.john", "user.jane");
        Timestamp oneDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));
        Timestamp sevenDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(7, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));
        role.getRoleMembers().add(new RoleMember().setMemberName("user.oneday")
                .setExpiration(oneDayExpiry).setApproved(true));
        role.getRoleMembers().add(new RoleMember().setMemberName("user.sevenday")
                .setExpiration(sevenDayExpiry).setApproved(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName1, "role1", role, "test", "putrole");

        Role role2 = createRoleObject(domainName1, "role2", null, "user.john", "user.jane");
        Timestamp twoDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(2, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));
        role2.getRoleMembers().add(new RoleMember().setMemberName("user.twoday")
                .setExpiration(twoDayExpiry).setApproved(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName1, "role2", role2, "test", "putrole");

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName2, "test desc", "org", false,
                "", 1235, "", 0), admins, null, auditRef);

        Role role3 = createRoleObject(domainName2, "role3", null, "user.john", "user.jane");
        Timestamp fourteenDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(14, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));
        Timestamp thirtyfiveDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(35, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));
        role3.getRoleMembers().add(new RoleMember().setMemberName("user.fourteenday")
                .setExpiration(fourteenDayExpiry).setApproved(true));
        role3.getRoleMembers().add(new RoleMember().setMemberName("user.thirtyfiveday")
                .setExpiration(thirtyfiveDayExpiry).setApproved(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName2, "role3", role3, "test", "putrole");

        Map<String, DomainRoleMember> domainRoleMembers = zms.dbService.getRoleExpiryMembers();
        assertNotNull(domainRoleMembers);
        assertEquals(domainRoleMembers.size(), 3);

        DomainRoleMember roleMember = domainRoleMembers.get("user.oneday");
        assertNotNull(roleMember);

        roleMember = domainRoleMembers.get("user.sevenday");
        assertNotNull(roleMember);

        roleMember = domainRoleMembers.get("user.fourteenday");
        assertNotNull(roleMember);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName1, auditRef, "deletedomain");
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName2, auditRef, "deletedomain");
    }

    @Test
    public void testGetRoleExpiryMembersFailure() {

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockConn);
        Mockito.when(mockConn.updateRoleMemberExpirationNotificationTimestamp(anyString(), anyLong())).thenReturn(false);

        assertNull(zms.dbService.getRoleExpiryMembers());
        zms.dbService.store = saveStore;
    }

    private RoleMember createRoleMember (String name, boolean active, Timestamp expiry, boolean approved) {
        return new RoleMember().setMemberName(name).setActive(active).setApproved(approved).setExpiration(expiry);
    }

    @Test
    public void testApplyMembershipChanges() {
        List<RoleMember> incomingMembers = new ArrayList<>(3);
        List<RoleMember> originalMembers = new ArrayList<>(5);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));

        Timestamp currentExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(4, TimeUnit.DAYS));


        incomingMembers.add(createRoleMember("user.user1", true, thirtyDayExpiry, true));
        incomingMembers.add(createRoleMember("user.user2", true, thirtyDayExpiry, true));
        incomingMembers.add(createRoleMember("user.user4", false, thirtyDayExpiry, true));

        Role incomingRole = new Role().setName("role1").setRoleMembers(incomingMembers);

        originalMembers.add(createRoleMember("user.user1", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user2", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user3", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user4", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user5", true, currentExpiry, true));

        Role originalRole = new Role().setName("role1").setRoleMembers(originalMembers);

        Role updatedRole = new Role().setName("role1");

        zms.dbService.applyMembershipChanges(updatedRole, originalRole, incomingRole, auditRef);

        assertEquals(updatedRole.getRoleMembers().size(), 3);
        List<String> expectedMemberNames = Arrays.asList("user.user1", "user.user2", "user.user4");
        for (RoleMember roleMember : updatedRole.getRoleMembers()) {
            assertTrue(roleMember.getApproved());
            assertEquals(roleMember.getExpiration(), thirtyDayExpiry);
            assertTrue(expectedMemberNames.contains(roleMember.getMemberName()));
            assertEquals(roleMember.getAuditRef(), auditRef);
            if (roleMember.getMemberName().equals("user.user4")) {
                assertFalse(roleMember.getActive());
            } else {
                assertTrue(roleMember.getActive());
            }
        }

        originalRole.setAuditEnabled(true);
        updatedRole.setRoleMembers(null);

        List<RoleMember> noactionMembers = zms.dbService.applyMembershipChanges(updatedRole, originalRole, incomingRole, auditRef);

        assertEquals(noactionMembers.size(), 2);
        int noActChecked = 0;
        for (RoleMember roleMember : noactionMembers) {
            switch (roleMember.getMemberName()) {
                case "user.user3":
                    noActChecked += 1;
                    break;
                case "user.user5":
                    noActChecked += 1;
                    break;
            }
        }

        assertEquals(noActChecked, 2);

        assertEquals(updatedRole.getRoleMembers().size(), 3);
        for (RoleMember roleMember : updatedRole.getRoleMembers()) {
            assertFalse(roleMember.getApproved());
            assertEquals(roleMember.getExpiration(), thirtyDayExpiry);
            assertTrue(expectedMemberNames.contains(roleMember.getMemberName()));
            assertEquals(roleMember.getAuditRef(), auditRef);
            if (roleMember.getMemberName().equals("user.user4")) {
                assertFalse(roleMember.getActive());
            } else {
                assertTrue(roleMember.getActive());
            }
        }
    }

    @Test
    public void testExecutePutRoleReviewDelegatedRole() {
        final String domainName = "role-review";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", "dummydom:role.dummyrole", "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole");

        Role incomingRole = new Role().setName("role1");

        try {
            zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole, "review test", "putRoleReview");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 400);
        }

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleReview() {
        final String domainName = "role-review";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole");

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new RoleMember().setMemberName("user.john").setActive(false).setExpiration(thirtyDayExpiry));
        incomingMembers.add(new RoleMember().setMemberName("user.jane").setActive(true).setExpiration(thirtyDayExpiry));
        incomingRole.setRoleMembers(incomingMembers);
        zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole, "review test", "putRoleReview");

        Role resRole = zms.dbService.getRole(domainName, "role1", false, false, false);

        assertEquals(resRole.getRoleMembers().size(), 2);

        int membersChecked = 0;

        for (RoleMember roleMember : resRole.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.jane":
                    // user.jane is extended to new expiry
                    assertEquals(roleMember.getExpiration(), thirtyDayExpiry);
                    assertTrue(roleMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.tim":
                    // user.tim was not part of incoming role, so he remains unchanged
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 2);
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleReviewNoAction() {
        final String domainName = "role-review";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole");

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingRole.setRoleMembers(incomingMembers);

        zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole, "review test", "putRoleReview");

        Role resRole = zms.dbService.getRole(domainName, "role1", false, false, false);

        assertEquals(resRole.getRoleMembers().size(), 3);

        int membersChecked = 0;

        for (RoleMember roleMember : resRole.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                    assertNull(roleMember.getExpiration());
                    assertTrue(roleMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.jane":
                    assertNull(roleMember.getExpiration());
                    assertTrue(roleMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleReviewDelError() {
        final String domainName = "role-review";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole");

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new RoleMember().setMemberName("user.john").setActive(false).setExpiration(thirtyDayExpiry));
        incomingMembers.add(new RoleMember().setMemberName("user.jane").setActive(true).setExpiration(thirtyDayExpiry));
        incomingRole.setRoleMembers(incomingMembers);

        Domain resDom = zms.dbService.getDomain(domainName, true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockConn);
        Mockito.when(mockConn.getDomain(domainName)).thenReturn(resDom);
        Mockito.when(mockConn.getRole(domainName, "role1")).thenReturn(role1);
        Mockito.when(mockConn.listRoleMembers(domainName, "role1", false)).thenReturn(role1.getRoleMembers());
        Mockito.when(mockConn.deleteRoleMember(domainName, "role1", "user.john", adminUser, auditRef))
                .thenThrow(new ResourceException(ResourceException.NOT_FOUND));

        try {
            zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole, "review test", "putRoleReview");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        zms.dbService.store = saveStore;

        Role resRole = zms.dbService.getRole(domainName, "role1", false, false, false);

        assertEquals(resRole.getRoleMembers().size(), 3);

        int membersChecked = 0;

        for (RoleMember roleMember : resRole.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                    assertNull(roleMember.getExpiration());
                    assertTrue(roleMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.jane":
                    assertNull(roleMember.getExpiration());
                    assertTrue(roleMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleReviewExtendError() {
        final String domainName = "role-review";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole");

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new RoleMember().setMemberName("user.john").setActive(false).setExpiration(thirtyDayExpiry));
        incomingMembers.add(new RoleMember().setMemberName("user.jane").setActive(true).setExpiration(thirtyDayExpiry));
        incomingRole.setRoleMembers(incomingMembers);

        Domain resDom = zms.dbService.getDomain(domainName, true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockConn);
        Mockito.when(mockConn.getDomain(domainName)).thenReturn(resDom);
        Mockito.when(mockConn.getRole(domainName, "role1")).thenReturn(role1);
        Mockito.when(mockConn.listRoleMembers(domainName, "role1", false)).thenReturn(role1.getRoleMembers());
        Mockito.when(mockConn.deleteRoleMember(anyString(), anyString(), anyString(), anyString(), anyString())).thenReturn(true);
        Mockito.when(mockConn.insertRoleMember(anyString(), anyString(), any(RoleMember.class), anyString(), anyString()))
                .thenReturn(false);

        try {
            zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole, "review test", "putRoleReview");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        zms.dbService.store = saveStore;

        Role resRole = zms.dbService.getRole(domainName, "role1", false, false, false);

        assertEquals(resRole.getRoleMembers().size(), 3);

        int membersChecked = 0;

        for (RoleMember roleMember : resRole.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                    assertNull(roleMember.getExpiration());
                    assertTrue(roleMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.jane":
                    assertNull(roleMember.getExpiration());
                    assertTrue(roleMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleReviewRetry() {
        final String domainName = "role-review";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole");

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new RoleMember().setMemberName("user.john").setActive(false).setExpiration(thirtyDayExpiry));
        incomingMembers.add(new RoleMember().setMemberName("user.jane").setActive(true).setExpiration(thirtyDayExpiry));
        incomingRole.setRoleMembers(incomingMembers);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(false, true)).thenReturn(mockConn);
        Mockito.when(mockConn.getDomain(domainName)).thenThrow(new ResourceException(ResourceException.CONFLICT));

        try {
            zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole, "review test", "putRoleReview");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // getDomain gets called to check domain auditEnabled requirement. verification of 2 retries happened
        verify(mockConn, times(2)).getDomain("role-review");

        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = saveRetryCount;

        Role resRole = zms.dbService.getRole(domainName, "role1", false, false, false);

        assertEquals(resRole.getRoleMembers().size(), 3);

        int membersChecked = 0;

        for (RoleMember roleMember : resRole.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                    assertNull(roleMember.getExpiration());
                    assertTrue(roleMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.jane":
                    assertNull(roleMember.getExpiration());
                    assertTrue(roleMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testSetMembersInDomainNullRoles() {

        String domainName = "null-roles";

        Domain domain = new Domain().setModified(Timestamp.fromCurrentTime());
        AthenzDomain athenzDomain = new AthenzDomain(domainName);
        athenzDomain.setDomain(domain);
        athenzDomain.setRoles(null);
        Mockito.when(mockObjStore.getConnection(true, false)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getAthenzDomain(domainName)).thenReturn(athenzDomain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        AthenzDomain resAthenzDomain = zms.dbService.getAthenzDomain(domainName, false);
        assertNull(resAthenzDomain.getRoles());

        zms.dbService.store = saveStore;
    }

    @Test
    public void testSetMembersInDomainEmptyMembers() {

        String domainName = "no-role-members";

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.admin"));
        Role role = new Role().setMembers(null).setRoleMembers(roleMembers);
        List<Role> roles = new ArrayList<>();
        roles.add(role);
        Domain domain = new Domain().setModified(Timestamp.fromCurrentTime());
        AthenzDomain athenzDomain = new AthenzDomain(domainName);
        athenzDomain.setDomain(domain);
        athenzDomain.setRoles(roles);
        Mockito.when(mockObjStore.getConnection(true, false)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getAthenzDomain(domainName)).thenReturn(athenzDomain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        AthenzDomain resAthenzDomain = zms.dbService.getAthenzDomain(domainName, false);
        assertNotNull(resAthenzDomain.getRoles());
        List<String> members = resAthenzDomain.getRoles().get(0).getMembers();
        assertEquals(members.size(), 1);
        assertEquals(members.get(0), "user.admin");

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePendingMemberFailureRetry() {

        final String domainName = "pendingdeletembrretry";
        final String roleName = "role1";
        final String memberName = "user.member1";
        final String adminName = "user.user1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deletePendingRoleMember(domainName, roleName, memberName, adminName, auditRef))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeletePendingMembership(mockDomRsrcCtx, domainName, roleName,
                    memberName, auditRef, "deletePendingMember");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteMemberFailureNotFound() {

        final String domainName = "deletembrnotfound";
        final String roleName = "role1";
        final String memberName = "user.member1";
        final String adminName = "user.user1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deleteRoleMember(domainName, roleName, memberName, adminName, auditRef))
                .thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeleteMembership(mockDomRsrcCtx, domainName, roleName,
                    memberName, auditRef, "deleteMember");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteMemberFailureRetry() {

        final String domainName = "deletembrretry";
        final String roleName = "role1";
        final String memberName = "user.member1";
        final String adminName = "user.user1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(true, true)).thenReturn(mockFileConn);
        Mockito.when(mockFileConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockFileConn.deleteRoleMember(domainName, roleName, memberName, adminName, auditRef))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeleteMembership(mockDomRsrcCtx, domainName, roleName,
                    memberName, auditRef, "deleteMember");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }
}
