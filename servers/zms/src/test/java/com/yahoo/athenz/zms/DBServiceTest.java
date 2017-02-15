/**
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

import org.mockito.Mockito;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.*;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.log.AuditLogFactory;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.provider.ProviderMockClient;
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
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import junit.framework.TestCase;

public class DBServiceTest extends TestCase {
    
    @Mock FileConnection mockFileConn;
    @Mock ObjectStore mockObjStore;
    
    ZMSImpl zms             = null;
    String adminUser        = null;
    String pubKey           = null; // assume default is K0
    String pubKeyK1         = null;
    String pubKeyK2         = null;
    String privKey          = null; // assume default is K0
    String privKeyK1        = null; 
    String privKeyK2        = null; 
    String auditRef         = "audittest";

    // typically used when creating and deleting domains with all the tests
    //
    @Mock ZMSImpl.RsrcCtxWrapper mockDomRsrcCtx;
    @Mock com.yahoo.athenz.common.server.rest.ResourceContext mockDomRestRsrcCtx;
    Principal rsrcPrince    = null; // used with the mockDomRestRsrcCtx

    private static final String MOCKCLIENTADDR = "10.11.12.13";
    @Mock HttpServletRequest mockServletRequest;
    @Mock HttpServletResponse mockServletResponse;
    
    private static final String ZMS_DATA_STORE_PATH = "/tmp/zms_core_unit_tests/zms_root";

    static final Struct TABLE_PROVIDER_ROLE_ACTIONS = new Struct()
            .with("admin", "*").with("writer", "WRITE").with("reader", "READ");

    static final Struct RESOURCE_PROVIDER_ROLE_ACTIONS = new Struct()
            .with("writer", "WRITE").with("reader", "READ");
    
    static final int BASE_PRODUCT_ID = 500000000; // these product ids will lie in 500 million range
    static java.util.Random domainProductId = new java.security.SecureRandom();
    static synchronized int getRandomProductId() {
        return BASE_PRODUCT_ID + domainProductId.nextInt(99999999);
    }

    @BeforeClass
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        setupServiceId();
    }

    ResourceContext createResourceContext(Principal prince) {
        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx = Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(prince);
        Mockito.when(rsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(rsrcCtx.response()).thenReturn(mockServletResponse);

        ZMSImpl.RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(ZMSImpl.RsrcCtxWrapper.class);
        Mockito.when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        Mockito.when(rsrcCtxWrapper.principal()).thenReturn(prince);
        Mockito.when(rsrcCtxWrapper.request()).thenReturn(mockServletRequest);
        Mockito.when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        return rsrcCtxWrapper;
    }
    
    ResourceContext createResourceContext(Principal principal, HttpServletRequest request) {
        if (request == null) {
            return createResourceContext(principal);
        }

        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx = Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(request);
        Mockito.when(rsrcCtx.response()).thenReturn(mockServletResponse);

        ZMSImpl.RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(ZMSImpl.RsrcCtxWrapper.class);
        Mockito.when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        Mockito.when(rsrcCtxWrapper.request()).thenReturn(request);
        Mockito.when(rsrcCtxWrapper.principal()).thenReturn(principal);
        Mockito.when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        return rsrcCtxWrapper;
    }

    Object getWebAppExcEntity(javax.ws.rs.WebApplicationException wex) {
        javax.ws.rs.core.Response resp = wex.getResponse();
        return resp.getEntity();
    }

    Object getWebAppExcMapValue(javax.ws.rs.WebApplicationException wex, String header) {
        javax.ws.rs.core.MultivaluedMap<String, Object> mvmap = wex.getResponse().getMetadata();
        Object obj = mvmap.getFirst(header);
        return obj;
    }

    private ZMSImpl zmsInit() {
        // we want to make sure we start we clean dir structure
        FileConnection.deleteDirectory(new File(ZMS_DATA_STORE_PATH));

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();

        rsrcPrince = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        ((SimplePrincipal) rsrcPrince).setUnsignedCreds("v=U1;d=user;n=user1");
        
        Mockito.when(mockDomRestRsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockDomRestRsrcCtx.principal()).thenReturn(rsrcPrince);
        Mockito.when(mockDomRsrcCtx.context()).thenReturn(mockDomRestRsrcCtx);
        Mockito.when(mockDomRsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockDomRsrcCtx.principal()).thenReturn(rsrcPrince);

        ObjectStore store = new FileObjectStore(new File(ZMS_DATA_STORE_PATH));

        String pubKeyName = System.getProperty(ZMSTest.ZMS_PROP_PUBLIC_KEY);
        File pubKeyFile = new File(pubKeyName);
        pubKey = Crypto.encodedFile(pubKeyFile);
        
        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File privKeyFile = new File(privKeyName);
        privKey = Crypto.encodedFile(privKeyFile);
        PrivateKey privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        String privKeyId = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY_ID, "0");

        adminUser = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN);

        // enable product id support
        System.setProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "true");
        System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, "src/test/resources/solution_templates.json");

        Metric debugMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        ZMSImpl zmsObj = new ZMSImpl("localhost", store, debugMetric, privateKey,
                privKeyId, AuditLogFactory.getLogger(), null);
        
        ServiceIdentity service = createServiceObject("sys.auth",
                        "zms", "http://localhost", "/usr/bin/java", "root",
                        "users", "host1");

        zmsObj.putServiceIdentity(mockDomRsrcCtx, "sys.auth", "zms", auditRef, service);
        
        return zmsObj;
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
            members.add(new RoleMember().setMemberName(member1));
        }
        if (member2 != null) {
            members.add(new RoleMember().setMemberName(member2));
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

        List<Assertion> assertList = new ArrayList<Assertion>();
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
        
        List<PublicKeyEntry> publicKeyList = new ArrayList<PublicKeyEntry>();
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
        
        List<String> hosts = new ArrayList<String>();
        hosts.add(host);
        service.setHosts(hosts);
        
        return service;
    }
    
    ZMSImpl getZmsImpl(String storeDir, AuditLogger alogger) {
        
        FileConnection.deleteDirectory(new File(storeDir));
        ObjectStore store = new FileObjectStore(new File(storeDir));
        
        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File   privKeyFile = new File(privKeyName);
        String privKey = Crypto.encodedFile(privKeyFile);
        PrivateKey privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));

        String privKeyId = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY_ID, "0");
        ServiceIdentity service = createServiceObject("sys.auth",
                        "zms", "http://localhost", "/usr/bin/java", "root",
                        "users", "host1");

        Metric debugMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        ZMSImpl zmsObj = new ZMSImpl("localhost", store, debugMetric, privateKey,
                privKeyId, alogger, null);
        zmsObj.putServiceIdentity(mockDomRsrcCtx, "sys.auth", "zms", auditRef, service);
        zmsObj.setProviderClientClass(ProviderMockClient.class);
        return zmsObj;
    }

    public void setupServiceId() throws IOException {

        Path path = Paths.get("./src/test/resources/zms_public_k1.pem");
        pubKeyK1 = Crypto.ybase64((new String(Files.readAllBytes(path))).getBytes());

        path = Paths.get("./src/test/resources/zms_public_k2.pem");
        pubKeyK2 = Crypto.ybase64(new String(Files.readAllBytes(path)).getBytes());

        path = Paths.get("./src/test/resources/zms_private_k1.pem");
        privKeyK1 = Crypto.ybase64(new String(Files.readAllBytes(path)).getBytes());
 
        path = Paths.get("./src/test/resources/zms_private_k2.pem");
        privKeyK2 = Crypto.ybase64(new String(Files.readAllBytes(path)).getBytes());

        zms = zmsInit();
        zms.setProviderClientClass(ProviderMockClient.class);
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

        List<String> admins = new ArrayList<String>();
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
        
        String auditCheck   = "testaudit";
        String caller     = "testCheckDomainAuditEnabledFlagTrueRefValid";
        Domain dom = zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller);
        assertNotNull(dom);
    }

    @Test
    public void testGetResourceAccessList() {
        try {
            // currently in the filestore that we're using for our unit
            // we don't have an implementation for this method
            zms.dbService.getResourceAccessList("principal", "UPDATE");
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

        List<String> admins = new ArrayList<String>();
        admins.add(admin);
        dom.setAdminUsers(admins);

        return dom;
    }
    
    @Test
    public void testCheckDomainAuditEnabledFlagTrueRefNull() {
        
        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck   = null;
        String caller     = "testCheckDomainAuditEnabledFlagTrueRefNull";
        try {
            zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller);
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        }
    }

    @Test
    public void testCheckDomainAuditEnabledFlagTrueRefEmpty() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck   = "";  // empty string
        String caller     = "testCheckDomainAuditEnabledFlagTrueRefEmpty";
        try {
            zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller);
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        }
    }

    @Test
    public void testCheckDomainAuditEnabledFlagFalseRefValid() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck   = "testaudit";
        String caller     = "testCheckDomainAuditEnabledFlagFalseRefValid";
        Domain dom = zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller);
        assertNotNull(dom);
    }

    @Test
    public void testCheckDomainAuditEnabledFlagFalseRefNull() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck   = null;
        String caller     = "testCheckDomainAuditEnabledFlagFalseRefNull";
        Domain dom = zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller);
        assertNotNull(dom);
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
        
        String auditCheck   = "";
        String caller     = "testCheckDomainAuditEnabledFlagFalseRefEmpty";
        Domain dom = zms.dbService.checkDomainAuditEnabled(mockFileConn, domainName, auditCheck, caller);
        assertNotNull(dom);
    }
    
    @Test
    public void testCheckDomainAuditEnabledInvalidDomain() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain(domainName);
        
        String auditCheck   = "testaudit";
        String caller     = "testCheckDomainAuditEnabledDefault";
        try {
            zms.dbService.checkDomainAuditEnabled(mockFileConn, "unknown_domain", auditCheck, caller);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testUpdateTemplateRoleNoMembers() {
        Role role = new Role().setName("_domain_:role.readers");
        Role newRole = zms.dbService.updateTemplateRole(role, "athenz", "readers");
        assertEquals("athenz:role.readers", newRole.getName());
        assertEquals(0, newRole.getRoleMembers().size());
    }
    
    @Test
    public void testUpdateTemplateRoleWithTrust() {
        Role role = new Role().setName("_domain_:role.readers").setTrust("trustdomain");
        Role newRole = zms.dbService.updateTemplateRole(role, "athenz", "readers");
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
        role.setRoleMembers(members);
        
        Role newRole = zms.dbService.updateTemplateRole(role, "athenz", "readers");
        assertEquals("athenz:role.readers", newRole.getName());
        List<RoleMember> newMembers = newRole.getRoleMembers();
        assertEquals(2, newMembers.size());
        
        List<String> checkList = new ArrayList<String>();
        checkList.add("user.user1");
        checkList.add("user.user2");
        checkRoleMember(checkList, newMembers);
    }
    
    @Test
    public void testUpdateTemplatePolicy() {
        Policy policy = createPolicyObject("_domain_", "policy1",
                "role1", true, "read", "_domain_:*", AssertionEffect.ALLOW);
        
        Policy newPolicy = zms.dbService.updateTemplatePolicy(policy, "athenz", "policy1");
        
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
    public void testUpdateTemplatePolicyNoAssertions() {
        Policy policy = new Policy().setName("_domain_:policy.policy1");
        Policy newPolicy = zms.dbService.updateTemplatePolicy(policy, "athenz", "policy1");
        
        assertEquals("athenz:policy.policy1", newPolicy.getName());
        List<Assertion> assertions = newPolicy.getAssertions();
        assertEquals(0, assertions.size());
    }
    
    @Test
    public void testUpdateTemplatePolicyAssertionNoRewrite() {
        Policy policy = createPolicyObject("_domain_", "policy1",
                "coretech:role.role1", false, "read", "coretech:*", AssertionEffect.ALLOW);
        
        Policy newPolicy = zms.dbService.updateTemplatePolicy(policy, "athenz", "policy1");
        
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
    public void testIsTenantRolePrefixMatchNoPrefixMatch() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.role1",
                "coretech2.role.", "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchResGroupNullTenant() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.res_group.reader",
                "coretech.storage.", null));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchResGroupMultipleComponents() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.group1.group2.group3.reader",
                "coretech.storage.", "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchResGroupSingleComponent() {
        assertTrue(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.group1",
                "coretech.storage.", "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchSubdomainCheckExists() {
        
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockFileConn).getDomain("tenant.sub");
        
        // since subdomain exists - we're assuming is not a tenant role
        
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.sub.reader",
                "coretech.storage.", "tenant"));
    }
    
    @Test
    public void testIsTenantRolePrefixMatchSubdomainCheckDoesNotExist() {
        
        Mockito.doReturn(null).when(mockFileConn).getDomain("tenant.sub");
        
        // subdomain does not exist thus this is a tenant role
        
        assertTrue(zms.dbService.isTenantRolePrefixMatch(mockFileConn, "coretech.storage.sub.reader",
                "coretech.storage.", "tenant"));
    }

    @Test
    public void testIsTrustRoleForTenantPrefixNoMatch() {
        
        assertFalse(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech2.storage.tenant.", "athenz"));
    }
    
    @Test
    public void testIsTrustRoleForTenantNoRole() {
        
        Mockito.doReturn(null).when(mockFileConn).getRole("sports", "coretech.storage.tenant.admin");

        assertFalse(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", "athenz"));
    }
    
    @Test
    public void testIsTrustRoleForTenantNoRoleTrust() {
        
        Role role = new Role().setName(ZMSUtils.roleResourceName("sports",  "coretech.storage.tenant.admin"));
        Mockito.doReturn(role).when(mockFileConn).getRole("sports", "coretech.storage.tenant.admin");
        
        assertFalse(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", "athenz"));
    }
    
    @Test
    public void testIsTrustRoleForTenantRoleTrustMatch() {
        
        Role role = new Role().setName(ZMSUtils.roleResourceName("sports",  "coretech.storage.tenant.admin"))
                .setTrust("athenz");
        Mockito.doReturn(role).when(mockFileConn).getRole("sports", "coretech.storage.tenant.admin");
        
        assertTrue(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", "athenz"));
    }
    
    @Test
    public void testIsTrustRoleForTenantRoleTrustNoMatch() {
        
        Role role = new Role().setName(ZMSUtils.roleResourceName("sports",  "coretech.storage.tenant.admin"))
                .setTrust("athenz2");
        Mockito.doReturn(role).when(mockFileConn).getRole("sports", "coretech.storage.tenant.admin");
        
        assertFalse(zms.dbService.isTrustRoleForTenant(mockFileConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", "athenz"));
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
            assertTrue(ex.getCode() == 400);
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
            entityRes = zms.getEntity(mockDomRsrcCtx, domainName, entityName);
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

        Role role = zms.getRole(mockDomRsrcCtx, domainName, roleName, true, false);
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
    public void testExecuteDeletePublicKeyEntryLastKeyNotAllowed() {
        
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

        try {
            zms.dbService.executeDeletePublicKeyEntry(mockDomRsrcCtx, domainName, serviceName,
                    "2", auditRef, "deletePublicKeyEntry");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
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

        // our role counti is +1 because of the admin role
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
    public void testExecuteDeleteTenantRoles() {

        String tenantDomain = "deltenantrolesdom1";
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

        TenantRoles roles = zms.getTenantRoles(mockDomRsrcCtx, providerDomain, providerService,
                tenantDomain);
        assertNotNull(roles);
        assertEquals(roles.getDomain(), providerDomain);
        assertEquals(roles.getService(), providerService);
        assertEquals(roles.getTenant(), tenantDomain);
        assertEquals(roles.getRoles().size(), 0);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        TenantRoles tenantRoles = new TenantRoles().setDomain(providerDomain)
                .setService(providerService).setTenant(tenantDomain)
                .setRoles(roleActions);

        zms.putTenantRoles(mockDomRsrcCtx, providerDomain, providerService, tenantDomain,
                auditRef, tenantRoles);

        RoleList roleList = zms.getRoleList(mockDomRsrcCtx, providerDomain, null, null);
        assertNotNull(roleList);

        boolean readerFound = false;
        boolean writerFound = false;
        for (String roleName : roleList.getNames()) {
            if (roleName.contains("reader")) {
                readerFound = true;
            } else if (roleName.contains("writer")) {
                writerFound = true;
            }
        }

        assertTrue(readerFound);
        assertTrue(writerFound);

        PolicyList policyList = zms.getPolicyList(mockDomRsrcCtx, providerDomain, null, null);
        assertNotNull(policyList);

        readerFound = false;
        writerFound = false;
        for (String policy : policyList.getNames()) {
            if (policy.contains("reader")) {
                readerFound = true;
            } else if (policy.contains("writer")) {
                writerFound = true;
            }
        }

        assertTrue(readerFound);
        assertTrue(writerFound);

        zms.dbService.executeDeleteTenantRoles(mockDomRsrcCtx, providerDomain, providerService, tenantDomain,
                null, auditRef, "deleteTenantRoles");

        roleList = zms.getRoleList(mockDomRsrcCtx, providerDomain, null, null);
        assertNotNull(roleList);

        readerFound = false;
        writerFound = false;
        for (String roleName : roleList.getNames()) {
            if (roleName.contains("reader")) {
                readerFound = true;
            } else if (roleName.contains("writer")) {
                writerFound = true;
            }
        }

        assertFalse(readerFound);
        assertFalse(writerFound);

        policyList = zms.getPolicyList(mockDomRsrcCtx, providerDomain, null, null);
        assertNotNull(policyList);

        readerFound = false;
        writerFound = false;
        for (String policy : policyList.getNames()) {
            if (policy.contains("reader")) {
                readerFound = true;
            } else if (policy.contains("writer")) {
                writerFound = true;
            }
        }

        assertFalse(readerFound);
        assertFalse(writerFound);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
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
        assertEquals("testOrg", resDom1.getOrg());
        assertTrue(resDom1.getEnabled());
        assertFalse(resDom1.getAuditEnabled());
        
        // update meta with values for account and product ids
        
        DomainMeta meta = new DomainMeta().setDescription("Test2 Domain").setOrg("NewOrg")
                .setEnabled(true).setAuditEnabled(false).setAccount("12345").setYpmId(Integer.valueOf(1001));
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, auditRef, "putDomainMeta");

        Domain resDom2 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom2);
        assertEquals("Test2 Domain", resDom2.getDescription());
        assertEquals("NewOrg", resDom2.getOrg());
        assertTrue(resDom2.getEnabled());
        assertFalse(resDom2.getAuditEnabled());
        assertEquals(Integer.valueOf(1001), resDom2.getYpmId());
        assertEquals("12345", resDom2.getAccount());

        // now update without account and product ids
        
        meta = new DomainMeta().setDescription("Test2 Domain-New").setOrg("NewOrg-New")
                .setEnabled(true).setAuditEnabled(false);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, "metadom1", meta, auditRef, "putDomainMeta");

        Domain resDom3 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom3);
        assertEquals("Test2 Domain-New", resDom3.getDescription());
        assertEquals("NewOrg-New", resDom3.getOrg());
        assertTrue(resDom3.getEnabled());
        assertFalse(resDom3.getAuditEnabled());
        assertEquals(Integer.valueOf(1001), resDom3.getYpmId());
        assertEquals("12345", resDom3.getAccount());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MetaDom1", auditRef);
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

        Role role = zms.getRole(mockDomRsrcCtx, domainName, roleName, false, false);
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
            if (entry.getId().equals("1")) {
                foundKey1 = true;
            } else if (entry.getId().equals("2")) {
                foundKey2 = true;
            } else if (entry.getId().equals("zone1")) {
                foundKeyZONE1 = true;
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
    public void testExecutePutRole() {

        String domainName = "executeputroledom1";
        String roleName = "role1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole");

        Role role3 = zms.getRole(mockDomRsrcCtx, domainName, roleName, false, false);
        assertNotNull(role3);
        assertEquals(role3.getName(), domainName + ":role." + roleName);
        assertNull(role3.getTrust());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
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
    public void testExecutePutServiceIdentityRetryException() {

        String domainName = "serviceadddom1";
        String serviceName = "service1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockObjStore.getConnection(false)).thenReturn(mockFileConn);
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
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
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
    public void testExecutePutTenantRoles() throws Exception {
        
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
        
        ProviderMockClient.setReturnTenantRoles(true);
        zms.putTenancy(mockDomRsrcCtx, tenantDomain, "coretech.storage", auditRef, tenant);
        
        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }

        zms.dbService.executePutTenantRoles(mockDomRsrcCtx, providerDomain, providerService,
                tenantDomain, null, roleActions, auditRef, "putTenantRoles");
        
        Tenancy tenant1 = zms.getTenancy(mockDomRsrcCtx, tenantDomain, "coretech.storage");
        assertNotNull(tenant1);

        zms.deleteTenancy(mockDomRsrcCtx, tenantDomain, "coretech.storage", auditRef);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
    }
    
    void verifyPolicies(String domainName) {
        
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
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());
        
        // verify that our policy collections includes the policies defined in the template
        
        verifyPolicies(domainName);
        
        // Try applying the template again. This time, there should be no changes.
        
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);

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
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove vipng again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng", 
                auditRef, caller);
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false));
        
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
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the roles defined in template
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false);
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
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);

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
    public void testApplySolutionTemplateEmptyDomain() {
        
        String domainName = "solutiontemplate-ok";
        String caller = "testApplySolutionTemplateDomainExistingPolicies";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // apply the template
        
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());
        
        // verify that our policy collections includes the policies defined in the template
        
        names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        // Try applying the template again. This time, there should be no changes.
        
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);

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
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false));
        
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove vipng again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng", 
                auditRef, caller);
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false));
        
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
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);
        
        // apply the template again - nothing should change

        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertNull(role.getRoleMembers());
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false);
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
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false));
        
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
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);
        
        // apply the template again - nothing should change

        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, templates, auditRef, caller);
        
        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());
        
        // verify that our role collection includes the expected roles
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        
        // this should be our own role that we created previously
        
        Role role = zms.dbService.getRole(domainName, "vip_admin", false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertEquals(2, role.getRoleMembers().size());
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkRoleMember(checkList, role.getRoleMembers());
        
        // the rest should be whatever we had in the template
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false);
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
        
        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin"));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin"));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false));
        
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
        
        zms.dbService.setupTenantAdminPolicy(mockDomRsrcCtx, tenantDomain, providerDomain,
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

        DBService dbService = new DBService(null, null, "user");
        assertEquals(120, dbService.defaultRetryCount);
        assertEquals(250, dbService.retrySleepTime);

        System.clearProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_COUNT);
        System.clearProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_SLEEP_TIME);
    }
    
    @Test
    public void testShouldRetryOperation() {
        
        FileObjectStore store = new FileObjectStore(new File("."));
        DBService dbService = new DBService(store, null, "user");
        
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
        dom1.setYpmId(Integer.valueOf(101));
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
        dom1.setYpmId(Integer.valueOf(199));
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
        ZMSImpl.RsrcCtxWrapper rsrcCtx = Mockito.mock(ZMSImpl.RsrcCtxWrapper.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        assertEquals(zms.dbService.getPrincipalName(rsrcCtx), "user.user1");
        
        assertNull(zms.dbService.getPrincipalName(null));
        
        ZMSImpl.RsrcCtxWrapper rsrcCtx2 = Mockito.mock(ZMSImpl.RsrcCtxWrapper.class);
        Mockito.when(rsrcCtx2.principal()).thenReturn(null);
        assertNull(zms.dbService.getPrincipalName(rsrcCtx2));
    }
    
    @Test
    public void testAuditLogPublicKeyEntry() {
        StringBuilder auditDetails = new StringBuilder();
        assertFalse(zms.dbService.auditLogPublicKeyEntry(auditDetails, "keyId", true));
        assertEquals("{id: \"keyId\"}", auditDetails.toString());
        
        auditDetails.setLength(0);
        assertFalse(zms.dbService.auditLogPublicKeyEntry(auditDetails, "keyId", false));
        assertEquals(",{id: \"keyId\"}", auditDetails.toString());
    }
    
    @Test
    public void testApplySolutionTemplateNullTemplat() {
        StringBuilder auditDetails = new StringBuilder();
        assertTrue(zms.dbService.applySolutionTemplate(null, null, "template1", null, true, null, null, auditDetails));
        assertEquals("{name: \"template1\"}", auditDetails.toString());
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
        
        Role role = zms.dbService.getRole(domainName, roleName, false, false);
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
        
        Role role = zms.dbService.getRole(domainName1, roleName, false, true);
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
        
        assertNull(zms.dbService.getDelegatedRoleMembers("dom1", "dom1", "role1"));
        assertNull(zms.dbService.getDelegatedRoleMembers("dom1", "invalid-domain", "role1"));
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

        List<RoleMember> members = zms.dbService.getDelegatedRoleMembers(domainName1, domainName2, roleName);
        assertEquals(3, members.size());
        
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkRoleMember(checkList, members);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName1, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName2, auditRef);
    }
}
