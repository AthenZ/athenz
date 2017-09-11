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

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.mockito.Mockito;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.*;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.impl.SimpleServiceIdentityProvider;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.impl.DefaultAuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.impl.DefaultAuditLogger;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.provider.ProviderMockClient;
import com.yahoo.athenz.zms.ZMSImpl.AccessStatus;
import com.yahoo.athenz.zms.ZMSImpl.AthenzObject;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.file.FileConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;

public class ZMSImplTest {

    public static final String ZMS_PROP_PUBLIC_KEY = "athenz.zms.publickey";

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
    @Mock RsrcCtxWrapper mockDomRsrcCtx;
    @Mock com.yahoo.athenz.common.server.rest.ResourceContext mockDomRestRsrcCtx;
    Principal rsrcPrince    = null; // used with the mockDomRestRsrcCtx
    AuditLogger auditLogger = null; // default audit logger
    
    @Mock RsrcCtxWrapper mockDomRsrcCtx2;
    @Mock com.yahoo.athenz.common.server.rest.ResourceContext mockDomRestRsrcCtx2;

    private static final String MOCKCLIENTADDR = "10.11.12.13";
    private static final String ZMS_DATA_STORE_FILE = "zms_root";
    
    @Mock HttpServletRequest mockServletRequest;
    @Mock HttpServletResponse mockServletResponse;
    
    private static final String ZMS_DATA_STORE_PATH = "/tmp/zms_core_unit_tests/zms_root";

    static final Struct TABLE_PROVIDER_ROLE_ACTIONS = new Struct()
            .with("admin", "*").with("writer", "WRITE").with("reader", "READ");

    static final Struct RESOURCE_PROVIDER_ROLE_ACTIONS = new Struct()
            .with("writer", "WRITE").with("reader", "READ");

    static final int BASE_PRODUCT_ID = 400000000; // these product ids will lie in 400 million range
    static java.util.Random domainProductId = new java.security.SecureRandom();
    static synchronized int getRandomProductId() {
        return BASE_PRODUCT_ID + domainProductId.nextInt(99999999);
    }
    
    static class TestAuditLogger implements AuditLogger {

        List<String> logMsgList = new ArrayList<>();

        public List<String> getLogMsgList() {
            return logMsgList;
        }

        public void clear() {
            logMsgList.clear();
        }

        public void log(String logMsg, String msgVersionTag) {
            logMsgList.add(logMsg);
        }
        public void log(AuditLogMsgBuilder msgBldr) {
            String msg = msgBldr.build();
            logMsgList.add(msg);
        }
        @Override
        public AuditLogMsgBuilder getMsgBuilder() {
            return new DefaultAuditLogMsgBuilder();
        }
    }

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        Mockito.when(mockServletRequest.isSecure()).thenReturn(true);
        
        System.setProperty(ZMSConsts.ZMS_PROP_FILE_NAME, "src/test/resources/zms.properties");
        System.setProperty(ZMSConsts.ZMS_PROP_METRIC_FACTORY_CLASS, ZMSConsts.ZMS_METRIC_FACTORY_CLASS);
        System.setProperty(ZMSConsts.ZMS_PROP_PROVIDER_ENDPOINTS, ".athenzcompany.com");
        
        System.setProperty(ZMSConsts.ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/zms_private.pem");
        System.setProperty(ZMS_PROP_PUBLIC_KEY, "src/test/resources/zms_public.pem");
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN, "user.testadminuser");
        System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME,
                "src/test/resources/authorized_services.json");
        System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME,
                "src/test/resources/solution_templates.json");
        auditLogger = new DefaultAuditLogger();
        
        initializeZms();
    }

    com.yahoo.athenz.zms.ResourceContext createResourceContext(Principal prince) {
        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx =
                Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(prince);
        Mockito.when(rsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(rsrcCtx.response()).thenReturn(mockServletResponse);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
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

        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx =
                Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(request);
        Mockito.when(rsrcCtx.response()).thenReturn(mockServletResponse);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
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
        String unsignedCreds = "v=U1;d=user;n=user1";
        rsrcPrince = SimplePrincipal.create("user", "user1", unsignedCreds + ";s=signature",
                0, principalAuthority);
        ((SimplePrincipal) rsrcPrince).setUnsignedCreds(unsignedCreds);
        
        Mockito.when(mockDomRestRsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockDomRestRsrcCtx.principal()).thenReturn(rsrcPrince);
        Mockito.when(mockDomRsrcCtx.context()).thenReturn(mockDomRestRsrcCtx);
        Mockito.when(mockDomRsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockDomRsrcCtx.principal()).thenReturn(rsrcPrince);

        String pubKeyName = System.getProperty(ZMS_PROP_PUBLIC_KEY);
        File pubKeyFile = new File(pubKeyName);
        pubKey = Crypto.encodedFile(pubKeyFile);
        
        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File privKeyFile = new File(privKeyName);
        privKey = Crypto.encodedFile(privKeyFile);

        adminUser = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN);
        
        System.setProperty(ZMSConsts.ZMS_PROP_FILE_STORE_PATH, "/tmp/zms_core_unit_tests/");
        System.clearProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE);
        System.clearProperty(ZMSConsts.ZMS_PROP_JDBC_RO_STORE);
        
        ZMSImpl zmsObj = new ZMSImpl();
        zmsObj.serverPublicKeyMap.put("1", pubKeyK1);
        zmsObj.serverPublicKeyMap.put("2", pubKeyK2);
        ZMSImpl.serverHostName = "localhost";

        return zmsObj;
    }
    
    ZMSImpl getZmsImpl(String storeFile, AuditLogger alogger) {
        
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
        
        System.clearProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE);
        System.clearProperty(ZMSConsts.ZMS_PROP_JDBC_RO_STORE);
        System.setProperty(ZMSConsts.ZMS_PROP_FILE_STORE_NAME, storeFile);
        System.setProperty(ZMSConsts.ZMS_PROP_FILE_STORE_PATH, "/tmp/zms_core_unit_tests/");

        ZMSImpl zmsObj = new ZMSImpl();
        zmsObj.auditLogger = alogger;
        zmsObj.dbService.auditLogger = alogger;
        
        ZMSImpl.serverHostName = "localhost";

        ServiceIdentity service = createServiceObject("sys.auth", "zms",
                "http://localhost", "/usr/bin/java", "root", "users", "host1");
        
        zmsObj.putServiceIdentity(mockDomRsrcCtx, "sys.auth", "zms", auditRef, service);
        zmsObj.setProviderClientClass(ProviderMockClient.class);
        return zmsObj;
    }

    public void initializeZms() throws IOException {

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

    @AfterClass(alwaysRun=true)
    public void shutdown() {
        FileConnection.deleteDirectory(new File(ZMS_DATA_STORE_PATH));
    }

    private Membership generateMembership(String roleName, String memberName) {
        return generateMembership(roleName, memberName, null);
    }
    
    private Membership generateMembership(String roleName, String memberName,
            Timestamp expiration) {
        Membership mbr = new Membership();
        mbr.setRoleName(roleName);
        mbr.setMemberName(memberName);
        mbr.setIsMember(true);
        mbr.setExpiration(expiration);
        return mbr;
    }
    
    private TopLevelDomain createTopLevelDomainObject(String name,
            String description, String org, String admin) {

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setYpmId(getRandomProductId());

        List<String> admins = new ArrayList<String>();
        admins.add(admin);
        dom.setAdminUsers(admins);

        return dom;
    }

    private UserDomain createUserDomainObject(String name, String description, String org) {

        UserDomain dom = new UserDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);

        return dom;
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

    private DomainMeta createDomainMetaObject(String description, String org,
            Boolean enabled, Boolean auditEnabled, String account, Integer productId) {

        DomainMeta meta = new DomainMeta();
        meta.setDescription(description);
        meta.setOrg(org);
        if (enabled != null) {
            meta.setEnabled(enabled);
        }
        if (auditEnabled != null) {
            meta.setAuditEnabled(auditEnabled);
        }
        if (account != null) {
            meta.setAccount(account);
        }
        meta.setYpmId(productId);

        return meta;
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
    
    private Role createRoleObject(String domainName, String roleName,
            String trust) {
        Role role = new Role();
        role.setName(ZMSUtils.roleResourceName(domainName, roleName));
        role.setTrust(trust);
        return role;
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
    
    private Policy createPolicyObject(String domainName, String policyName,
            String roleName, String action,  String resource, 
            AssertionEffect effect) {
        return createPolicyObject(domainName, policyName, roleName, true,
                action, resource, effect);
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

    private Policy createPolicyObject(String domainName, String policyName) {
        return createPolicyObject(domainName, policyName, "Role1", "*",
                domainName + ":*", AssertionEffect.ALLOW);
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
    
    private Entity createEntityObject(String entityName) {

        Entity entity = new Entity();
        entity.setName(entityName);

        Struct value = new Struct();
        value.put("Key1", "Value1");
        entity.setValue(value);

        return entity;
    }
    
    private void setupTenantDomainProviderService(ZMSImpl zms, String tenantDomain, String providerDomain,
            String providerService, String providerEndpoint) {

        // create domain for tenant
        //
        TopLevelDomain dom1 = createTopLevelDomainObject(tenantDomain,
                "Test Tenant Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        // create domain for provider
        //
        TopLevelDomain domProv = createTopLevelDomainObject(providerDomain,
                "Test Provider Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, domProv);

        // create service identity for providerDomain.providerService
        //
        ServiceIdentity service = createServiceObject(
                providerDomain, providerService, providerEndpoint,
                "/usr/bin/java", "root", "users", "localhost");

        zms.putServiceIdentity(mockDomRsrcCtx, providerDomain, providerService, auditRef, service);
    }

    private void setupTenantDomainProviderService(String tenantDomain, String providerDomain,
            String providerService, String providerEndpoint) {
        setupTenantDomainProviderService(zms, tenantDomain, providerDomain, providerService, providerEndpoint);
    }
    
    private Tenancy createTenantObject(String domain, String service) {
        
        Tenancy tenant = new Tenancy();
        tenant.setDomain(domain);
        tenant.setService(service);
        
        return tenant;
    }

    @Test
    public void testSchema() {
        Schema schema = zms.schema();
        assertNotNull(schema);
    }

    @Test
    public void testGetAuditLogMsgBuilder() {
        AuditLogMsgBuilder msgBldr = ZMSUtils.getAuditLogMsgBuilder(mockDomRsrcCtx, auditLogger,
                "mydomain", auditRef, "myapi", "PUT");
        assertNotNull(msgBldr);
    }

    @Test
    public void testGetAuditLogMsgBuilderNullCtx() {
        AuditLogMsgBuilder msgBldr = ZMSUtils.getAuditLogMsgBuilder(null, auditLogger,
                "mydomain", auditRef, "myapi", "PUT");
        assertNotNull(msgBldr);
    }

    @Test
    public void testGetAuditLogMsgBuilderNullPrincipal() {
        ResourceContext ctx = createResourceContext(null);
        AuditLogMsgBuilder msgBldr = ZMSUtils.getAuditLogMsgBuilder(ctx, auditLogger,
                "mydomain", auditRef, "myapi", "PUT");
        assertNotNull(msgBldr);
    }

    @Test
    public void testGetAuditLogMsgBuilderTokenWithSig() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String userId     = "user1";
        String signature = "ABRACADABRA";
        String unsignedCreds = "v=U1;d=user;n=user1";
        Principal principal = SimplePrincipal.create("user", userId, unsignedCreds + ";s=" + signature,
                0, principalAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds); // set unsigned creds
        ResourceContext ctx = createResourceContext(principal);
        AuditLogMsgBuilder msgBldr = ZMSUtils.getAuditLogMsgBuilder(ctx, auditLogger,
                "mydomain", auditRef, "myapi", "PUT");
        assertNotNull(msgBldr);
        String who = msgBldr.who();
        assertNotNull(who);
        assertTrue(who.contains(userId));
        assertTrue(!who.contains(signature), "Should not contain the signature: " + who);
    }

    @Test
    public void testGetAuditLogMsgBuilderTokenSigMissing() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String userId     = "user1";
        String unsignedCreds = "v=U1;d=user;n=user1";
        Principal principal = SimplePrincipal.create("user", userId, unsignedCreds,
                0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal);
        AuditLogMsgBuilder msgBldr = ZMSUtils.getAuditLogMsgBuilder(ctx, auditLogger,
                "mydomain", auditRef, "myapi", "PUT");
        assertNotNull(msgBldr);
        String who = msgBldr.who();
        assertNotNull(who);
        assertTrue(who.contains(userId));
    }

    @Test
    public void testGetAuditLogMsgBuilderNullParams() {
        AuditLogMsgBuilder msgBldr = ZMSUtils.getAuditLogMsgBuilder(mockDomRsrcCtx, auditLogger,
                null, null, null, null);
        assertNotNull(msgBldr);
    }

    @Test
    public void testGetDomain() {
        Domain domain = zms.getDomain(mockDomRsrcCtx, "sys.auth");
        assertNotNull(domain);
    }
    
    @Test
    public void testGetDomainThrowException() {
        try {
            zms.getDomain(mockDomRsrcCtx, "wrongDomain");
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test(groups="post-domain-tests")
    public void testPostDomain() {
        String domName = "olddominion";
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domName, auditRef);
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(domName);
        dom.setDescription("old virginny");
        dom.setOrg("universities");
        dom.setYpmId(1930);

        List<String> admins = new ArrayList<String>();
        admins.add(adminUser);
        dom.setAdminUsers(admins);

        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        // post subdomain
        String subDomName = "extension";
        SubDomain subDom = createSubDomainObject(subDomName, domName,
                "old dominion extension", "education", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, domName, auditRef, subDom);

        // post sub domain that is too big - default length is 128
        String subDomNameBad = "extension0extension0extension0extension0";
        subDomNameBad = subDomNameBad.concat("extension0extension0extension0extension0");
        subDomNameBad = subDomNameBad.concat("extension0extension0extension0extension0");

        subDom = createSubDomainObject(subDomNameBad, domName,
                "old dominion extension+++", "education", adminUser);
        try {
            zms.postSubDomain(mockDomRsrcCtx, domName, auditRef, subDom);
            fail("requesterror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid SubDomain name"));
            assertTrue(ex.getMessage().contains("name length cannot exceed"));
        }

        zms.deleteSubDomain(mockDomRsrcCtx, domName, subDomName, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domName, auditRef);
    }
    
    @Test(groups="post-domain-tests")
    public void testPostDomainNullObject() {
        try {
            zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null);
            fail("requesterror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test(groups="post-domain-tests")
    public void testPostTopLevelDomainNoProductId() {
        
        // enable product id support
        
        System.setProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "true");
        ZMSImpl zmsImpl = zmsInit();
        
        String domName = "jabberwocky";
        try {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domName, auditRef);
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(domName);
        dom.setDescription("mythic animal");
        dom.setOrg("animals");

        List<String> admins = new ArrayList<String>();
        admins.add(adminUser);
        dom.setAdminUsers(admins);

        try {
            zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);
            fail("requesterror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Product Id is required when creating top level domain"));
        }
        
        System.clearProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT);
    }

    @Test(groups="post-domain-tests")
    public void testPostTopLevelDomainNameTooLong() {
        String domName = "a234567890";
        StringBuilder dname = new StringBuilder();
        dname.append(domName).append(domName).append(domName).append(domName);
        dname.append(domName).append(domName).append(domName).append(domName);
        dname.append(domName).append(domName).append(domName).append(domName);
        dname.append("a23456789"); // have 129 chars - default is 128
        domName = dname.toString();
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domName, auditRef);
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(domName);
        dom.setDescription("bigun");
        dom.setOrg("bigdog");

        List<String> admins = new ArrayList<String>();
        admins.add(adminUser);
        dom.setAdminUsers(admins);

        try {
            zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);
            fail("requesterror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("name length cannot exceed"));
        }
    }

    @Test(groups="post-domain-tests")
    public void testPostDomainNameOnSizeLimit() {

        // set the domain size limit to 45
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_NAME_MAX_SIZE, "45");

        ZMSImpl zmsImpl = zmsInit();

        String domName = "a234567890";
        StringBuilder dname = new StringBuilder();
        dname.append(domName).append(domName).append(domName).append(domName);
        dname.append("a2345"); // have 45 chars
        domName = dname.toString();
        try {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domName, auditRef);
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(domName);
        dom.setDescription("bigun");
        dom.setOrg("bigdog");
        dom.setYpmId(999999);

        List<String> admins = new ArrayList<String>();
        admins.add(adminUser);
        dom.setAdminUsers(admins);

        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        // post sub domain which will be too big by 1 char
        String subDomNameBad = "B";
        SubDomain subDom = createSubDomainObject(subDomNameBad, domName,
                "1 char too many", "dogs", adminUser);
        try {
            zmsImpl.postSubDomain(mockDomRsrcCtx, domName, auditRef, subDom);
            fail("requesterror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid SubDomain name"));
            assertTrue(ex.getMessage().contains("name length cannot exceed"));
        }

        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domName, auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_DOMAIN_NAME_MAX_SIZE);
    }

    @Test
    public void testPostTopLevelDomainNameReduceSizeLimitTooSmall() {

        // lower name length to 5 which should be reset internally to the default
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_NAME_MAX_SIZE, "5");
        ZMSImpl zmsImpl = zmsInit();

        String domName = "abcdef7890";
        try {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domName, auditRef);
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(domName);
        dom.setDescription("bigun");
        dom.setOrg("bigdog");
        dom.setYpmId(77777);

        List<String> admins = new ArrayList<String>();
        admins.add(adminUser);
        dom.setAdminUsers(admins);

        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domName, auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_DOMAIN_NAME_MAX_SIZE);
    }

    @Test
    public void testGetDomainList() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ListDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("ListDom2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        DomainList domList = zms.getDomainList(mockDomRsrcCtx, null, null, null, null,
                null, null, null, null, null);
        assertNotNull(domList);

        assertTrue(domList.getNames().contains("ListDom1".toLowerCase()));
        assertTrue(domList.getNames().contains("ListDom2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDom2", auditRef);
    }

    @Test
    public void testGetDomainListByAccount() {
        
        String domainName = "lookupdomainaccount";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setAccount("1234");
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        DomainList domList = zms.getDomainList(mockDomRsrcCtx, null, null, null, null,
                "1234", null, null, null, null);
        assertNotNull(domList.getNames());
        assertEquals(domList.getNames().size(), 1);
        assertEquals(domList.getNames().get(0), domainName);
        
        domList = zms.getDomainList(mockDomRsrcCtx, null, null, null, null,
                "1235", null, null, null, null);
        assertNull(domList.getNames());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetDomainListByProductId() {
        
        String domainName = "lookupdomainbyproductid";
        
        // enable product id support
        
        System.setProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "true");
        ZMSImpl zmsImpl = zmsInit();
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setYpmId(Integer.valueOf(101));
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        DomainList domList = zmsImpl.getDomainList(mockDomRsrcCtx, null, null, null,
                null, null, Integer.valueOf(101), null, null, null);
        assertNotNull(domList.getNames());
        assertEquals(domList.getNames().size(), 1);
        assertEquals(domList.getNames().get(0), domainName);
        
        domList = zmsImpl.getDomainList(mockDomRsrcCtx, null, null, null, null, null,
                Integer.valueOf(102), null, null, null);
        assertNull(domList.getNames());
        
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT);
    }
    
    @Test
    public void testGetDomainListIfModifiedSince() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ListDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        // let's get the current time
        
        Date now = new Date();
        
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
        }
        
        TopLevelDomain dom2 = createTopLevelDomainObject("ListDom2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        DateFormat df = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss zzz");
        String modifiedSince = df.format(now);
     
        // this is only a partial list since our file struct store
        // which the unit tests use does not support last modified
        // option so this will be tested in zms_system_test package
        
        DomainList domList = zms.getDomainList(mockDomRsrcCtx, null, null, null,
                null, null, null, null, null, modifiedSince);
        assertNotNull(domList);

        assertTrue(domList.getNames().contains("ListDom2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDom2", auditRef);
    }
    
    @Test
    public void testGetDomainListInvalidIfModifiedSince() {

        try {
            zms.getDomainList(mockDomRsrcCtx, null, null, null, null, null,
                    null, null, null, "abc");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        try {
            zms.getDomainList(mockDomRsrcCtx, null, null, null, null, null,
                    null, null, null, "May 20, 1099");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        try {
            zms.getDomainList(mockDomRsrcCtx, null, null, null, null, null,
                    null, null, null, "03:03:20 PM");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testGetDomainListParamsLimit() {

        TopLevelDomain dom1 = createTopLevelDomainObject("LimitDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("LimitDom2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        DomainList domList = zms.getDomainList(mockDomRsrcCtx, 1, null, null,
                null, null, null, null, null, null);
        assertTrue(domList.getNames().size() == 1);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "LimitDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "LimitDom2", auditRef);
    }

    @Test
    public void testGetDomainListParamsSkip() {

        TopLevelDomain dom1 = createTopLevelDomainObject("SkipDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("SkipDom2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        TopLevelDomain dom3 = createTopLevelDomainObject("SkipDom3",
                "Test Domain3", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom3);

        DomainList domList = zms.getDomainList(mockDomRsrcCtx, null, null, null,
                null, null, null, null, null, null);
        int size = domList.getNames().size();
        assertTrue(size > 3);

        // ask for only for 2 domains back
        domList = zms.getDomainList(mockDomRsrcCtx, 2, null, null, null, null,
                null, null, null, null);
        assertEquals(domList.getNames().size(), 2);

        // ask for the remaining domains
        DomainList remList = zms.getDomainList(mockDomRsrcCtx, null, domList.getNext(),
                null, null, null, null, null, null, null);
        assertEquals(remList.getNames().size(), size - 2);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "SkipDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "SkipDom2", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "SkipDom3", auditRef);
    }

    @Test
    public void testGetDomainListParamsPrefix() {

        TopLevelDomain dom1 = createTopLevelDomainObject("NoPrefixDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("PrefixDom2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        DomainList domList = zms.getDomainList(mockDomRsrcCtx, null, null,
                "Prefix", null, null, null, null, null, null);

        assertFalse(domList.getNames().contains("NoPrefixDom1".toLowerCase()));
        assertTrue(domList.getNames().contains("PrefixDom2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "NoPrefixDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PrefixDom2", auditRef);
    }

    @Test
    public void testGetDomainListParamsDepth() {

        TopLevelDomain dom1 = createTopLevelDomainObject("DepthDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        SubDomain dom2 = createSubDomainObject("DepthDom2", "DepthDom1",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "DepthDom1", auditRef, dom2);

        SubDomain dom3 = createSubDomainObject("DepthDom3",
                "DepthDom1.DepthDom2", "Test Domain3", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "DepthDom1.DepthDom2", auditRef, dom3);

        DomainList domList = zms.getDomainList(mockDomRsrcCtx, null, null, null,
                1, null, null, null, null, null);

        assertTrue(domList.getNames().contains("DepthDom1".toLowerCase()));
        assertTrue(domList.getNames().contains("DepthDom1.DepthDom2".toLowerCase()));
        assertFalse(domList.getNames().contains("DepthDom1.DepthDom2.DepthDom3".toLowerCase()));
        
        zms.deleteSubDomain(mockDomRsrcCtx, "DepthDom1.DepthDom2", "DepthDom3", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "DepthDom1", "DepthDom2", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "DepthDom1", auditRef);
    }
    
    @Test
    public void testGetDomainListThrowException() {
        try {
            zms.getDomainList(mockDomRsrcCtx, -1, null, null, null, null, null, null, null, null);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
    }

    @Test
    public void testCreateTopLevelDomain() {

        TopLevelDomain dom1 = createTopLevelDomainObject("AddTopDom1",
                "Test Domain1", "testOrg", adminUser);
        Domain resDom1 = zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        assertNotNull(resDom1);

        Domain resDom2 = zms.getDomain(mockDomRsrcCtx, "AddTopDom1");
        assertNotNull(resDom2);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "AddTopDom1", auditRef);
    }

    @Test
    public void testCreateTopLevelDomainOnceOnly() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_posttopdomonceonly";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        TopLevelDomain dom1 = createTopLevelDomainObject("AddOnceTopDom1",
                "Test Domain1", "testOrg", adminUser);
        Domain resDom1 = zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        assertNotNull(resDom1);

        // we should get an exception for the second call

        try {
            zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "AddOnceTopDom1", auditRef);
    }

    @Test
    public void testCreateSubDomain() {

        TopLevelDomain dom1 = createTopLevelDomainObject("AddSubDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        SubDomain dom2 = createSubDomainObject("AddSubDom2", "AddSubDom1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom1 = zms.postSubDomain(mockDomRsrcCtx, "AddSubDom1", auditRef, dom2);
        assertNotNull(resDom1);

        Domain resDom2 = zms.getDomain(mockDomRsrcCtx, "AddSubDom1.AddSubDom2");
        assertNotNull(resDom2);

        zms.deleteSubDomain(mockDomRsrcCtx, "AddSubDom1", "AddSubDom2", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "AddSubDom1", auditRef);
    }

    @Test
    public void testCreateUserDomain() {

        UserDomain dom1 = createUserDomainObject("hga", "Test Domain1", "testOrg");
        zms.postUserDomain(mockDomRsrcCtx, "hga", auditRef, dom1);

        Domain resDom2 = zms.getDomain(mockDomRsrcCtx, "user.hga");
        assertNotNull(resDom2);

        zms.deleteUserDomain(mockDomRsrcCtx, "hga", auditRef);
    }
    

    @Test
    public void testCreateUserDomainMismatch() {

        UserDomain dom1 = createUserDomainObject("hga", "Test Domain1", "testOrg");
        try {
            zms.postUserDomain(mockDomRsrcCtx, "hga2", auditRef, dom1);
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
        }
    }
    
    @Test
    public void testDeleteUserDomain() {

        UserDomain dom1 = createUserDomainObject("hga", "Test Domain1", "testOrg");
        zms.postUserDomain(mockDomRsrcCtx, "hga", auditRef, dom1);

        zms.deleteUserDomain(mockDomRsrcCtx, "hga", auditRef);

        try {
            zms.getDomain(mockDomRsrcCtx, "hga");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testCreateSubDomainWithVirtualLimit() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT, "2");
        ZMSImpl zmsTest = zmsInit();
        
        TopLevelDomain dom1 = createTopLevelDomainObject("SubDomNoVirtual",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        SubDomain dom = createSubDomainObject("sub1", "SubDomNoVirtual",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "SubDomNoVirtual", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub2", "SubDomNoVirtual",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "SubDomNoVirtual", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub3", "SubDomNoVirtual",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "SubDomNoVirtual", auditRef, dom);
        assertNotNull(resDom);
        
        zms.deleteSubDomain(mockDomRsrcCtx, "SubDomNoVirtual", "sub3", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "SubDomNoVirtual", "sub2", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "SubDomNoVirtual", "sub1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "SubDomNoVirtual", auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT);
    }
    
    @Test
    public void testCreateSubDomainVirtual() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT, "5");
        ZMSImpl zmsTest = zmsInit();
        
        SubDomain dom = createSubDomainObject("sub1", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub2", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub3", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub1a", "user.user1.sub1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1.sub1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub1aa", "user.user1.sub1.sub1a",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1.sub1.sub1a", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub1ab", "user.user1.sub1.sub1a",
                "Test Domain2", "testOrg", adminUser);
        try {
            zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1.sub1.sub1a", auditRef, dom);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        
        dom = createSubDomainObject("sub4", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        try {
            zms.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1.sub1.sub1a", "sub1aa", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1.sub1", "sub1a", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub3", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub2", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub1", auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT);
    }
    
    @Test
    public void testCreateSubDomainVirtualNoLimit() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT, "0");
        ZMSImpl zmsTest = zmsInit();
        
        SubDomain dom = createSubDomainObject("sub1", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub2", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub3", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub4", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub5", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub6", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zmsTest.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub6", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub5", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub4", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub3", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub2", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub1", auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT);
    }
    
    @Test
    public void testCreateSubDomainMismatchParent() {

        TopLevelDomain dom1 = createTopLevelDomainObject("AddSubMismatchParentDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        SubDomain dom2 = createSubDomainObject("AddSubDom2", "AddSubMismatchParentDom1",
                "Test Domain2", "testOrg", adminUser);
        
        try {
            zms.postSubDomain(mockDomRsrcCtx, "AddSubMismatchParentDom2", auditRef, dom2);
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 403);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "AddSubMismatchParentDom1", auditRef);
    }

    @Test
    public void testCreateSubdomainOnceOnly() {

        TopLevelDomain dom1 = createTopLevelDomainObject("AddOnceSubDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        SubDomain dom2 = createSubDomainObject("AddOnceSubDom2",
                "AddOnceSubDom1", "Test Domain2", "testOrg", adminUser);
        Domain resDom1 = zms.postSubDomain(mockDomRsrcCtx, "AddOnceSubDom1", auditRef, dom2);
        assertNotNull(resDom1);

        // we should get an exception for the second call

        try {
            zms.postSubDomain(mockDomRsrcCtx, "AddOnceSubDom1", auditRef, dom2);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zms.deleteSubDomain(mockDomRsrcCtx, "AddOnceSubDom1", "AddOnceSubDom2", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "AddOnceSubDom1", auditRef);
    }

    @Test
    public void testDeleteDomain() {
        TopLevelDomain dom = createTopLevelDomainObject(
            "TestDeleteDomain", null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        zms.deleteDomain(mockDomRsrcCtx, auditRef, "testdeletedomain", "testDeleteDomain");

        try {
            zms.getDomain(mockDomRsrcCtx, "TestDeleteDomain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteDomainNonExistant() {
        try {
            zms.deleteDomain(mockDomRsrcCtx, auditRef, "TestDeleteDomainNonExist", "testDeleteDomainNonExistant");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteDomainMissingAuditRef() {
        // create domain and require auditing
        String domain = "testdeletedomainmissingauditref";
        TopLevelDomain dom = createTopLevelDomainObject(
            domain, null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        // delete it without an auditRef and catch exception
        try {
            zms.deleteDomain(mockDomRsrcCtx, null, domain, "testDeleteDomainMissingAuditRef");
            fail("requesterror not thrown by testDeleteDomainMissingAuditRef.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testDeleteTopLevelDomain() {

        TopLevelDomain dom1 = createTopLevelDomainObject("DelTopDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Domain resDom1 = zms.getDomain(mockDomRsrcCtx, "DelTopDom1");
        assertNotNull(resDom1);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "DelTopDom1", auditRef);

        // we should get a forbidden exception since the domain
        // no longer exists

        try {
            zms.getDomain(mockDomRsrcCtx, "DelTopDom1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testDeleteTopLevelDomainChildExist() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_deltopdomhrowexc";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        TopLevelDomain dom1 = createTopLevelDomainObject("DelTopChildDom1",
                "Test Domain1", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        SubDomain dom2 = createSubDomainObject("DelSubDom2", "DelTopChildDom1",
                "Test Domain2", "testOrg", adminUser);
        zmsImpl.postSubDomain(mockDomRsrcCtx, "DelTopChildDom1", auditRef, dom2);

        // we can't delete Dom1 since Dom2 still exists
        
        try {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "DelTopChildDom1", auditRef);
            fail("requesterror not thrown.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }
        
        zmsImpl.deleteSubDomain(mockDomRsrcCtx, "DelTopChildDom1", "DelSubDom2", auditRef);
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "DelTopChildDom1", auditRef);
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }

    @Test
    public void testDeleteTopLevelDomainNonExistant() {
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, "NonExistantDomain", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteTopLevelDomainNonExistantNoAuditRef() {
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, "NonExistantDomain", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteTopLevelDomainMissingAuditRef() {
        // create domain and require auditing
        TopLevelDomain dom = createTopLevelDomainObject(
            "TopDomainAuditRequired", null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        // delete it without an auditRef and catch exception
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, "TopDomainAuditRequired", null);
            fail("requesterror not thrown by deleteTopLevelDomain.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, "TopDomainAuditRequired", auditRef);
        }
    }

    @Test
    public void testDeleteSubDomain() {

        TopLevelDomain dom1 = createTopLevelDomainObject("DelSubDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        SubDomain dom2 = createSubDomainObject("DelSubDom2", "DelSubDom1",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "DelSubDom1", auditRef, dom2);

        Domain resDom1 = zms.getDomain(mockDomRsrcCtx, "DelSubDom1.DelSubDom2");
        assertNotNull(resDom1);

        zms.deleteSubDomain(mockDomRsrcCtx, "DelSubDom1", "DelSubDom2", auditRef);

        // we should get a forbidden exception since the domain
        // no longer exists

        try {
            zms.getDomain(mockDomRsrcCtx, "DelSubDom1.DelSubDom2");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "DelSubDom1", auditRef);
    }

    @Test
    public void testDeleteSubDomainChildExist() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_delsubdomchildexist";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        TopLevelDomain dom1 = createTopLevelDomainObject("DelSubChildDom1",
                "Test Domain1", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        SubDomain dom2 = createSubDomainObject("DelSubDom2", "DelSubChildDom1",
                "Test Domain2", "testOrg", adminUser);
        zmsImpl.postSubDomain(mockDomRsrcCtx, "DelSubChildDom1", auditRef, dom2);

        SubDomain dom3 = createSubDomainObject("DelSubDom3", "DelSubChildDom1.DelSubDom2",
                "Test Domain3", "testOrg", adminUser);
        zmsImpl.postSubDomain(mockDomRsrcCtx, "DelSubChildDom1.DelSubDom2", auditRef, dom3);

        // we can't delete Dom2 since Dom3 still exists
        
        try {
            zmsImpl.deleteSubDomain(mockDomRsrcCtx, "DelSubChildDom1", "DelSubDom2", auditRef);
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zmsImpl.deleteSubDomain(mockDomRsrcCtx, "DelSubChildDom1.DelSubDom2", "DelSubDom3", auditRef);
        zmsImpl.deleteSubDomain(mockDomRsrcCtx, "DelSubChildDom1", "DelSubDom2", auditRef);
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "DelSubChildDom1", auditRef);
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testDeleteSubDomainNonExistant() {
        TopLevelDomain dom = createTopLevelDomainObject(
            "ExistantTopDomain", null, null, adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);
        try {
            zms.deleteSubDomain(mockDomRsrcCtx, "ExistantTopDomain", "NonExistantSubDomain", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ExistantTopDomain", auditRef);
    }

    @Test
    public void testDeleteSubDomainSubAndTopNonExistant() {
        try {
            zms.deleteSubDomain(mockDomRsrcCtx, "NonExistantTopDomain", "NonExistantSubDomain", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteSubDomainMissingAuditRef() {
        TopLevelDomain dom = createTopLevelDomainObject(
            "ExistantTopDomain2", null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        SubDomain subDom = createSubDomainObject(
            "ExistantSubDom2", "ExistantTopDomain2",
            null, null, adminUser);
        subDom.setAuditEnabled(true);
        zms.postSubDomain(mockDomRsrcCtx, "ExistantTopDomain2", auditRef, subDom);

        try {
            zms.deleteSubDomain(mockDomRsrcCtx, "ExistantTopDomain2", "ExistantSubDom2", null);
            fail("requesterror not thrown by deleteSubDomain.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteSubDomain(mockDomRsrcCtx, "ExistantTopDomain2", "ExistantSubDom2", auditRef);
            zms.deleteTopLevelDomain(mockDomRsrcCtx, "ExistantTopDomain2", auditRef);
        }
    }

    @Test
    public void testPutDomainMetaThrowException() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_putdommetathrowexc";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domName = "wrongDomainName";
        DomainMeta meta = new DomainMeta();
        meta.setYpmId(getRandomProductId());
        try {
            zmsImpl.putDomainMeta(mockDomRsrcCtx, domName, auditRef, meta);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(404, e.getCode());
        }
    }

    @Test(groups="post-domain-tests")
    public void testPutDomainMeta() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MetaDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Domain resDom1 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom1);
        assertEquals(resDom1.getDescription(), "Test Domain1");
        assertEquals(resDom1.getOrg(), "testOrg");
        assertTrue(resDom1.getEnabled());
        assertFalse(resDom1.getAuditEnabled());

        DomainMeta meta = createDomainMetaObject("Test2 Domain", "NewOrg",
                true, true, "12345", 1001);
        zms.putDomainMeta(mockDomRsrcCtx, "MetaDom1", auditRef, meta);

        Domain resDom3 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom3);
        assertEquals(resDom3.getDescription(), "Test2 Domain");
        assertEquals(resDom3.getOrg(), "NewOrg");
        assertTrue(resDom3.getEnabled());
        assertTrue(resDom3.getAuditEnabled());
        assertEquals("12345", resDom3.getAccount());
        assertEquals(Integer.valueOf(1001), resDom3.getYpmId());

        // put the meta data using same product id
        meta.setDescription("just a new desc");
        meta.setOrg("organs");
        zms.putDomainMeta(mockDomRsrcCtx, "MetaDom1", auditRef, meta);

        resDom3 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom3);
        assertEquals(resDom3.getDescription(), "just a new desc");
        assertEquals(resDom3.getOrg(), "organs");
        assertTrue(resDom3.getEnabled());
        assertTrue(resDom3.getAuditEnabled());
        assertEquals("12345", resDom3.getAccount());
        assertEquals(Integer.valueOf(1001), resDom3.getYpmId());

        // put the meta data using new product
        Integer newProductId = getRandomProductId();
        meta.setYpmId(newProductId);
        zms.putDomainMeta(mockDomRsrcCtx, "MetaDom1", auditRef, meta);

        resDom3 = zms.getDomain(mockDomRsrcCtx, "MetaDom1");
        assertNotNull(resDom3);
        assertEquals(resDom3.getDescription(), "just a new desc");
        assertEquals(resDom3.getOrg(), "organs");
        assertTrue(resDom3.getEnabled());
        assertTrue(resDom3.getAuditEnabled());
        assertEquals("12345", resDom3.getAccount());
        assertEquals(newProductId, resDom3.getYpmId());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MetaDom1", auditRef);
    }

    @Test(groups="post-domain-tests")
    public void testPutDomainMetaInvalid() {

        // enable product id support
        
        System.setProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "true");
        ZMSImpl zmsImpl = zmsInit();
        
        TopLevelDomain dom = createTopLevelDomainObject("MetaDomProductid",
                "Test Domain", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Domain resDom = zmsImpl.getDomain(mockDomRsrcCtx, "MetaDomProductid");
        assertNotNull(resDom);
        assertEquals(resDom.getDescription(), "Test Domain");
        assertEquals(resDom.getOrg(), "testOrg");
        assertTrue(resDom.getEnabled());
        assertFalse(resDom.getAuditEnabled());
        Integer productId = resDom.getYpmId();

        DomainMeta meta = createDomainMetaObject("Test2 Domain", "NewOrg",
                true, true, "12345", null);
        try {
            zmsImpl.putDomainMeta(mockDomRsrcCtx, "MetaDomProductid", auditRef, meta);
            fail("bad request exc not thrown");
        } catch (ResourceException exc) {
            assertEquals(400, exc.getCode());
            assertTrue(exc.getMessage().contains("Unique Product Id must be specified for top level domain"));
        }

        // put meta data using another domains productId
        dom = createTopLevelDomainObject("MetaDomProductid2",
                "Test Domain", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        resDom = zmsImpl.getDomain(mockDomRsrcCtx, "MetaDomProductid2");
        Integer productId2 = resDom.getYpmId();
        assertFalse(productId.intValue() == productId2.intValue());

        meta = createDomainMetaObject("Test3 Domain", "NewOrg",
                true, true, "12345", productId2);
        try {
            zmsImpl.putDomainMeta(mockDomRsrcCtx, "MetaDomProductid", auditRef, meta);
            fail("bad request exc not thrown");
        } catch (ResourceException exc) {
            assertEquals(400, exc.getCode());
            assertTrue(exc.getMessage().contains("is already assigned to domain"));
        }

        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "MetaDomProductid", auditRef);
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "MetaDomProductid2", auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT);
    }

    @Test
    public void testPutDomainMetaDefaults() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MetaDom2",
                null, null, adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Domain resDom1 = zms.getDomain(mockDomRsrcCtx, "MetaDom2");
        assertNotNull(resDom1);
        assertNull(resDom1.getDescription());
        assertNull(resDom1.getOrg());
        assertTrue(resDom1.getEnabled());
        assertFalse(resDom1.getAuditEnabled());

        DomainMeta meta = createDomainMetaObject("Test2 Domain", "NewOrg",
                true, false, null, 0);
        zms.putDomainMeta(mockDomRsrcCtx, "MetaDom2", auditRef, meta);

        Domain resDom3 = zms.getDomain(mockDomRsrcCtx, "MetaDom2");
        assertNotNull(resDom3);
        assertEquals(resDom3.getDescription(), "Test2 Domain");
        assertEquals(resDom3.getOrg(), "NewOrg");
        assertTrue(resDom3.getEnabled());
        assertFalse(resDom3.getAuditEnabled());
        assertNull(resDom3.getAccount());
        assertEquals(Integer.valueOf(0), resDom3.getYpmId());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MetaDom2", auditRef);
    }

    @Test
    public void testPutDomainMetaMissingAuditRef() {
        String domain = "testSetDomainMetaMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test1 Domain", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Domain resDom = zms.getDomain(mockDomRsrcCtx, domain);
        assertNotNull(resDom);
        assertEquals(resDom.getDescription(), "Test1 Domain");
        assertEquals(resDom.getOrg(), "testOrg");
        assertTrue(resDom.getAuditEnabled());

        DomainMeta meta = createDomainMetaObject("Test2 Domain", "NewOrg", true, true, null, 0);
        try {
            zms.putDomainMeta(mockDomRsrcCtx, domain, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test(groups="post-domain-tests")
    public void testPutDomainMetaSubDomain() {
        try {
            TopLevelDomain dom = createTopLevelDomainObject("MetaDomProductid",
                "Test Domain", "testOrg", adminUser);
            zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);
        } catch (ResourceException rexc) {
            assertTrue(rexc.getCode() == 400);
        }

        SubDomain subDom = createSubDomainObject("metaSubDom", "MetaDomProductid",
                "sub Domain", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "MetaDomProductid", auditRef, subDom);

        // put meta data with null productId
        DomainMeta meta = createDomainMetaObject("Test sub Domain", "NewOrg",
                true, true, "12345", null);
        zms.putDomainMeta(mockDomRsrcCtx, "MetaDomProductid.metaSubDom", auditRef, meta);

        // put meta data with a productId
        meta = createDomainMetaObject("Test sub Domain", "NewOrg",
                true, true, "12345", getRandomProductId());
        zms.putDomainMeta(mockDomRsrcCtx, "MetaDomProductid.metaSubDom", auditRef, meta);

        zms.deleteSubDomain(mockDomRsrcCtx, "MetaDomProductid", "metaSubDom", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MetaDomProductid", auditRef);
    }

    @Test
    public void testGetRoleList() {

        TopLevelDomain dom1 = createTopLevelDomainObject("RoleListDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("RoleListDom1", "Role1", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, "RoleListDom1", "Role1", auditRef, role1);

        Role role2 = createRoleObject("RoleListDom1", "Role2", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, "RoleListDom1", "Role2", auditRef, role2);

        RoleList roleList = zms.getRoleList(mockDomRsrcCtx, "RoleListDom1", null, null);
        assertNotNull(roleList);

        assertTrue(roleList.getNames().contains("Role1".toLowerCase()));
        assertTrue(roleList.getNames().contains("Role2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "RoleListDom1", auditRef);
    }
    
    @Test
    public void testGetRoleListParams() {

        TopLevelDomain dom1 = createTopLevelDomainObject("RoleListParamDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("RoleListParamDom1", "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "RoleListParamDom1", "Role1", auditRef, role1);

        Role role2 = createRoleObject("RoleListParamDom1", "Role2", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "RoleListParamDom1", "Role2", auditRef, role2);

        RoleList roleList = zms.getRoleList(mockDomRsrcCtx, "RoleListParamDom1", null, "Role1");
        assertNotNull(roleList);

        assertFalse(roleList.getNames().contains("Role1".toLowerCase()));
        assertTrue(roleList.getNames().contains("Role2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "RoleListParamDom1", auditRef);
    }
    
    @Test
    public void testGetRoleListThrowException() {
        try {
            zms.getRoleList(mockDomRsrcCtx, "wrongDomainName", null, null);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testGetRole() {

        TopLevelDomain dom1 = createTopLevelDomainObject("GetRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("GetRoleDom1", "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "GetRoleDom1", "Role1", auditRef, role1);

        Role role = zms.getRole(mockDomRsrcCtx, "GetRoleDom1", "Role1", false, false);
        assertNotNull(role);

        assertEquals(role.getName(), "GetRoleDom1:role.Role1".toLowerCase());
        assertNull(role.getTrust());
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 2);

        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkRoleMember(checkList, members);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "GetRoleDom1", auditRef);
    }
    
    @Test
    public void testGetRoleThrowException() {
        String domainName = "MbrGetRoleDom1";
        String roleName = "Role1";
        
        // Tests the getRole() condition: if (domain == null)...
        try {
            zms.getRole(mockDomRsrcCtx, domainName, roleName, false, false);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // Tests the getRole() condition: if (collection == null)...
        try {
            // Should fail because we did not create a role resource.
            zms.getRole(mockDomRsrcCtx, domainName, roleName, false, false);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        // Tests the getRole() condition: if (role == null)...
        String wrongRoleName = "Role2";
        try {
            Role role1 = createRoleObject(domainName, roleName, null);
            zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);
            
            // Should fail because we are trying to find a non-existent role.
            zms.getRole(mockDomRsrcCtx, domainName, wrongRoleName, false, false);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testPutRoleThrowException() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_putrolethrowexc";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domainName = "DomainName1";
        String roleName = "RoleName1";
        Role role = new Role();
        
        // Tests the getRole() condition : if (!roleResourceName(domainName, roleName).equals(role.getName()))...
        try {
            String roleRoleName = "inconsistentRoleName1";
            role.setName(roleRoleName);
            
            // The role naming is inconsistent.
            zmsImpl.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
        
        // Tests the getRole() condition : if (domain == null)...
        try {
            String roleRoleName = "DomainName1:role.RoleName1";
            role.setName(roleRoleName);
            
            // We never created a domain for this role.
            zmsImpl.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }

        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }

    @Test
    public void testCreateRole() {

        TestAuditLogger alogger = new TestAuditLogger();
        List<String> aLogMsgs = alogger.getLogMsgList();
        String storeFile = ZMS_DATA_STORE_FILE + "_createrole";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        TopLevelDomain dom1 = createTopLevelDomainObject("CreateRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("CreateRoleDom1", "Role1", null,
                "user.joe", "user.jane");
        zmsImpl.putRole(mockDomRsrcCtx, "CreateRoleDom1", "Role1", auditRef, role1);

        Role role3 = zmsImpl.getRole(mockDomRsrcCtx, "CreateRoleDom1", "Role1", false, false);
        assertNotNull(role3);
        assertEquals(role3.getName(), "CreateRoleDom1:role.Role1".toLowerCase());
        assertNull(role3.getTrust());

        // check audit log msg for putRole
        boolean foundError = false;
        System.err.println("testCreateRole: Number of lines: " + aLogMsgs.size());
        for (String msg: aLogMsgs) {
            if (msg.indexOf("WHAT-api=(putrole)") == -1) {
                continue;
            }
            assertTrue(msg.indexOf("CLIENT-IP=(" + MOCKCLIENTADDR + ")") != -1, msg);
            int index = msg.indexOf("WHAT-details=(");
            assertTrue(index != -1, msg);
            int index2 = msg.indexOf("\"name\": \"role1\", \"trust\": \"null\", \"added-members\": [");
            assertTrue(index2 > index, msg);
            foundError = true;
            break;
        }
        assertTrue(foundError);

        // delete member of the role
        //
        List<RoleMember> listrm = role1.getRoleMembers();
        for (RoleMember rmemb: listrm) {
            if (rmemb.getMemberName().equals("user.jane")) {
                listrm.remove(rmemb);
                break;
            }
        }

        aLogMsgs.clear();
        zmsImpl.putRole(mockDomRsrcCtx, "CreateRoleDom1", "Role1", auditRef, role1);

        foundError = false;
        System.err.println("testCreateRole: Now Number of lines: " + aLogMsgs.size());
        for (String msg: aLogMsgs) {
            if (msg.indexOf("WHAT-api=(putrole)") == -1) {
                continue;
            }
            assertTrue(msg.indexOf("CLIENT-IP=(" + MOCKCLIENTADDR + ")") != -1, msg);
            int index = msg.indexOf("WHAT-details=(");
            assertTrue(index != -1, msg);
            int index2 = msg.indexOf("\"name\": \"role1\", \"trust\": \"null\", \"deleted-members\": [\"user.jane\"], \"added-members\": []");
            assertTrue(index2 > index, msg);
            foundError = true;
            break;
        }
        assertTrue(foundError);

        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "CreateRoleDom1", auditRef);

        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }

    @Test
    public void testCreateRoleLocalNameOnly() {

        TopLevelDomain dom1 = createTopLevelDomainObject("CreateRoleLocalNameOnly",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = new Role();
        role1.setName("role1");
        
        zms.putRole(mockDomRsrcCtx, "CreateRoleLocalNameOnly", "Role1", auditRef, role1);

        Role role3 = zms.getRole(mockDomRsrcCtx, "CreateRoleLocalNameOnly", "Role1", false, false);
        assertNotNull(role3);
        assertEquals(role3.getName(), "CreateRoleLocalNameOnly:role.Role1".toLowerCase());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "CreateRoleLocalNameOnly", auditRef);
    }
    
    @Test
    public void testCreateRoleMissingAuditRef() {
        String domain = "testCreateRoleMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Role role = createRoleObject(
            domain, "Role1", null, "user.joe", "user.jane");
        try {
            zms.putRole(mockDomRsrcCtx, domain, "Role1", null, role);
            fail("requesterror not thrown by putRole.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testCreateRoleMismatchName() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "CreateMismatchRoleDom1", "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("CreateMismatchRoleDom1", "Role1", null,
                "user.joe", "user.jane");

        try {
            zms.putRole(mockDomRsrcCtx, "CreateMismatchRoleDom1",
                    "CreateMismatchRoleDom1.Role1", auditRef, role1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "CreateMismatchRoleDom1", auditRef);
    }
    
    @Test
    public void testCreateRoleInvalidName() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "CreateRoleInvalidNameDom1", "Test Domain1", "testOrg",
                adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = new Role();
        role1.setName("Role1");

        try {
            zms.putRole(mockDomRsrcCtx, "CreateRoleInvalidNameDom1", "Role111", auditRef, role1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx,"CreateRoleInvalidNameDom1", auditRef);
    }

    @Test
    public void testCreateRoleInvalidStruct() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "CreateRoleInvalidStructDom1", "Test Domain1", "testOrg",
                adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = new Role();

        try {
            zms.putRole(mockDomRsrcCtx, "CreateRoleInvalidStructDom1", "Role1", auditRef, role1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx,"CreateRoleInvalidStructDom1", auditRef);
    }

    @Test
    public void testCreateRoleInvalidMembers() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "CreateInvalidMemberRoleDom1", "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("CreateInvalidMemberRoleDom1", "Role1", null,
                "user.joe", "jane");

        try {
            zms.putRole(mockDomRsrcCtx, "CreateInvalidMemberRoleDom1", "Role1", auditRef, role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }

        Role role2 = createRoleObject("CreateInvalidMemberRoleDom1", "Role2", null,
                "joe", "user.jane");

        try {
            zms.putRole(mockDomRsrcCtx, "CreateInvalidMemberRoleDom1", "Role2", auditRef, role2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx,"CreateInvalidMemberRoleDom1", auditRef);
    }
    
    @Test
    public void testCreateRoleBothMemberAndTrust() {

        String domainName = "rolebothmemberandtrust";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, "Role1", "sys.auth",
                "user.joe", "user.jane");

        try {
            zms.putRole(mockDomRsrcCtx, domainName, "Role1", auditRef, role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testCreateRoleTrustItself() {

        String domainName = "roletrustitself";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, "Role1", domainName,
                null, null);

        try {
            zms.putRole(mockDomRsrcCtx, domainName, "Role1", auditRef, role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testCreateDuplicateMemberRole() {

        TopLevelDomain dom1 = createTopLevelDomainObject("CreateDuplicateMemberRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("CreateDuplicateMemberRoleDom1", "Role1", null,
                "user.joe", "user.joe");
        zms.putRole(mockDomRsrcCtx, "CreateDuplicateMemberRoleDom1", "Role1", auditRef, role1);

        Role role = zms.getRole(mockDomRsrcCtx, "CreateDuplicateMemberRoleDom1", "Role1", false, false);
        assertNotNull(role);

        assertEquals(role.getName(), "CreateDuplicateMemberRoleDom1:role.Role1".toLowerCase());
        assertNull(role.getTrust());
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertTrue(members.get(0).getMemberName().equals("user.joe"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx,"CreateDuplicateMemberRoleDom1", auditRef);
    }
    
    @Test
    public void testCreateNormalizedUserMemberRole() {

        TopLevelDomain dom1 = createTopLevelDomainObject("CreateNormalizedUserMemberRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user:joe"));
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("user:joe"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        
        Role role1 = createRoleObject("CreateNormalizedUserMemberRoleDom1", "Role1", 
                null, roleMembers);
        zms.putRole(mockDomRsrcCtx, "CreateNormalizedUserMemberRoleDom1", "Role1", auditRef, role1);

        Role role = zms.getRole(mockDomRsrcCtx, "CreateNormalizedUserMemberRoleDom1", "Role1", false, false);
        assertNotNull(role);

        assertEquals(role.getName(), "CreateNormalizedUserMemberRoleDom1:role.Role1".toLowerCase());
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 2);
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkRoleMember(checkList, members);

        zms.deleteTopLevelDomain(mockDomRsrcCtx,"CreateNormalizedUserMemberRoleDom1", auditRef);
    }
    
    @Test
    public void testCreateNormalizedServiceMemberRole() {

        TopLevelDomain dom1 = createTopLevelDomainObject("CreateNormalizedServiceMemberRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        SubDomain subDom3 = createSubDomainObject("user1", "user",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "user", auditRef, subDom3);
        
        SubDomain subDom4 = createSubDomainObject("dom1", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, subDom4);
        
        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("coretech.storage"));
        roleMembers.add(new RoleMember().setMemberName("coretech:service.storage"));
        roleMembers.add(new RoleMember().setMemberName("user.user1.dom1:service.api"));
        
        Role role1 = createRoleObject("CreateNormalizedServiceMemberRoleDom1", "Role1", 
                null, roleMembers);
        zms.putRole(mockDomRsrcCtx, "CreateNormalizedServiceMemberRoleDom1", "Role1", auditRef, role1);

        Role role = zms.getRole(mockDomRsrcCtx, "CreateNormalizedServiceMemberRoleDom1", "Role1", false, false);
        assertNotNull(role);

        assertEquals(role.getName(), "CreateNormalizedServiceMemberRoleDom1:role.Role1".toLowerCase());
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 2);
        List<String> checkList = new ArrayList<>();
        checkList.add("coretech.storage");
        checkList.add("user.user1.dom1.api");
        checkRoleMember(checkList, members);

        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "dom1", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user", "user1", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx,"CreateNormalizedServiceMemberRoleDom1", auditRef);
    }
    
    @Test
    public void testCreateNormalizedCombinedMemberRole() {

        TopLevelDomain dom1 = createTopLevelDomainObject("CreateNormalizedCombinedMemberRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        SubDomain subDom3 = createSubDomainObject("user1", "user",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "user", auditRef, subDom3);
        
        SubDomain subDom4 = createSubDomainObject("dom1", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, subDom4);
        
        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user:joe"));
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("user:joe"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        roleMembers.add(new RoleMember().setMemberName("coretech.storage"));
        roleMembers.add(new RoleMember().setMemberName("coretech:service.storage"));
        roleMembers.add(new RoleMember().setMemberName("user.user1.dom1:service.api"));
        
        Role role1 = createRoleObject("CreateNormalizedCombinedMemberRoleDom1", "Role1", 
                null, roleMembers);
        zms.putRole(mockDomRsrcCtx, "CreateNormalizedCombinedMemberRoleDom1", "Role1", auditRef, role1);

        Role role = zms.getRole(mockDomRsrcCtx, "CreateNormalizedCombinedMemberRoleDom1", "Role1", false, false);
        assertNotNull(role);

        assertEquals(role.getName(), "CreateNormalizedCombinedMemberRoleDom1:role.Role1".toLowerCase());
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 4);
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("coretech.storage");
        checkList.add("user.user1.dom1.api");
        checkRoleMember(checkList, members);

        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "dom1", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user", "user1", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx,"CreateNormalizedCombinedMemberRoleDom1", auditRef);
    }
    
    @Test
    public void testDeleteRole() {

        TopLevelDomain dom1 = createTopLevelDomainObject("DelRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("DelRoleDom1", "Role1", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, "DelRoleDom1", "Role1", auditRef, role1);

        Role role2 = createRoleObject("DelRoleDom1", "Role2", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, "DelRoleDom1", "Role2", auditRef, role2);

        RoleList roleList = zms.getRoleList(mockDomRsrcCtx, "DelRoleDom1", null, null);
        assertNotNull(roleList);

        // our role count is +1 because of the admin role
        assertEquals(roleList.getNames().size(), 3);

        zms.deleteRole(mockDomRsrcCtx,"DelRoleDom1", "Role1", auditRef);

        roleList = zms.getRoleList(mockDomRsrcCtx, "DelRoleDom1", null, null);
        assertNotNull(roleList);

        // our role counti is +1 because of the admin role
        assertEquals(roleList.getNames().size(), 2);

        assertFalse(roleList.getNames().contains("Role1".toLowerCase()));
        assertTrue(roleList.getNames().contains("Role2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx,"DelRoleDom1", auditRef);
    }

    @Test
    public void testDeleteRoleMissingAuditRef() {
        String domain = "testDeleteRoleMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Role role = createRoleObject(
            domain, "Role1", null, "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domain, "Role1", auditRef, role);

        try {
            zms.deleteRole(mockDomRsrcCtx, domain, "Role1", null);
            fail("requesterror not thrown by deleteRole.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testDeleteRoleThrowException() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_delrolethrowexc";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domainName = "DomainName1";
        String roleName = "RoleName1";
        try {
            zmsImpl.deleteRole(mockDomRsrcCtx,domainName, roleName, auditRef);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }

        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
        
    @Test
    public void testDeleteAdminRole() {

        TopLevelDomain dom1 = createTopLevelDomainObject("DelAdminRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        try {
            zms.deleteRole(mockDomRsrcCtx,"DelAdminRoleDom1", "admin", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx,"DelAdminRoleDom1", auditRef);
    }

    @Test
    public void testGetMembership() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrGetRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("MbrGetRoleDom1", "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrGetRoleDom1", "Role1", auditRef, role1);

        Membership member1 = zms.getMembership(mockDomRsrcCtx, "MbrGetRoleDom1", "Role1",
                "user.joe");
        assertNotNull(member1);
        assertEquals(member1.getMemberName(), "user.joe");
        assertEquals(member1.getRoleName(), "MbrGetRoleDom1:role.Role1".toLowerCase());
        assertTrue(member1.getIsMember());

        Membership member2 = zms.getMembership(mockDomRsrcCtx, "MbrGetRoleDom1", "Role1",
                "user.doe");
        assertNotNull(member2);
        assertEquals(member2.getMemberName(), "user.doe");
        assertEquals(member2.getRoleName(), "MbrGetRoleDom1:role.Role1".toLowerCase());
        assertFalse(member2.getIsMember());

        zms.deleteTopLevelDomain(mockDomRsrcCtx,"MbrGetRoleDom1", auditRef);
    }
    
    @Test
    public void testGetMembershipThrowException() {
        String domainName = "MbrGetRoleDom1";
        String roleName = "Role1";
        String memberName1 = "user.john";
        String memberName2 = "user.jane";
        
        // Tests the getMembership() condition : if (domain == null)...
        try {
            // Should fail because we never created this domain.
            zms.getMembership(mockDomRsrcCtx, domainName, roleName, memberName1);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // Tests the getMembership() condition: if (collection == null)...
        try {
            // Should fail because we never added a role to this domain.
            zms.getMembership(mockDomRsrcCtx, domainName, roleName, memberName1);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        // Tests the getMembership() condition: if (role == null)...
        try {
            String missingRoleName = "Role2";
            
            Role role1 = createRoleObject("MbrGetRoleDom1", "Role1", null,
                    memberName1, memberName2);
            zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);
            
            // Trying to find a non-existent role.
            zms.getMembership(mockDomRsrcCtx, domainName, missingRoleName, memberName1);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx,domainName, auditRef);
    }

    @Test
    public void testPutMembership() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_putmembership";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom1",
                "Test Domain1", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zmsImpl.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        Role role1 = createRoleObject("MbrAddDom1", "Role1", null,
                "user.joe", "user.jane");
        zmsImpl.putRole(mockDomRsrcCtx, "MbrAddDom1", "Role1", auditRef, role1);
        
        Membership mbr = generateMembership("Role1", "user.doe");
        zmsImpl.putMembership(mockDomRsrcCtx, "MbrAddDom1", "Role1", "user.doe", auditRef, mbr);

        // check audit log msg for putRole
        boolean foundError = false;
        List<String> aLogMsgs = alogger.getLogMsgList();
        System.err.println("testPutMembership: Number of lines: " + aLogMsgs.size());
        for (String msg: aLogMsgs) {
            if (msg.indexOf("WHAT-api=(putmembership)") == -1) {
                continue;
            }
            int index = msg.indexOf("WHAT-details=(");
            assertTrue(index != -1, msg);
            int index2 = msg.indexOf("{\"member\": \"user.doe\"}");
            assertTrue(index2 > index, msg);
            foundError = true;
            break;
        }
        assertTrue(foundError);
        
        aLogMsgs.clear();
        mbr = generateMembership("Role1", "coretech.storage");
        zmsImpl.putMembership(mockDomRsrcCtx, "MbrAddDom1", "Role1", "coretech.storage", auditRef, mbr);

        Role role = zmsImpl.getRole(mockDomRsrcCtx, "MbrAddDom1", "Role1", false, false);
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

        foundError = false;
        System.err.println("testPutMembership: now Number of lines: " + aLogMsgs.size());
        for (String msg: aLogMsgs) {
            if (msg.indexOf("WHAT-api=(putmembership)") == -1) {
                continue;
            }
            int index = msg.indexOf("WHAT-details=(");
            assertTrue(index != -1, msg);
            int index2 = msg.indexOf("{\"member\": \"coretech.storage\"}");
            assertTrue(index2 > index, msg);
            foundError = true;
            break;
        }
        assertTrue(foundError);
        
        
        zmsImpl.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx,"MbrAddDom1", auditRef);
    }

    @Test
    public void testPutMembershipExpiration() {

        String domainName = "testPutMembershipExpiration";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        try {
            zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("coretech - already exists"));
        }
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        Role role1 = createRoleObject(domainName, "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "Role1", auditRef, role1);
        
        Timestamp expired = Timestamp.fromMillis(System.currentTimeMillis() - 100);
        Timestamp notExpired = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.HOURS.toMillis(1));
        
        Membership mbr = generateMembership("Role1", "user.doe", expired);
        zms.putMembership(mockDomRsrcCtx, domainName, "Role1", "user.doe", auditRef, mbr);
        Membership expiredMember = zms.getMembership(mockDomRsrcCtx, domainName,
                "Role1", "user.doe");
        
        mbr = generateMembership("Role1", "coretech.storage", notExpired);
        zms.putMembership(mockDomRsrcCtx, domainName, "Role1", "coretech.storage", auditRef, mbr);
        Membership notExpiredMember = zms.getMembership(mockDomRsrcCtx, domainName,
                "Role1", "coretech.storage");

        Role role = zms.getRole(mockDomRsrcCtx, domainName, "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 4);

        List<String> checkList = new ArrayList<String>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkList.add("coretech.storage");
        checkRoleMember(checkList, role.getRoleMembers());
        
        for (RoleMember roleMember: members) {
            if (roleMember.getMemberName().equalsIgnoreCase("user.doe")) {
                Timestamp actual = roleMember.getExpiration();
                assertNotNull(actual);
                assertEquals(actual, expired);
            }
            if (roleMember.getMemberName().equalsIgnoreCase("coretech.storage")) {
                Timestamp actual = roleMember.getExpiration();
                assertNotNull(actual);
                assertEquals(actual, notExpired);
            }
        }
        
        assertFalse(expiredMember.getIsMember());
        assertTrue(notExpiredMember.getIsMember());
        
        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx,domainName, auditRef);
    }
    
    @Test
    public void testPutMembershipEmptyRoleMembers() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom1EmptyRole",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = new Role();
        role1.setName(ZMSUtils.roleResourceName("MbrAddDom1EmptyRole", "Role1"));
        zms.putRole(mockDomRsrcCtx, "MbrAddDom1EmptyRole", "Role1", auditRef, role1);
        
        Membership mbr = generateMembership("Role1", "user.doe");
        zms.putMembership(mockDomRsrcCtx, "MbrAddDom1EmptyRole", "Role1", "user.doe", auditRef, mbr);

        Role role = zms.getRole(mockDomRsrcCtx, "MbrAddDom1EmptyRole", "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 1);

        assertTrue(members.get(0).getMemberName().equals("user.doe"));
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx,"MbrAddDom1EmptyRole", auditRef);
    }
    
    @Test
    public void testPutMembershipMissingAuditRef() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_putmembershipmissauditref";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domain = "testPutMembershipMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Role role = createRoleObject(
            domain, "Role1", null, "user.joe", "user.jane");
        zmsImpl.putRole(mockDomRsrcCtx, domain, "Role1", auditRef, role);

        Membership mbr = generateMembership("Role1", "user.john");
        try {
            zmsImpl.putMembership(mockDomRsrcCtx, domain, "Role1", "user.john", null, mbr);
            fail("requesterror not thrown by putMembership.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testPutMembershipNormalizedUser() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom2",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        Role role1 = createRoleObject("MbrAddDom2", "Role1", null,
                "coretech.storage", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrAddDom2", "Role1", auditRef, role1);
        
        Membership mbr = generateMembership("Role1", "user:doe");
        zms.putMembership(mockDomRsrcCtx, "MbrAddDom2", "Role1", "user:doe", auditRef, mbr);

        Role role = zms.getRole(mockDomRsrcCtx, "MbrAddDom2", "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 3);

        List<String> checkList = new ArrayList<>();
        checkList.add("coretech.storage");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkRoleMember(checkList, members);
        
        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrAddDom2", auditRef);
    }
    
    @Test
    public void testPutMembershipNormalizedUseruser() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom3",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        Role role1 = createRoleObject("MbrAddDom3", "Role1", null,
                "coretech.storage", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrAddDom3", "Role1", auditRef, role1);
        
        Membership mbr = generateMembership("Role1", "user:doe");
        zms.putMembership(mockDomRsrcCtx, "MbrAddDom3", "Role1", "user:doe", auditRef, mbr);

        Role role = zms.getRole(mockDomRsrcCtx, "MbrAddDom3", "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 3);

        List<String> checkList = new ArrayList<>();
        checkList.add("coretech.storage");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkRoleMember(checkList, members);
        
        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrAddDom3", auditRef);
    }

    @Test
    public void testPutMembershipNormalizedService() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom4",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        TopLevelDomain dom3 = createTopLevelDomainObject("weather",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom3);
        
        SubDomain subDom3 = createSubDomainObject("storage", "weather",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "weather", auditRef, subDom3);
        
        Role role1 = createRoleObject("MbrAddDom4", "Role1", null,
                "coretech.storage", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrAddDom4", "Role1", auditRef, role1);
 
        Membership mbr = generateMembership("Role1", "weather:service.storage");
        zms.putMembership(mockDomRsrcCtx, "MbrAddDom4", "Role1", "weather:service.storage", auditRef, mbr);

        Role role = zms.getRole(mockDomRsrcCtx, "MbrAddDom4", "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 3);

        List<String> checkList = new ArrayList<>();
        checkList.add("coretech.storage");
        checkList.add("user.jane");
        checkList.add("weather.storage");
        checkRoleMember(checkList, members);
        
        zms.deleteSubDomain(mockDomRsrcCtx, "weather", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "weather", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrAddDom4", auditRef);
    }

    public void testPutMembershipRoleNotPresent() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDomNoRole",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        Role role1 = createRoleObject("MbrAddDomNoRole", "Role1", null,
                "coretech.storage", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrAddDomNoRole", "Role1", auditRef, role1);

        // membership object with only member

        Membership mbr = new Membership();
        mbr.setMemberName("user.joe");

        zms.putMembership(mockDomRsrcCtx, "MbrAddDomNoRole", "Role1", "user.joe", auditRef, mbr);

        Role role = zms.getRole(mockDomRsrcCtx, "MbrAddDomNoRole", "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 3);

        List<String> checkList = new ArrayList<>();
        checkList.add("coretech.storage");
        checkList.add("user.jane");
        checkList.add("user.joe");
        checkRoleMember(checkList, members);

        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrAddDomNoRole", auditRef);
    }
 
    @Test
    public void testPutMembershipInvalid() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom5",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        Role role1 = createRoleObject("MbrAddDom5", "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrAddDom5", "Role1", auditRef, role1);
        try {
            Membership mbr = generateMembership("Role1", "coretech");
            zms.putMembership(mockDomRsrcCtx, "MbrAddDom5", "Role1", "coretech", auditRef, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrAddDom5", auditRef);
    }
    
    @Test
    public void testPutMembershipRoleMismatch() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom6",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("MbrAddDom6", "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrAddDom6", "Role1", auditRef, role1);
        try {
            Membership mbr = generateMembership("Role2", "user.john");
            zms.putMembership(mockDomRsrcCtx, "MbrAddDom6", "Role1", "user.john", auditRef, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrAddDom6", auditRef);
    }
    
    @Test
    public void testPutMembershipMemberMismatch() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom7",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("MbrAddDom7", "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrAddDom7", "Role1", auditRef, role1);
        try {
            Membership mbr = generateMembership("Role1", "user.john");
            zms.putMembership(mockDomRsrcCtx, "MbrAddDom7", "Role1", "user.johnny", auditRef, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrAddDom7", auditRef);
    }
    
    @Test
    public void testPutMembershipThrowException() {
        String domainName = "MbrGetRoleDom1";
        String roleName = "Role1";
        String memberName1 = "user.john";
        String memberName2 = "user.jane";
        String wrongDomainName = "MbrGetRoleDom2";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // Tests the putMembership() condition : if (domain == null)...
        try {
            // Trying to add a wrong domain name.
            Membership mbr = generateMembership(roleName, memberName1);
            zms.putMembership(mockDomRsrcCtx, wrongDomainName, roleName, memberName1, auditRef, mbr);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        // Tests the putMembership() condition: if (collection == null)...
        try {
            // Should fail because we never added a role resource.
            Membership mbr = generateMembership(roleName, memberName1);
            zms.putMembership(mockDomRsrcCtx, domainName, roleName, memberName1, auditRef, mbr);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        // Tests the putMembership() condition : invalid membership object - null
        try {
            // Trying to add a wrong domain name.
            zms.putMembership(mockDomRsrcCtx, wrongDomainName, roleName, memberName1, auditRef, null);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
        
        // Tests the putMembership() condition : invalid membership object - missing name
        try {
            // Trying to add a wrong domain name.
            Membership mbr = new Membership();
            zms.putMembership(mockDomRsrcCtx, wrongDomainName, roleName, memberName1, auditRef, mbr);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
        
        // Tests the putMembership() condition: if (role == null)...
        try {
            String wrongRoleName = "Role2";
            
            Role role1 = createRoleObject(domainName, roleName, null,
                    memberName1, memberName2);
            zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);
            
            // Trying to add member to non-existent role.
            Membership mbr = generateMembership(wrongRoleName, memberName1);
            zms.putMembership(mockDomRsrcCtx, domainName, wrongRoleName, memberName1, auditRef, mbr);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testDeleteMembership() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrDelDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("MbrDelDom1", "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrDelDom1", "Role1", auditRef, role1);
        zms.deleteMembership(mockDomRsrcCtx, "MbrDelDom1", "Role1", "user.joe", auditRef);

        Role role = zms.getRole(mockDomRsrcCtx, "MbrDelDom1", "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 1);

        boolean found = false;
        for (RoleMember member: members) {
            if (member.getMemberName().equalsIgnoreCase("user.joe")) {
                fail("delete user.joe failed");
            }
            if (member.getMemberName().equalsIgnoreCase("user.jane")) {
                found = true;
            }
        }
        if (!found) {
            fail("user.jane not found");
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrDelDom1", auditRef);
    }

    @Test
    public void testDeleteMembershipMissingAuditRef() {
        String domain = "testDeleteMembershipMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Role role = createRoleObject(
            domain, "Role1", null, "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domain, "Role1", auditRef, role);

        try {
            zms.deleteMembership(mockDomRsrcCtx, domain, "Role1", "user.joe", null);
            fail("requesterror not thrown by deleteMembership.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testDeleteMembershipInvalidDomain() {
        String domainName = "MbrGetRoleDom1";
        String roleName = "Role1";
        String memberName1 = "user.john";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // Tests the deleteMembership() condition : if (domain == null)...
        try {
            String wrongDomainName = "MbrGetRoleDom2";
            
            // Should fail because this domain does not exist.
            zms.deleteMembership(mockDomRsrcCtx, wrongDomainName, roleName, memberName1, auditRef);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testDeleteMembershipInvalidRoleCollection() {
        String domainName = "MbrGetRoleDom1";
        String roleName = "Role1";
        String memberName1 = "user.john";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // Test the deleteMembership() condition: if (collection == null)...
        try {
            // Should fail b/c a role entity was never added.
            zms.deleteMembership(mockDomRsrcCtx, domainName, roleName, memberName1, auditRef);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testDeleteMembershipInvalidRole() {
        String domainName = "MbrGetRoleDom1";
        String roleName = "Role1";
        String memberName1 = "user.john";
        String memberName2 = "user.jane";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // Tests the deleteMembership() condition: if (role == null)... 
        try {
            String wrongRoleName = "Role2";
            Role role1 = createRoleObject(domainName, roleName, null,
                    memberName1, memberName2);
            zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, role1);
            
            // Should fail b/c trying to find a non-existent role.
            zms.deleteMembership(mockDomRsrcCtx, domainName, wrongRoleName, memberName1, auditRef);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testDeleteMembershipAdminRoleSingleMember() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_delmembershipadminrsm";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domainName = "MbrGetRoleDom1";
        String memberName1 = "user.john";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // Test the deleteMembership() condition: if ("admin".equals(roleName))...
        try {
            String adminRoleName = "admin";
            
            List<RoleMember> members = new ArrayList<>();
            members.add(new RoleMember().setMemberName(memberName1));
            Role role1 = createRoleObject(domainName, adminRoleName, null, members);
            zmsImpl.putRole(mockDomRsrcCtx, domainName, adminRoleName, auditRef, role1);
            
            // Can not delete the last admin role.
            zmsImpl.deleteMembership(mockDomRsrcCtx, domainName, adminRoleName, memberName1, auditRef);
            fail("forbiddenerror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 403);
        }
        
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testDeleteMembershipNormalizedUser() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrDelDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("MbrDelDom1", "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrDelDom1", "Role1", auditRef, role1);
        zms.deleteMembership(mockDomRsrcCtx, "MbrDelDom1", "Role1", "user:joe", auditRef);

        Role role = zms.getRole(mockDomRsrcCtx, "MbrDelDom1", "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertEquals(members.get(0).getMemberName(), "user.jane");

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrDelDom1", auditRef);
    }
    
    @Test
    public void testDeleteMembershipNormalizeduser() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrDelDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("MbrDelDom1", "Role1", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, "MbrDelDom1", "Role1", auditRef, role1);
        zms.deleteMembership(mockDomRsrcCtx, "MbrDelDom1", "Role1", "user:joe", auditRef);

        Role role = zms.getRole(mockDomRsrcCtx, "MbrDelDom1", "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertEquals(members.get(0).getMemberName(), "user.jane");

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrDelDom1", auditRef);
    }
    
    @Test
    public void testDeleteMembershipNormalizedService() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrDelDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
        
        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, subDom2);
        
        Role role1 = createRoleObject("MbrDelDom1", "Role1", null,
                "user.joe", "coretech.storage");
        zms.putRole(mockDomRsrcCtx, "MbrDelDom1", "Role1", auditRef, role1);
        zms.deleteMembership(mockDomRsrcCtx, "MbrDelDom1", "Role1", "coretech:service.storage", auditRef);

        Role role = zms.getRole(mockDomRsrcCtx, "MbrDelDom1", "Role1", false, false);
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertEquals(members.get(0).getMemberName(), "user.joe");

        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MbrDelDom1", auditRef);
    }

    @Test
    public void testGetPolicyList() {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyListDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject("PolicyListDom1", "Policy1");
        zms.putPolicy(mockDomRsrcCtx, "PolicyListDom1", "Policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject("PolicyListDom1", "Policy2");
        zms.putPolicy(mockDomRsrcCtx, "PolicyListDom1", "Policy2", auditRef, policy2);

        PolicyList policyList = zms.getPolicyList(mockDomRsrcCtx, "PolicyListDom1", null, null);
        assertNotNull(policyList);

        // policy count +1 due to admin policy
        assertEquals(policyList.getNames().size(), 3);

        assertTrue(policyList.getNames().contains("Policy1".toLowerCase()));
        assertTrue(policyList.getNames().contains("Policy2".toLowerCase()));
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyListDom1", auditRef);
    }

    @Test
    public void testGetPolicyListParams() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "PolicyListParamsDom1", "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject("PolicyListParamsDom1", "Policy1");
        zms.putPolicy(mockDomRsrcCtx, "PolicyListParamsDom1", "Policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject("PolicyListParamsDom1", "Policy2");
        zms.putPolicy(mockDomRsrcCtx, "PolicyListParamsDom1", "Policy2", auditRef, policy2);

        PolicyList policyList = zms.getPolicyList(mockDomRsrcCtx, "PolicyListParamsDom1", null,
                "Policy1");
        assertNotNull(policyList);

        assertFalse(policyList.getNames().contains("Policy1".toLowerCase()));
        assertTrue(policyList.getNames().contains("Policy2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyListParamsDom1", auditRef);
    }
    
    @Test
    public void testGetPolicyListThrowException() {
        try {
            zms.getPolicyList(mockDomRsrcCtx, "WrongDomainName", null, null);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testGetPolicy() {

        TestAuditLogger alogger = new TestAuditLogger();
        List<String> aLogMsgs = alogger.getLogMsgList();
        String storeFile = ZMS_DATA_STORE_FILE + "_getpol";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyGetDom1",
                "Test Domain1", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject("PolicyGetDom1", "Policy1");
        zmsImpl.putPolicy(mockDomRsrcCtx, "PolicyGetDom1", "Policy1", auditRef, policy1);

        Policy policy = zmsImpl.getPolicy(mockDomRsrcCtx, "PolicyGetDom1", "Policy1");
        assertNotNull(policy);
        assertEquals(policy.getName(), "PolicyGetDom1:policy.Policy1".toLowerCase());

        List<Assertion> assertList = policy.getAssertions();
        assertNotNull(assertList);
        assertEquals(assertList.size(), 1);
        Assertion obj = assertList.get(0);
        assertEquals(obj.getAction(), "*");
        assertEquals(obj.getEffect(), AssertionEffect.ALLOW);
        assertEquals(obj.getResource(), "policygetdom1:*");
        assertEquals(obj.getRole(), "PolicyGetDom1:role.Role1".toLowerCase());

        boolean foundError = false;
        System.err.println("testGetPolicy: Number of lines: " + aLogMsgs.size());
        for (String msg: aLogMsgs) {
            if (msg.indexOf("WHAT-api=(putpolicy)") == -1) {
                continue;
            }
            assertTrue(msg.indexOf("CLIENT-IP=(" + MOCKCLIENTADDR + ")") != -1, msg);
            int index = msg.indexOf("WHAT-details=(");
            assertTrue(index != -1, msg);
            int index2 = msg.indexOf("\"added-assertions\": [{\"role\": \"policygetdom1:role.role1\", \"action\": \"*\", \"effect\": \"ALLOW\", \"resource\": \"policygetdom1:*\"}]");
            assertTrue(index < index2, msg);
            index2 = msg.indexOf("ERROR");
            assertTrue(index2 == -1, msg);
            foundError = true;
            break;
        }
        assertTrue(foundError);

        // modify the assertion: result is add of new assertion, delete of old
        //
        obj.setAction("layup");
        obj.setEffect(AssertionEffect.DENY);
        List<Assertion> assertions = new ArrayList<>();
        assertions.add(obj);
        policy1.setAssertions(assertions);
        aLogMsgs.clear();
        zmsImpl.putPolicy(mockDomRsrcCtx, "PolicyGetDom1", "Policy1", auditRef, policy1);

        foundError = false;
        System.err.println("testGetPolicy: Number of lines: " + aLogMsgs.size());
        for (String msg: aLogMsgs) {
            if (msg.indexOf("WHAT-api=(putpolicy)") == -1) {
                continue;
            }
            assertTrue(msg.indexOf("CLIENT-IP=(" + MOCKCLIENTADDR + ")") != -1, msg);
            int index = msg.indexOf("WHAT-details=(");
            assertTrue(index != -1, msg);
            int index2 = msg.indexOf("\"added-assertions\": [{\"role\": \"policygetdom1:role.role1\", \"action\": \"layup\", \"effect\": \"DENY\", \"resource\": \"policygetdom1:*\"}]");
            assertTrue(index < index2, msg);
            index2 = msg.indexOf("\"deleted-assertions\": [{\"role\": \"policygetdom1:role.role1\", \"action\": \"*\", \"effect\": \"ALLOW\", \"resource\": \"policygetdom1:*\"}]");
            index2 = msg.indexOf("ERROR");
            assertTrue(index2 == -1, msg);
            foundError = true;
            break;
        }
        assertTrue(foundError);

        // this should throw an exception
        try {
            zmsImpl.getPolicy(mockDomRsrcCtx, "PolicyGetDom1", "Policy2");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyGetDom1", auditRef);
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testGetPolicyThrowException() {
        String domainName = "PolicyGetDom1";
        String policyName = "Policy1";
        
        // Tests the getPolicy() condition : if (domain == null)...
        try {
            zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // Tests the getPolicy() condition: if (collection == null)...
        try {
            // Should fail b/c a policy was never added.
            zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }

        // Tests the getPolicy() condition: if (policy == null)...
        try {
            String wrongPolicyName = "Policy2";

            Policy policy1 = createPolicyObject(domainName, policyName);
            zms.putPolicy(mockDomRsrcCtx, domainName, policyName, auditRef, policy1);

            // Should fail b/c trying to find a non-existent policy.
            zms.getPolicy(mockDomRsrcCtx, domainName, wrongPolicyName);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testPutPolicyThrowException() {
        String domainName = "DomainName";
        String policyName = "PolicyName";
        String wrongPolicyName = "WrongPolicyName";
        
        // Tests the putPolicy() condition : if (!policyResourceName(domainName, policyName).equals(policy.getName()))...
        try {
            Policy policy = createPolicyObject(domainName, wrongPolicyName);
            
            // policyName should not be the same as policy.getName()
            zms.putPolicy(mockDomRsrcCtx, domainName, policyName, auditRef, policy);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
        
        // Tests the putPolicy() condition: if (domain == null)...
        try {
            Policy policy = createPolicyObject(domainName, policyName);
            
            // should fail b/c we never created a top level domain.
            zms.putPolicy(mockDomRsrcCtx, domainName, policyName, auditRef, policy);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testCreatePolicy() {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyAddDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject("PolicyAddDom1", "Policy1");
        zms.putPolicy(mockDomRsrcCtx, "PolicyAddDom1", "Policy1", auditRef, policy1);

        Policy policyRes2 = zms.getPolicy(mockDomRsrcCtx, "PolicyAddDom1", "Policy1");
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), "PolicyAddDom1:policy.Policy1".toLowerCase());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyAddDom1", auditRef);
    }

    @Test
    public void testCreatePolicyWithLocalName() {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyAddDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = new Policy();
        policy.setName("policy1");

        Assertion assertion = new Assertion();
        assertion.setAction("read");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("policyadddom1:*");
        assertion.setRole("policyadddom1:role.admin");

        List<Assertion> assertList = new ArrayList<Assertion>();
        assertList.add(assertion);

        policy.setAssertions(assertList);

        zms.putPolicy(mockDomRsrcCtx, "PolicyAddDom1", "Policy1", auditRef, policy);

        Policy policyRes2 = zms.getPolicy(mockDomRsrcCtx, "PolicyAddDom1", "Policy1");
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), "PolicyAddDom1:policy.Policy1".toLowerCase());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyAddDom1", auditRef);
    }
    
    @Test
    public void testCreatePolicyMissingAuditRef() {
        String domain = "testCreatePolicyMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Policy policy = createPolicyObject(domain, "Policy1");
        try {
            zms.putPolicy(mockDomRsrcCtx, domain, "Policy1", null, policy);
            fail("requesterror not thrown by putPolicy.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testPutPolicyChanges() {
        String domain     = "PutPolicyChanges";
        String policyName = "Jobs";
        TopLevelDomain dom1 = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject(domain, policyName);
        List<Assertion> origAsserts = policy1.getAssertions();

        String userId = "hank";
        
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=" + userId;
        Principal principal = SimplePrincipal.create("user", userId, unsignedCreds + ";s=signature",
                0, principalAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);
        
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        zms.putPolicy(rsrcCtx1, domain, policyName, auditRef, policy1);

        Policy policyRes1A = zms.getPolicy(mockDomRsrcCtx, domain, policyName);
        List<Assertion> resAsserts = policyRes1A.getAssertions();

        // check assertions are the same - should only be 1
        assertEquals(origAsserts.size(), resAsserts.size());

        // now replace the old assertion with a new ones
        //
        Assertion assertionA = new Assertion();
        assertionA.setResource(domain + ":books");
        assertionA.setAction("READ");
        assertionA.setRole(domain + ":role.librarian");
        assertionA.setEffect(AssertionEffect.ALLOW);

        Assertion assertionB = new Assertion();
        assertionB.setResource(domain + ":jupiter");
        assertionB.setAction("TRAVEL");
        assertionB.setRole(domain + ":role.astronaut");
        assertionB.setEffect(AssertionEffect.ALLOW);

        List<Assertion> newAssertions = new ArrayList<Assertion>();
        newAssertions.add(assertionA);
        newAssertions.add(assertionB);

        policyRes1A.setAssertions(newAssertions);
        
        zms.putPolicy(mockDomRsrcCtx, domain, policyName, auditRef, policyRes1A);

        Policy policyRes1B = zms.getPolicy(mockDomRsrcCtx, domain, policyName);
        List<Assertion> resAssertsB = policyRes1B.getAssertions();

        // check assertions are the same - should be 2
        assertEquals(newAssertions.size(), resAssertsB.size());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
    }

    @Test
    public void testPutAdminPolicyRejection() {
        
        String domain = "put-admin-rejection";

        TopLevelDomain dom1 = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = createPolicyObject(domain, "admin");
        try {
            zms.putPolicy(mockDomRsrcCtx, domain, "admin", auditRef, policy);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("admin policy cannot be modified"), ex.getMessage());
        }
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
    }
    
    @Test
    public void testCreatePolicyNoAssertions() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "testCreatePolicyNoAssertions", "Test Domain1", "testOrg",
                adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = new Policy();
        policy1.setName(ZMSUtils.policyResourceName("testCreatePolicyNoAssertions",
                "Policy1"));

        try {
            zms.putPolicy(mockDomRsrcCtx, "testCreatePolicyNoAssertions", "Policy1", auditRef, policy1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "testCreatePolicyNoAssertions", auditRef);
    }

    @Test
    public void testPutPolicyInvalidAssertionResources() {
        
        String domainName = "InvalidAssertionResources";
        String policyName = "Policy1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(
                domainName, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = new Policy();
        policy.setName(ZMSUtils.policyResourceName(domainName, policyName));

        // assertion missing domain name
        
        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("resource1");
        assertion.setRole(ZMSUtils.roleResourceName(domainName, "role1"));

        List<Assertion> assertList = new ArrayList<Assertion>();
        assertList.add(assertion);
        policy.setAssertions(assertList);
        
        try {
            zms.putPolicy(mockDomRsrcCtx, domainName, policyName, auditRef, policy);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        // assertion with invalid domain name
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain name:resource1");
        assertion.setRole(ZMSUtils.roleResourceName(domainName, "role1"));
        
        assertList.clear();
        assertList.add(assertion);
        policy.setAssertions(assertList);
        
        try {
            zms.putPolicy(mockDomRsrcCtx, domainName, policyName, auditRef, policy);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testCreatePolicyMismatchName() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "PolicyAddMismatchNameDom1", "Test Domain1", "testOrg",
                adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject("PolicyAddMismatchNameDom1",
                "Policy1");

        try {
            zms.putPolicy(mockDomRsrcCtx, "PolicyAddMismatchNameDom1",
                    "PolicyAddMismatchNameDom1.Policy1", auditRef, policy1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyAddMismatchNameDom1", auditRef);
    }

    @Test
    public void testCreatePolicyInvalidName() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "PolicyAddInvalidNameDom1", "Test Domain1", "testOrg",
                adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = new Policy();
        policy.setName("Policy1");

        try {
            zms.putPolicy(mockDomRsrcCtx, "PolicyAddInvalidNameDom1", "Policy1", auditRef, policy);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyAddInvalidNameDom1", auditRef);
    }

    @Test
    public void testCreatePolicyInvalidStruct() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "PolicyAddInvalidStructDom1", "Test Domain1", "testOrg",
                adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = new Policy();

        try {
            zms.putPolicy(mockDomRsrcCtx, "PolicyAddInvalidStructDom1", "Policy1", auditRef, policy);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyAddInvalidStructDom1", auditRef);
    }

    @Test
    public void testDeletePolicy() {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyDelDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject("PolicyDelDom1", "Policy1");
        zms.putPolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject("PolicyDelDom1", "Policy2");
        zms.putPolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy2", auditRef, policy2);

        Policy policyRes1 = zms.getPolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy1");
        assertNotNull(policyRes1);

        Policy policyRes2 = zms.getPolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy2");
        assertNotNull(policyRes2);

        zms.deletePolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy1", auditRef);

        // we need to get an exception here
        try {
            zms.getPolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        policyRes2 = zms.getPolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy2");
        assertNotNull(policyRes2);

        zms.deletePolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy2", auditRef);

        // we need to get an exception here
        try {
            zms.getPolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        // we need to get an exception here
        try {
            zms.getPolicy(mockDomRsrcCtx, "PolicyDelDom1", "Policy2");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyDelDom1", auditRef);
    }
    
    @Test
    public void testDeletePolicyThrowException() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_delpolhrowexc";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domainName = "WrongDomainName";
        String policyName = "WrongPolicyName";
        try {
            zmsImpl.deletePolicy(mockDomRsrcCtx, domainName, policyName, auditRef);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }

        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }

    @Test
    public void testDeleteAdminPolicy() {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyAdminDelDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        try {
            zms.deletePolicy(mockDomRsrcCtx, "PolicyAdminDelDom1", "admin", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyAdminDelDom1", auditRef);
    }

    @Test
    public void testDeletePolicyMissingAuditRef() {
        // create a new policy without an auditref
        String domain = "testDeletePolicyMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
            domain, null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        try {
            zms.deletePolicy(mockDomRsrcCtx, domain, "Policy1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testCreateServiceIdentity() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceAddDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceAddDom1", "Service1", auditRef, service);

        ServiceIdentity serviceRes2 = zms.getServiceIdentity(mockDomRsrcCtx, "ServiceAddDom1",
                "Service1");
        assertNotNull(serviceRes2);
        assertEquals(serviceRes2.getName(), "ServiceAddDom1.Service1".toLowerCase());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceAddDom1", auditRef);
    }

    @Test
    public void testCreateServiceIdentityNotSimpleName() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_createsvcidnosimplename";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddDom1NotSimpleName",
                "Test Domain1", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceAddDom1NotSimpleName",
                "Service1.Test", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        try {
            zmsImpl.putServiceIdentity(mockDomRsrcCtx, "ServiceAddDom1NotSimpleName", "Service1.Test", auditRef, service);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceAddDom1NotSimpleName", auditRef);
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testCreateServiceIdentityMissingAuditRef() {
        String domain = "testCreateServiceIdentityMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        ServiceIdentity service = createServiceObject(
            domain,
            "Service1", "http://localhost", "/usr/bin/java", "root",
            "users", "host1");
        try {
            zms.putServiceIdentity(mockDomRsrcCtx, domain, "Service1", null, service);
            fail("requesterror not thrown by putServiceIdentity.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testCreateServiceIdentityMismatchName() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddMismatchNameDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceAddMismatchNameDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        try {
            zms.putServiceIdentity(mockDomRsrcCtx, "ServiceAddMismatchNameDom1", 
                    "ServiceAddMismatchNameDom1.Service1", auditRef, service);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceAddMismatchNameDom1", auditRef);
    }

    @Test
    public void testCreateServiceIdentityInvalidName() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddInvalidNameDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = new ServiceIdentity();
        service.setName("Service1");

        try {
            zms.putServiceIdentity(mockDomRsrcCtx, "ServiceAddInvalidNameDom1", "Service1", auditRef, service);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceAddInvalidNameDom1", auditRef);
    }

    @Test
    public void testCreateServiceIdentityInvalidCert() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddInvalidCertDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = new ServiceIdentity();
        service.setName(ZMSUtils.serviceResourceName("ServiceAddInvalidCertDom1", "Service1"));
        List<PublicKeyEntry> pubKeys = new ArrayList<>();
        pubKeys.add(new PublicKeyEntry().setId("0").setKey("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTk"));
        service.setPublicKeys(pubKeys);
        
        try {
            zms.putServiceIdentity(mockDomRsrcCtx, "ServiceAddInvalidCertDom1", "Service1", auditRef, service);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceAddInvalidCertDom1", auditRef);
    }

    @Test
    public void testCreateServiceIdentityInvalidStruct() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddInvalidStructDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = new ServiceIdentity();
        
        try {
            zms.putServiceIdentity(mockDomRsrcCtx, "ServiceAddInvalidStructDom1", "Service1", auditRef, service);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceAddInvalidStructDom1", auditRef);
    }


    @Test
    public void testPutServiceIdentityWithoutPubKey() {
        String domainName = "ServicePutDom1";
        String serviceName = "Service1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = new ServiceIdentity();
        service.setName(ZMSUtils.serviceResourceName(domainName, serviceName));

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, service);

        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), "ServicePutDom1.Service1".toLowerCase());

        zms.deleteTopLevelDomain(mockDomRsrcCtx,  domainName, auditRef);
    }
    
    @Test
    public void testPutServiceIdentityThrowException() {
        String domainName = "DomainName";
        String serviceName = "ServiceName";
        String wrongServiceName = "WrongServiceName";
        
        // Tests the putServiceIdentity() condition: if (!serviceResourceName(domainName, serviceName).equals(detail.getName()))...
        try {
            ServiceIdentity detail = createServiceObject(domainName,
                    wrongServiceName, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            
            // serviceName should not rendered to be the same as domainName:service.wrongServiceName
            zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, detail);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
        
        // Tests the putServiceIdentity() condition: if (domain == null)...
        try {
            ServiceIdentity detail = createServiceObject(domainName,
                    serviceName, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            
            // should fail b/c we never created a top level domain.
            zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, detail);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testGetServiceIdentity() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceGetDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceGetDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceGetDom1", "Service1", auditRef, service);

        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, "ServiceGetDom1",
                "Service1");
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), "ServiceGetDom1.Service1".toLowerCase());
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getProviderEndpoint().toString(),
                "http://localhost");
        assertEquals(serviceRes.getUser(), "root");

        List<String> hosts = serviceRes.getHosts();
        assertNotNull(hosts);
        assertEquals(hosts.size(), 1);
        assertEquals(hosts.get(0), "host1");

        // this should throw a not found exception
        try {
            zms.getServiceIdentity(mockDomRsrcCtx, "ServiceGetDom1", "Service2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 404);
        }

        // this should throw a request error exception
        try {
            zms.getServiceIdentity(mockDomRsrcCtx, "ServiceGetDom1", "Service2.Service3");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceGetDom1", auditRef);
    }
    
    @Test
    public void testGetServiceIdentityThrowException() {
        String domainName = "ServiceGetDom1";
        String serviceName = "Service1";
        
        // Tests the getServiceIdentity() condition : if (domain == null)...
        try {
            // Should fail because we never created this domain.
            zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // Tests the getServiceIdentity() condition : if (collection == null)...
        try {
            // Should fail because we never added a service identity to this domain.
            zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        // Tests the getServiceIdentity() condition : if (service == null)...
        try {
            String wrongServiceName = "Service2";
            
            ServiceIdentity service = createServiceObject(domainName,
                    serviceName, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, service);

            // Should fail because trying to find a non-existent service identity.
            zms.getServiceIdentity(mockDomRsrcCtx, domainName, wrongServiceName);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testDeleteServiceIdentity() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceDelDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service1 = createServiceObject("ServiceDelDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1", "Service1", auditRef, service1);

        ServiceIdentity service2 = createServiceObject("ServiceDelDom1",
                "Service2", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1", "Service2", auditRef, service2);

        ServiceIdentity serviceRes1 = zms.getServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1",
                "Service1");
        assertNotNull(serviceRes1);

        ServiceIdentity serviceRes2 = zms.getServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1",
                "Service2");
        assertNotNull(serviceRes2);

        zms.deleteServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1", "Service1", auditRef);

        // this should throw a not found exception
        try {
            zms.getServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1", "Service1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 404);
        }

        serviceRes2 = zms.getServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1", "Service2");
        assertNotNull(serviceRes2);

        zms.deleteServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1", "Service2", auditRef);

        // this should throw a not found exception
        try {
            zms.getServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1", "Service1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 404);
        }

        // this should throw a not found exception
        try {
            zms.getServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1", "Service2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 404);
        }

        // this should throw an invalid exception
        try {
            zms.getServiceIdentity(mockDomRsrcCtx, "ServiceDelDom1", "Service2.Service3");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceDelDom1", auditRef);
    }

    @Test
    public void testDeleteServiceIdentityMissingAuditRef() {
        String domain = "testDeleteServiceIdentityMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        ServiceIdentity service = createServiceObject(
            domain,
            "Service1", "http://localhost", "/usr/bin/java", "root",
            "users", "host1");
        zms.putServiceIdentity(mockDomRsrcCtx, domain, "Service1", auditRef, service);
        ServiceIdentity serviceRes =
            zms.getServiceIdentity(mockDomRsrcCtx, domain, "Service1");
        assertNotNull(serviceRes);
        try {
            zms.deleteServiceIdentity(mockDomRsrcCtx, domain, "Service1", null);
            fail("requesterror not thrown by deleteServiceIdentity.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testDeleteServiceIdentityThrowException() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_delsvcidthrowexc";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domainName = "WrongDomainName";
        String serviceName = "WrongServiceName";
        try {
            zmsImpl.deleteServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testGetServiceIdentityList() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceListDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service1 = createServiceObject("ServiceListDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceListDom1", "Service1", auditRef, service1);

        ServiceIdentity service2 = createServiceObject("ServiceListDom1",
                "Service2", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceListDom1", "Service2", auditRef, service2);

        ServiceIdentityList serviceList = zms.getServiceIdentityList(
                mockDomRsrcCtx, "ServiceListDom1", null, null);
        assertNotNull(serviceList);
        assertEquals(serviceList.getNames().size(), 2);

        assertTrue(serviceList.getNames().contains("Service1".toLowerCase()));
        assertTrue(serviceList.getNames().contains("Service2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceListDom1", auditRef);
    }

    @Test
    public void testGetServiceIdentityListParams() {

        TopLevelDomain dom1 = createTopLevelDomainObject(
                "ServiceListParamsDom1", "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service1 = createServiceObject("ServiceListParamsDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceListParamsDom1", "Service1", auditRef, service1);

        ServiceIdentity service2 = createServiceObject("ServiceListParamsDom1",
                "Service2", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceListParamsDom1", "Service2", auditRef, service2);

        ServiceIdentityList serviceList = zms.getServiceIdentityList(
                mockDomRsrcCtx, "ServiceListParamsDom1", 1, null);
        assertNotNull(serviceList);
        assertEquals(serviceList.getNames().size(), 1);

        serviceList = zms.getServiceIdentityList(mockDomRsrcCtx, "ServiceListParamsDom1", null,
                "Service1");
        assertNotNull(serviceList);
        assertEquals(serviceList.getNames().size(), 1);

        assertFalse(serviceList.getNames().contains("Service1".toLowerCase()));
        assertTrue(serviceList.getNames().contains("Service2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceListParamsDom1", auditRef);
    }
    
    @Test
    public void testGetServiceIdentityListThrowException() {
        String domainName = "WrongDomainName";
        try {
            zms.getServiceIdentityList(mockDomRsrcCtx, domainName, null, null);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testGetEntity() {

        TopLevelDomain dom1 = createTopLevelDomainObject("GetEntityDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Entity entity1 = createEntityObject("Entity1");
        zms.putEntity(mockDomRsrcCtx, "GetEntityDom1", "Entity1", auditRef, entity1);

        Entity entity2 = zms.getEntity(mockDomRsrcCtx, "GetEntityDom1", "Entity1");
        assertNotNull(entity2);

        assertEquals(entity2.getName(), "Entity1".toLowerCase());
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "GetEntityDom1", auditRef);
    }
    
    @Test
    public void testGetEntityThrowException() {
        try {
            zms.getEntity(mockDomRsrcCtx, "wrongDomainName", "wrongEntityName");
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testCreateEntity() {

        TopLevelDomain dom1 = createTopLevelDomainObject("CreateEntityDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Entity entity1 = createEntityObject("Entity1");
        zms.putEntity(mockDomRsrcCtx, "CreateEntityDom1", "Entity1", auditRef, entity1);

        Entity entity2 = zms.getEntity(mockDomRsrcCtx, "CreateEntityDom1", "Entity1");
        assertNotNull(entity2);
        assertEquals(entity2.getName(), "Entity1".toLowerCase());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "CreateEntityDom1", auditRef);
    }

    @Test
    public void testListEntity() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ListEntityDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        EntityList entityList = zms.getEntityList(mockDomRsrcCtx, "ListEntityDom1");
        assertNotNull(entityList);
        assertEquals(0, entityList.getNames().size());
        
        Entity entity1 = createEntityObject("Entity1");
        zms.putEntity(mockDomRsrcCtx, "ListEntityDom1", "Entity1", auditRef, entity1);

        entityList = zms.getEntityList(mockDomRsrcCtx, "ListEntityDom1");
        assertNotNull(entityList);
        assertEquals(1, entityList.getNames().size());
        assertTrue(entityList.getNames().contains("entity1"));

        Entity entity2 = createEntityObject("Entity2");
        zms.putEntity(mockDomRsrcCtx, "ListEntityDom1", "Entity2", auditRef, entity2);

        entityList = zms.getEntityList(mockDomRsrcCtx, "ListEntityDom1");
        assertNotNull(entityList);
        assertEquals(2, entityList.getNames().size());
        assertTrue(entityList.getNames().contains("entity1"));
        assertTrue(entityList.getNames().contains("entity2"));

        zms.deleteEntity(mockDomRsrcCtx, "ListEntityDom1", "entity1", auditRef);
        
        entityList = zms.getEntityList(mockDomRsrcCtx, "ListEntityDom1");
        assertNotNull(entityList);
        assertEquals(1, entityList.getNames().size());
        assertTrue(entityList.getNames().contains("entity2"));
        
        zms.deleteEntity(mockDomRsrcCtx, "ListEntityDom1", "entity2", auditRef);

        entityList = zms.getEntityList(mockDomRsrcCtx, "ListEntityDom1");
        assertNotNull(entityList);
        assertEquals(0, entityList.getNames().size());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListEntityDom1", auditRef);
    }
    
    @Test
    public void testCreateEntityMissingAuditRef() {
        String domain = "testCreateEntityMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Entity entity = createEntityObject("Entity1");
        try {
            zms.putEntity(mockDomRsrcCtx, domain, "Entity1", null, entity);
            fail("requesterror not thrown by putEntity.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testCreateEntityReservedNames() {
        // create the weather domain
        
        TopLevelDomain dom = createTopLevelDomainObject("EntityReservedNames",
                "Test entity", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Role role = createRoleObject("EntityReservedNames", "Role1", null, null, null);
        zms.putRole(mockDomRsrcCtx, "EntityReservedNames", "Role1", auditRef, role);
        
        Policy policy = createPolicyObject("EntityReservedNames", "Policy1",
                "Role1", "READ", "EntityReservedNames:*", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "EntityReservedNames", "Policy1", auditRef, policy);

        ServiceIdentity service = createServiceObject("EntityReservedNames",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "EntityReservedNames", "Service1", auditRef, service);
        
        Entity entity = createEntityObject("role");
        try {
            zms.putEntity(mockDomRsrcCtx, "EntityReservedNames", "role", auditRef, entity);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        entity = createEntityObject("policy");
        try {
            zms.putEntity(mockDomRsrcCtx, "EntityReservedNames", "policy", auditRef, entity);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        entity = createEntityObject("service");
        try {
            zms.putEntity(mockDomRsrcCtx, "EntityReservedNames", "service", auditRef, entity);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        Role roleRes = zms.getRole(mockDomRsrcCtx, "EntityReservedNames", "Role1", false, false);
        assertNotNull(roleRes);
        
        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, "EntityReservedNames", "Policy1");
        assertNotNull(policyRes);
        
        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, "EntityReservedNames", "Service1");
        assertNotNull(serviceRes);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "EntityReservedNames", auditRef);
    }
    
    @Test
    public void testDeleteEntity() {

        TopLevelDomain dom1 = createTopLevelDomainObject("DelEntityDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Entity entity1 = createEntityObject("Entity1");
        zms.putEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity1", auditRef, entity1);

        Entity entity2 = createEntityObject("Entity2");
        zms.putEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity2", auditRef, entity2);

        Entity entityRes = zms.getEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity1");
        assertNotNull(entityRes);

        entityRes = zms.getEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity2");
        assertNotNull(entityRes);

        zms.deleteEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity1", auditRef);

        try {
            entityRes = zms.getEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        entityRes = zms.getEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity2");
        assertNotNull(entityRes);

        zms.deleteEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity2", auditRef);

        try {
            entityRes = zms.getEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        try {
            entityRes = zms.getEntity(mockDomRsrcCtx, "DelEntityDom1", "Entity2");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "DelEntityDom1", auditRef);
    }

    @Test
    public void testDeleteEntityMissingAuditRef() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_delentitymissauditref";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domain = "testDeleteEntityMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Entity entity = createEntityObject("Entity1");
        zmsImpl.putEntity(mockDomRsrcCtx, domain, "Entity1", auditRef, entity);

        try {
            zmsImpl.deleteEntity(mockDomRsrcCtx, domain, "Entity1", null);
            fail("requesterror not thrown by deleteEntity.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
            FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
        }
    }

    @Test
    public void testGetUserToken() {
        
        // Use real Principal Authority to verify signatures
        PrincipalAuthority principalAuthority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        principalAuthority.setKeyStore(zms);

        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        
        String userId = "george";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password",
                0, userAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        
        zms.privateKeyId = "0";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        UserToken token = zms.getUserToken(rsrcCtx1, userId, null, null);
        assertNotNull(token);
        assertTrue(token.getToken().startsWith("v=U1;d=user;n=" + userId + ";"));
        assertTrue(token.getToken().contains(";h=localhost"));
        assertTrue(token.getToken().contains(";i=10.11.12.13"));
        assertTrue(token.getToken().contains(";k=0"));
        // Verify signature
        Principal principalToVerify = principalAuthority.authenticate(token.getToken(), "10.11.12.13", "GET", null);
        assertNotNull(principalToVerify);
        
        zms.privateKeyId = "1";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKeyK1));
        token = zms.getUserToken(rsrcCtx1, userId, null, false);
        assertNotNull(token);
        assertTrue(token.getToken().contains("k=1"));
        // Verify signature
        principalToVerify = principalAuthority.authenticate(token.getToken(), "10.11.12.13", "GET", null);
        assertNotNull(principalToVerify);
        
        zms.privateKeyId = "2";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKeyK2));

        token = zms.getUserToken(rsrcCtx1, userId, null, null);
        assertNotNull(token);
        assertTrue(token.getToken().contains("k=2"));
        // Verify signature
        principalToVerify = principalAuthority.authenticate(token.getToken(), "10.11.12.13", "GET", null);
        assertNotNull(principalToVerify);
    }
    
    @Test
    public void testGetUserTokenAuthorizedService() {
        
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        
        String userId = "george";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password",
                0, userAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        
        zms.privateKeyId = "0";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        UserToken token = zms.getUserToken(rsrcCtx1, userId, "coretech.storage", null);
        assertNotNull(token);
        assertTrue(token.getToken().contains(";b=coretech.storage;"));
        
        token = zms.getUserToken(rsrcCtx1, userId, "coretech.storage,sports.hockey", false);
        assertNotNull(token);
        assertTrue(token.getToken().contains(";b=coretech.storage,sports.hockey;"));
    }
        
    @Test
    public void testGetUserTokenInvalidAuthorizedService() {
        
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        
        String userId = "george";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password",
                0, userAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        
        try {
            zms.getUserToken(rsrcCtx1, userId, "coretech.storage,sports", null);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
            assertTrue(ex.getMessage().contains("getUserToken: Service sports is not authorized in ZMS"));
        }

        try {
            zms.getUserToken(rsrcCtx1, userId, "baseball", false);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
            assertTrue(ex.getMessage().contains("getUserToken: Service baseball is not authorized in ZMS"));
        }
        
        try {
            zms.getUserToken(rsrcCtx1, userId, "hat trick", false);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
            assertTrue(ex.getMessage().contains("getUserToken: Service hat trick is not authorized in ZMS"));
        }
    }
    
    @Test
    public void testGetUserTokenExpiredIssueTime() {
        
        // Use real Principal Authority to verify signatures
        PrincipalAuthority principalAuthority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        principalAuthority.setKeyStore(zms);

        // we're going to set the issue time 2 hours before the current time
        
        long issueTime = (System.currentTimeMillis() / 1000) - 7200;
        
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        
        String userId = "george";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password",
                0, userAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        
        zms.privateKeyId = "0";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        UserToken token = zms.getUserToken(rsrcCtx1, userId, null, null);
        assertNotNull(token);
        // Verify signature
        Principal principalToVerify = principalAuthority.authenticate(token.getToken(), "10.11.12.13", "GET", null);
        assertNotNull(principalToVerify);
        
        // verify that the issue time for the user token is not our issue time
        
        PrincipalToken pToken = new PrincipalToken(token.getToken());
        assertNotEquals(pToken.getTimestamp(), issueTime);
        
        // verify that our expiry is close to 1 hour default value
        
        assertTrue(pToken.getExpiryTime() - (System.currentTimeMillis() / 1000) > 3500);
    }
    
    @Test
    public void testGetUserTokenMismatchName() {
        int code = 401;
        
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        
        String userId = "user1";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password",
                0, userAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        
        try {
            zms.getUserToken(rsrcCtx1, "user2", null, null);
            fail("unauthorizederror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), code);
        }
        
        try {
            zms.getUserToken(rsrcCtx1, "_self", null, false);
            fail("unauthorizederror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), code);
        }
        
        try {
            zms.getUserToken(rsrcCtx1, "self", null, false);
            fail("unauthorizederror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), code);
        }
    }
    
    @Test
    public void testGetUserTokenDefaultSelfName() {

        // Use real Principal Authority to verify signatures
        PrincipalAuthority principalAuthority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        principalAuthority.setKeyStore(zms);

        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        
        String userId = "user10";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password",
                0, userAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        
        zms.privateKeyId = "0";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        UserToken token = zms.getUserToken(rsrcCtx1, "_self_", null, false);
        assertNotNull(token);
        assertTrue(token.getToken().startsWith("v=U1;d=user;n=" + userId + ";"));
        assertTrue(token.getToken().contains(";h=localhost"));
        assertTrue(token.getToken().contains(";i=10.11.12.13"));
        assertTrue(token.getToken().contains(";k=0"));
        // Verify signature
        Principal principalToVerify = principalAuthority.authenticate(token.getToken(), "10.11.12.13", "GET", null);
        assertNotNull(principalToVerify);
    }
    
    @Test
    public void testGetUserTokenBadAuthority() {
        int code = 401;
        
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        
        try {
            zms.getUserToken(rsrcCtx1, "user1", null, null);
            fail("unauthorizederror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), code);
        }
    }
    
    @Test
    public void testGetUserTokenNullAuthority() {
        int code = 401;
        
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature");
        ResourceContext rsrcCtx1 = createResourceContext(principal);

        try {
            zms.getUserToken(rsrcCtx1, "user1", null, null);
            fail("unauthorizederror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), code);
        }
    }
    
    @Test
    public void testDeleteTenantRoles() {

        setupTenantDomainProviderService("DelTenantRolesDom1", "coretech", "storage",
                "http://localhost:8090/tableprovider");

        TenantRoles roles = zms.getTenantRoles(mockDomRsrcCtx, "coretech", "storage",
                "DelTenantRolesDom1");
        assertNotNull(roles);
        assertEquals(roles.getDomain(), "coretech");
        assertEquals(roles.getService(), "storage");
        assertEquals(roles.getTenant(), "DelTenantRolesDom1".toLowerCase());
        assertEquals(roles.getRoles().size(), 0);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        TenantRoles tenantRoles = new TenantRoles().setDomain("coretech")
                .setService("storage").setTenant("DelTenantRolesDom1")
                .setRoles(roleActions);

        zms.putTenantRoles(mockDomRsrcCtx, "coretech", "storage", "DelTenantRolesDom1",
                auditRef, tenantRoles);

        RoleList roleList = zms.getRoleList(mockDomRsrcCtx, "coretech", null, null);
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

        PolicyList policyList = zms.getPolicyList(mockDomRsrcCtx, "coretech", null, null);
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

        zms.deleteTenantRoles(mockDomRsrcCtx, "coretech", "storage", "DelTenantRolesDom1", auditRef);

        roleList = zms.getRoleList(mockDomRsrcCtx, "coretech", null, null);
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

        policyList = zms.getPolicyList(mockDomRsrcCtx, "coretech", null, null);
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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "DelTenantRolesDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
    }
 
    @Test
    public void testDeleteTenantRolesWithResourceGroup() {

        String domain = "testDeleteTenantRoles";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String serviceName  = "storage";
        String tenantDomain = "tenantTestDeleteTenantRoles";
        String resourceGroup = "Group1";
        
        TenantResourceGroupRoles tenantRoles = new TenantResourceGroupRoles().setDomain(domain)
                .setService(serviceName).setTenant(tenantDomain)
                .setRoles(roleActions).setResourceGroup(resourceGroup);
        zms.putTenantResourceGroupRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain, resourceGroup,
                auditRef, tenantRoles);

        TenantResourceGroupRoles tRoles = zms.getTenantResourceGroupRoles(mockDomRsrcCtx, domain, serviceName,
                tenantDomain, resourceGroup);
        assertNotNull(tRoles);
        assertEquals(domain.toLowerCase(), tRoles.getDomain());
        assertEquals(serviceName.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(TABLE_PROVIDER_ROLE_ACTIONS.size(), tRoles.getRoles().size());

        zms.deleteTenantResourceGroupRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain, resourceGroup, auditRef);

        tRoles = zms.getTenantResourceGroupRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain, resourceGroup);
        assertNotNull(tRoles);
        assertEquals(domain.toLowerCase(), tRoles.getDomain());
        assertEquals(serviceName.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(0, tRoles.getRoles().size());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "testDeleteTenantRoles", auditRef);
    }
    
    @Test
    public void testDeleteTenantRolesMissingAuditRef() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_deltenantrolesmissauditref";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domain = "testDeleteTenantRolesMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String serviceName  = "storage";
        String tenantDomain = "tenantTestDeleteTenantRolesMissingAuditRef";
        TenantRoles tenantRoles = new TenantRoles().setDomain(domain)
                .setService(serviceName).setTenant(tenantDomain)
                .setRoles(roleActions);
        zmsImpl.putTenantRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain, auditRef, tenantRoles);

        TenantRoles tRoles = zmsImpl.getTenantRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain);
        assertNotNull(tRoles);
        assertEquals(tRoles.getDomain(), domain.toLowerCase());
        assertEquals(tRoles.getService(), serviceName.toLowerCase());
        assertEquals(tRoles.getTenant(), tenantDomain.toLowerCase());
        assertEquals(tRoles.getRoles().size(), TABLE_PROVIDER_ROLE_ACTIONS.size());

        try {
            zmsImpl.deleteTenantRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain, null);
            fail("requesterror not thrown by deleteTenantRoles.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));

        } finally {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
            FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
        }
    }
 
    @Test
    public void testValidatedAdminUsersThrowException() {
        try {
            zms.validatedAdminUsers(null);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
    }

    @Test
    public void testPutDefaultAdmins() {

        TopLevelDomain sportsDomain = createTopLevelDomainObject("sports",
                "Test domain for sports", "testOrg", adminUser);
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
        } catch (ResourceException ex) {
        }
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, sportsDomain);

        List<String> adminList = new ArrayList<String>();
        DefaultAdmins admins = new DefaultAdmins();

        // negative test, pass an empty list
        admins.setAdmins(adminList);
        zms.putDefaultAdmins(mockDomRsrcCtx, "sports", auditRef, admins);

        Role role = zms.getRole(mockDomRsrcCtx, "sports", "admin", false, false);
        assertNotNull(role);
        assertEquals(role.getName(), "sports:role.admin");
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertEquals(members.get(0).getMemberName(), adminUser);
        
        // positive test
        adminList.add("user.sports_admin");
        adminList.add("sports.fantasy");
        adminList.add("user.joeschmoe");
        adminList.add("user.johndoe");

        admins.setAdmins(adminList);
        zms.putDefaultAdmins(mockDomRsrcCtx, "sports", auditRef, admins);

        role = zms.getRole(mockDomRsrcCtx, "sports", "admin", false, false);
        assertNotNull(role);
        assertEquals(role.getName(), "sports:role.admin");
        members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 5);

        // add user.testadminuser to the list for verification since it should be
        // there when the domain was added
        adminList.add(adminUser);
        for (String admin : adminList) {
            boolean found = false;
            for (RoleMember memberFromRole : members) {
                if (memberFromRole.getMemberName().equalsIgnoreCase(admin)) {
                    found = true;
                    break;
                }
            }
            assertTrue(found);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
    }

    @Test
    public void testPutDefaultAdminsMissingAuditRef() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_putdefaminsmissauditref";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domain = "testPutDefaultAdminsMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<String> adminList = new ArrayList<String>();
        adminList.add("user.sports_admin");
        adminList.add("sports.fantasy");
        DefaultAdmins admins = new DefaultAdmins();
        admins.setAdmins(adminList);
        try {
            zmsImpl.putDefaultAdmins(mockDomRsrcCtx, domain, null, admins);
            fail("requesterror not thrown by putDefaultAdmins.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
            FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
        }
    }
    
    @Test
    public void testPutDefaultAdmins_NoAdminRole() {

        TopLevelDomain sportsDomain = createTopLevelDomainObject("sports",
                "Test domain for sports", "testOrg", adminUser);
        
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
        } catch (ResourceException ex) {
        }
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, sportsDomain);

        // since we can't delete the admin role anymore
        // we're going to access the store object directly to
        // accomplish that for our unit test
        
        zms.dbService.executeDeleteRole(mockDomRsrcCtx, sportsDomain.getName(), "admin",
                auditRef, "unittest");
        
        List<String> adminList = new ArrayList<String>();
        DefaultAdmins admins = new DefaultAdmins();
        adminList.add("user.sports_admin");
        adminList.add("sports.fantasy");
        adminList.add("user.joeschmoe");
        adminList.add("user.johndoe");
        adminList.add(adminUser);

        admins.setAdmins(adminList);
        zms.putDefaultAdmins(mockDomRsrcCtx, "sports", auditRef, admins);

        Role role = zms.getRole(mockDomRsrcCtx, "sports", "admin", false, false);
        assertNotNull(role);
        assertEquals(role.getName(), "sports:role.admin");
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 5);

        // add user.testadminuser to the list for verification since it should be
        // there when the domain was added
        adminList.add(adminUser);
        for (String admin : adminList) {
            boolean found = false;
            for (RoleMember memberFromRole : members) {
                if (memberFromRole.getMemberName().equalsIgnoreCase(admin)) {
                    found = true;
                    break;
                }
            }
            assertTrue(found);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
    }

    @Test
    public void testPutDefaultAdmins_NoAdminPolicy() {

        TopLevelDomain sportsDomain = createTopLevelDomainObject("sports",
                "Test domain for sports", "testOrg", adminUser);
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
        } catch (ResourceException ex) {
        }
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, sportsDomain);

        // since we can't delete the admin policy anymore
        // we're going to access the store object directly to
        // accomplish that for our unit test
        
        zms.dbService.executeDeletePolicy(mockDomRsrcCtx, sportsDomain.getName(), "admin",
                auditRef, "unittest");

        List<String> adminList = new ArrayList<String>();
        DefaultAdmins admins = new DefaultAdmins();
        adminList.add("user.sports_admin");
        adminList.add("sports.fantasy");
        adminList.add("user.joeschmoe");
        adminList.add("user.johndoe");

        admins.setAdmins(adminList);
        zms.putDefaultAdmins(mockDomRsrcCtx, "sports", auditRef, admins);

        // Validate that admin policy has been added back
        Policy policy = zms.getPolicy(mockDomRsrcCtx, "sports", "admin");
        assertNotNull(policy);
        assertEquals(policy.getName(), "sports:policy.admin");
        List<Assertion> assertions = policy.getAssertions();
        boolean foundAssertion = false;
        for (Assertion assertion : assertions) {
            if ("sports:*".equals(assertion.getResource())
                    && "*".equals(assertion.getAction())
                    && "sports:role.admin".equals(assertion.getRole())) {
                foundAssertion = true;
            }
        }
        assertTrue(foundAssertion);

        Role role = zms.getRole(mockDomRsrcCtx, "sports", "admin", false, false);
        assertNotNull(role);
        assertEquals(role.getName(), "sports:role.admin");
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 5);

        for (String admin : adminList) {
            boolean found = false;
            for (RoleMember memberFromRole : members) {
                if (memberFromRole.getMemberName().equalsIgnoreCase(admin)) {
                    found = true;
                    break;
                }
            }
            assertTrue(found);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
    }

    @Test
    public void testPutDefaultAdmins_AdminPolicyWithDeny() {

        TopLevelDomain sportsDomain = createTopLevelDomainObject("sports",
                "Test domain for sports", "testOrg", adminUser);
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
        } catch (ResourceException ex) {
        }
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, sportsDomain);

        // Add policy which will DENY admin role
        Policy policy = new Policy();
        policy.setName(ZMSUtils.policyResourceName("sports", "denyAdmin"));
        Assertion assertion = new Assertion();
        assertion.setResource("sports:*");
        assertion.setAction("*");
        assertion.setRole("sports:role.admin");
        assertion.setEffect(AssertionEffect.DENY);
        List<Assertion> assertions = new ArrayList<Assertion>();
        assertions.add(assertion);
        policy.setAssertions(assertions);
        zms.putPolicy(mockDomRsrcCtx, "sports", "denyAdmin", auditRef, policy);

        List<String> adminList = new ArrayList<String>();
        DefaultAdmins admins = new DefaultAdmins();
        adminList.add("user.sports_admin");
        adminList.add("sports.fantasy");
        adminList.add("user.joeschmoe");
        adminList.add("user.johndoe");

        admins.setAdmins(adminList);
        zms.putDefaultAdmins(mockDomRsrcCtx, "sports", auditRef, admins);

        // denyAdmin policy should be deleted by putDefaultAdmins validation
        try {
            policy = zms.getPolicy(mockDomRsrcCtx, "sports", "denyAdmin");
            assertNotNull(policy); // should not be found
        } catch (ResourceException ex) {
            // policy should not be found
            if (ex.getCode() != 404) {
                throw ex;
            }
        }

        Role role = zms.getRole(mockDomRsrcCtx, "sports", "admin", false, false);
        assertNotNull(role);
        assertEquals(role.getName(), "sports:role.admin");
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 5);

        for (String admin : adminList) {
            boolean found = false;
            for (RoleMember memberFromRole : members) {
                if (memberFromRole.getMemberName().equalsIgnoreCase(admin)) {
                    found = true;
                    break;
                }
            }
            assertTrue(found);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
    }

    @Test
    public void testPutDefaultAdmins_DenyIndirectRole() {

        TopLevelDomain sportsDomain = createTopLevelDomainObject("sports",
                "Test domain for sports", "testOrg", adminUser);
        try {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
        } catch (ResourceException ex) {
        }
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, sportsDomain);

        // Add role indirectRole
        Role role = new Role();
        role.setName("sports:role.indirectRole");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.johnadams"));
        members.add(new RoleMember().setMemberName("user.sports_admin"));
        members.add(new RoleMember().setMemberName("sports.fantasy"));
        members.add(new RoleMember().setMemberName("user.joeschmoe"));
        members.add(new RoleMember().setMemberName("user.johndoe"));
        role.setRoleMembers(members);
        role.setTrust(null);
        zms.putRole(mockDomRsrcCtx, "sports", "indirectRole", auditRef, role);

        // Add policy which will DENY indirectRole role
        Policy policy = new Policy();
        policy.setName(ZMSUtils.policyResourceName("sports", "denyIndirectRole"));
        Assertion assertion = new Assertion();
        assertion.setResource("sports:*");
        assertion.setAction("*");
        assertion.setRole("sports:role.indirectRole");
        assertion.setEffect(AssertionEffect.DENY);
        List<Assertion> assertions = new ArrayList<Assertion>();
        assertions.add(assertion);
        policy.setAssertions(assertions);
        zms.putPolicy(mockDomRsrcCtx, "sports", "denyIndirectRole", auditRef, policy);

        List<String> adminList = new ArrayList<String>();
        DefaultAdmins admins = new DefaultAdmins();
        adminList.add("user.sports_admin");
        adminList.add("sports.fantasy");
        adminList.add("user.joeschmoe");
        adminList.add("user.johndoe");

        admins.setAdmins(adminList);
        zms.putDefaultAdmins(mockDomRsrcCtx, "sports", auditRef, admins);

        role = zms.getRole(mockDomRsrcCtx, "sports", "indirectRole", false, false);
        assertNotNull(role);
        assertEquals(role.getName(), "sports:role.indirectRole".toLowerCase());
        members = role.getRoleMembers();
        assertEquals(members.size(), 1);

        for (String admin : adminList) {
            boolean found = false;
            for (RoleMember memberFromRole : members) {
                if (memberFromRole.getMemberName().equalsIgnoreCase(admin)) {
                    found = true;
                    break;
                }
            }
            assertFalse(found);
        }

        role = zms.getRole(mockDomRsrcCtx, "sports", "admin", false, false);
        assertNotNull(role);
        assertEquals(role.getName(), "sports:role.admin");
        members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 5);

        for (String admin : adminList) {
            boolean found = false;
            for (RoleMember memberFromRole : members) {
                if (memberFromRole.getMemberName().equalsIgnoreCase(admin)) {
                    found = true;
                    break;
                }
            }
            assertTrue(found);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, sportsDomain.getName(), auditRef);
    }

    @Test
    public void testManageTenantRoles() {

        setupTenantDomainProviderService("AddTenantRolesDom1", "coretech", "storage",
                "http://localhost:8090/tableprovider");

        TenantRoles roles = zms.getTenantRoles(mockDomRsrcCtx, "coretech", "storage",
                "AddTenantRolesDom1");
        assertNotNull(roles);
        assertEquals(roles.getDomain(), "coretech");
        assertEquals(roles.getService(), "storage");
        assertEquals(roles.getTenant(), "AddTenantRolesDom1".toLowerCase());
        assertEquals(roles.getRoles().size(), 0);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        TenantRoles tenantRoles = new TenantRoles().setDomain("coretech")
                .setService("storage").setTenant("AddTenantRolesDom1")
                .setRoles(roleActions);

        zms.putTenantRoles(mockDomRsrcCtx, "coretech", "storage", "AddTenantRolesDom1",
                auditRef, tenantRoles);

        roles = zms.getTenantRoles(mockDomRsrcCtx, "coretech", "storage", "AddTenantRolesDom1");
        assertNotNull(roles);
        assertEquals(roles.getDomain(), "coretech");
        assertEquals(roles.getService(), "storage");
        assertEquals(roles.getTenant(), "AddTenantRolesDom1".toLowerCase());
        assertEquals(roles.getRoles().size(), 3);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "AddTenantRolesDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
    }

    @Test
    public void testGetSignedDomains() {

        // create multiple top level domains
        TopLevelDomain dom1 = createTopLevelDomainObject("SignedDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        // set the meta attributes for domain
        
        DomainMeta meta = createDomainMetaObject("Tenant Domain1", null, true, false, "12345", 0);
        zms.putDomainMeta(mockDomRsrcCtx, "signeddom1", auditRef, meta);
        
        TopLevelDomain dom2 = createTopLevelDomainObject("SignedDom2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        meta = createDomainMetaObject("Tenant Domain2", null, true, false, "12346", 0);
        zms.putDomainMeta(mockDomRsrcCtx, "signeddom2", auditRef, meta);
        
        DomainList domList = zms.getDomainList(mockDomRsrcCtx, null, null, null, null,
                null, null, null, null, null);
        List<String> domNames = domList.getNames();
        int numDoms = domNames.size();

        zms.privateKeyId = "0";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));

        GetSignedDomainsResult result = new GetSignedDomainsResult(mockDomRsrcCtx);
        SignedDomains sdoms = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, null, null, null, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
        }
        assertNotNull(sdoms);
        List<SignedDomain> list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(list.size(), numDoms);

        boolean dom1Found = false;
        boolean dom2Found = false;
        for(SignedDomain sDomain : list) {
            String signature = sDomain.getSignature();
            String keyId = sDomain.getKeyId();
            String publicKey = zms.getPublicKey("sys.auth", "zms", keyId);
            DomainData domainData = sDomain.getDomain();
            if (domainData.getName().equals("signeddom1")) {
                assertEquals("12345", domainData.getAccount());
                dom1Found = true;
            } else if (domainData.getName().equals("signeddom2")) {
                assertEquals("12346", domainData.getAccount());
                dom2Found = true;
            }
            assertTrue(Crypto.verify(SignUtils.asCanonicalString(sDomain.getDomain()), Crypto.loadPublicKey(publicKey), signature));
        }
        assertTrue(dom1Found);
        assertTrue(dom2Found);
        
        zms.privateKeyId = "1";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKeyK1));

        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        sdoms = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, null, null, null, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
        }
        assertNotNull(sdoms);
        list = null;
        list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(list.size(), numDoms);

        for(SignedDomain sDomain : list) {
            String signature = sDomain.getSignature();
            String keyId = sDomain.getKeyId();
            String publicKey = zms.getPublicKey("sys.auth", "zms", keyId);
            assertTrue(Crypto.verify(SignUtils.asCanonicalString(sDomain.getDomain()), Crypto.loadPublicKey(publicKey), signature));
            
            // we now need to verify the policy struct signature as well
            
            SignedPolicies signedPolicies = sDomain.getDomain().getPolicies();
            signature = signedPolicies.getSignature();
            keyId = signedPolicies.getKeyId();
            assertTrue(Crypto.verify(SignUtils.asCanonicalString(signedPolicies.getContents()), Crypto.loadPublicKey(publicKey), signature));
        }
        
        zms.privateKeyId = "2";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKeyK2));

        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        sdoms = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, null, null, null, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
        }
        assertNotNull(sdoms);

        list = null;
        list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(list.size(), numDoms);

        for(SignedDomain sDomain : list) {
            String signature = sDomain.getSignature();
            String keyId = sDomain.getKeyId();
            String publicKey = zms.getPublicKey("sys.auth", "zms", keyId);
            assertTrue(Crypto.verify(SignUtils.asCanonicalString(sDomain.getDomain()), Crypto.loadPublicKey(publicKey), signature));
        }

        // test metaonly=true
        //
        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        sdoms = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, null, "tRuE", null, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
        }
        assertNotNull(sdoms);

        list = null;
        list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(list.size(), numDoms);

        for (SignedDomain sDomain : list) {
            String signature = sDomain.getSignature();
            assertTrue(signature == null || signature.isEmpty());
            String keyId = sDomain.getKeyId();
            assertTrue(keyId == null || keyId.isEmpty());
            DomainData ddata = sDomain.getDomain();
            assertTrue(ddata != null);
            assertFalse(ddata.getName().isEmpty());
            assertTrue(ddata.getModified() != null);
            assertTrue(ddata.getPolicies() == null);
            assertTrue(ddata.getRoles() == null);
            assertTrue(ddata.getServices() == null);
        }

        // test metaonly=garbage
        //
        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        sdoms = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, null, "garbage", null, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
        }
        assertNotNull(sdoms);

        list = null;
        list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(list.size(), numDoms);

        for (SignedDomain sDomain : list) {
            String signature = sDomain.getSignature();
            String keyId = sDomain.getKeyId();
            String publicKey = zms.getPublicKey("sys.auth", "zms", keyId);
            assertTrue(Crypto.verify(SignUtils.asCanonicalString(sDomain.getDomain()), Crypto.loadPublicKey(publicKey), signature));
            DomainData ddata = sDomain.getDomain();
            assertTrue(ddata.getPolicies() != null);
            assertTrue(ddata.getRoles() != null && ddata.getRoles().size() > 0);
            assertTrue(ddata.getServices() != null);
        }

        // test metaonly=false
        //
        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        sdoms = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, null, "fAlSe", null, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
        }
        assertNotNull(sdoms);

        list = null;
        list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(list.size(), numDoms);

        for (SignedDomain sDomain : list) {
            String signature = sDomain.getSignature();
            String keyId = sDomain.getKeyId();
            String publicKey = zms.getPublicKey("sys.auth", "zms", keyId);
            assertTrue(Crypto.verify(SignUtils.asCanonicalString(sDomain.getDomain()), Crypto.loadPublicKey(publicKey), signature));
            DomainData ddata = sDomain.getDomain();
            assertTrue(ddata.getPolicies() != null);
            assertTrue(ddata.getRoles() != null && ddata.getRoles().size() > 0);
            assertTrue(ddata.getServices() != null);
        }

        // test bad tag format
        //
        String eTag  = new String("I am not good");
        String eTag2 = null;
        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        try {
            zms.getSignedDomains(mockDomRsrcCtx, null, null, eTag, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
            Object val = getWebAppExcMapValue(wexc, "ETag");
            eTag2 = val.toString();
        }

        assertNotNull(eTag2);
        assertNotEquals(eTag, eTag2);
        list = null;
        list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(list.size(), numDoms);

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
        }

        Policy policy1 = createPolicyObject("SignedDom1", "Policy1");
        zms.putPolicy(mockDomRsrcCtx, "SignedDom1", "Policy1", auditRef, policy1);

        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        sdoms  = null;
        eTag   = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, null, null, eTag2, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
            Object val = getWebAppExcMapValue(wexc, "ETag");
            eTag = val.toString();
        }

        assertNotNull(eTag);
        assertNotEquals(eTag, eTag2);
        list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(1, list.size());

        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        sdoms  = null;
        eTag2  = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, null, null, eTag, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            assertTrue(wexc.getResponse().getStatus() == 304);
            Object val = getWebAppExcMapValue(wexc, "ETag");
            eTag2 = val.toString();
        }
        assertNull(sdoms);

        assertNotNull(eTag2);
        assertEquals(eTag, eTag2);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "SignedDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "SignedDom2", auditRef);
    }
    
    @Test
    public void testGetSignedDomainsFiltered() {

        // create multiple top level domains
        TopLevelDomain dom1 = createTopLevelDomainObject("signeddom1filtered",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("signeddom2filtered",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        zms.privateKeyId = "0";
        zms.privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));

        GetSignedDomainsResult result = new GetSignedDomainsResult(mockDomRsrcCtx);
        SignedDomains sdoms = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, "signeddom1filtered", null, null, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
        }
        assertNotNull(sdoms);
        List<SignedDomain> list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(1, list.size());

        SignedDomain sDomain = list.get(0);
        String signature = sDomain.getSignature();
        String keyId = sDomain.getKeyId();
        String publicKey = zms.getPublicKey("sys.auth", "zms", keyId);
        assertTrue(Crypto.verify(SignUtils.asCanonicalString(sDomain.getDomain()), Crypto.loadPublicKey(publicKey), signature));
        assertEquals("signeddom1filtered", sDomain.getDomain().getName());

        // use domain=signeddom1filtered and metaonly=true
        //
        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        sdoms = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, "signeddom1filtered", "true", null, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
        }
        assertNotNull(sdoms);
        list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(1, list.size());

        sDomain = list.get(0);
        signature = sDomain.getSignature();
        assertTrue(signature == null || signature.isEmpty());
        keyId = sDomain.getKeyId();
        assertTrue(keyId == null || keyId.isEmpty());
        DomainData ddata = sDomain.getDomain();
        assertEquals("signeddom1filtered", ddata.getName());
        assertTrue(ddata.getModified() != null);
        assertTrue(ddata.getPolicies() == null);
        assertTrue(ddata.getRoles() == null);
        assertTrue(ddata.getServices() == null);

        // no changes, we should still get the same data back
        // we're going to pass the domain name with caps and
        // make sure we still get back our domain

        result = new GetSignedDomainsResult(mockDomRsrcCtx);
        sdoms = null;
        try {
            zms.getSignedDomains(mockDomRsrcCtx, "SignedDom1Filtered", null, null, result);
            fail("webappexc not thrown by getSignedDomains");
        } catch (javax.ws.rs.WebApplicationException wexc) {
            Object obj = getWebAppExcEntity(wexc);
            sdoms = (SignedDomains) obj;
        }
        assertNotNull(sdoms);
        list = null;
        list = sdoms.getDomains();
        assertNotNull(list);
        assertEquals(1, list.size());

        sDomain = list.get(0);
        signature = sDomain.getSignature();
        keyId = sDomain.getKeyId();
        publicKey = zms.getPublicKey("sys.auth", "zms", keyId);
        assertTrue(Crypto.verify(SignUtils.asCanonicalString(sDomain.getDomain()), Crypto.loadPublicKey(publicKey), signature));
        assertEquals("signeddom1filtered", sDomain.getDomain().getName());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "signeddom1filtered", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "signeddom2filtered", auditRef);
    }
    
    @Test
    public void testGetAccess() {

        TopLevelDomain dom1 = createTopLevelDomainObject("AccessDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("AccessDom1", "Role1", null, "user.user1",
                "user.user3");
        zms.putRole(mockDomRsrcCtx, "AccessDom1", "Role1", auditRef, role1);

        Role role2 = createRoleObject("AccessDom1", "Role2", null, "user.user2",
                "user.user3");
        zms.putRole(mockDomRsrcCtx, "AccessDom1", "Role2", auditRef, role2);

        Policy policy1 = createPolicyObject("AccessDom1", "Policy1", "Role1",
                "UPDATE", "AccessDom1:resource1", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "AccessDom1", "Policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject("AccessDom1", "Policy2", "Role2",
                "CREATE", "AccessDom1:resource2", AssertionEffect.DENY);
        zms.putPolicy(mockDomRsrcCtx, "AccessDom1", "Policy2", auditRef, policy2);

        Policy policy3 = createPolicyObject("AccessDom1", "Policy3", "Role2",
                "*", "AccessDom1:resource3", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "AccessDom1", "Policy3", auditRef, policy3);

        Policy policy4 = createPolicyObject("AccessDom1", "Policy4", "Role2",
                "DELETE", "accessdom1:*", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "AccessDom1", "Policy4", auditRef, policy4);

        Policy policy5 = createPolicyObject("AccessDom1", "Policy5", "Role1",
                "READ", "accessdom1:*", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "AccessDom1", "Policy5", auditRef, policy5);

        Policy policy6 = createPolicyObject("AccessDom1", "Policy6", "Role1",
                "READ", "AccessDom1:resource6", AssertionEffect.DENY);
        zms.putPolicy(mockDomRsrcCtx, "AccessDom1", "Policy6", auditRef, policy6);

        // user1 and user3 have access to UPDATE/resource1

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        Principal principal2 = principalAuthority.authenticate("v=U1;d=user;n=user2;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx2 = createResourceContext(principal2);
        Principal principal3 = principalAuthority.authenticate("v=U1;d=user;n=user3;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx3 = createResourceContext(principal3);

        Access access = zms.getAccess(rsrcCtx1, "UPDATE", "AccessDom1:resource1",
                "AccessDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "UPDATE", "AccessDom1:resource1",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "UPDATE", "AccessDom1:resource1",
                "AccessDom1", null);
        assertTrue(access.getGranted());

        // same set as before with no trust domain field

        access = zms.getAccess(rsrcCtx1, "UPDATE", "AccessDom1:resource1",
                null, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "UPDATE", "AccessDom1:resource1",
                null, null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "UPDATE", "AccessDom1:resource1",
                null, null);
        assertTrue(access.getGranted());

        // all three have no access to CREATE action on resource1

        access = zms.getAccess(rsrcCtx1, "CREATE", "AccessDom1:resource1",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "CREATE", "AccessDom1:resource1",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "CREATE", "AccessDom1:resource1",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        // all three have no access to invalid domain name on resource 1

        access = zms.getAccess(rsrcCtx1, "CREATE", "AccessDom1:resource1",
                "AccessDom2", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "CREATE", "AccessDom1:resource1",
                "AccessDom2", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "CREATE", "AccessDom1:resource1",
                "AccessDom2", null);
        assertFalse(access.getGranted());

        // same as before with no trust domain field

        access = zms.getAccess(rsrcCtx1, "CREATE", "AccessDom1:resource1",
                null, null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "CREATE", "AccessDom1:resource1",
                null, null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "CREATE", "AccessDom1:resource1",
                null, null);
        assertFalse(access.getGranted());

        // all three should have deny access to resource 2

        access = zms.getAccess(rsrcCtx1, "CREATE", "AccessDom1:resource2",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "CREATE", "AccessDom1:resource2",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "CREATE", "AccessDom1:resource2",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        // user2 and user3 have access to CREATE(*)/resource 3

        access = zms.getAccess(rsrcCtx1, "CREATE", "AccessDom1:resource3",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "CREATE", "AccessDom1:resource3",
                "AccessDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "CREATE", "AccessDom1:resource3",
                "AccessDom1", null);
        assertTrue(access.getGranted());

        // user2 and user3 have access to UPDATE(*)/resource 3

        access = zms.getAccess(rsrcCtx1, "UPDATE", "AccessDom1:resource3",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "UPDATE", "AccessDom1:resource3",
                "AccessDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "UPDATE", "AccessDom1:resource3",
                "AccessDom1", null);
        assertTrue(access.getGranted());

        // user2 and user3 have access to DELETE/resource 4 (*)

        access = zms.getAccess(rsrcCtx1, "DELETE", "AccessDom1:resource4",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "DELETE", "AccessDom1:resource4",
                "AccessDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "DELETE", "AccessDom1:resource4",
                "AccessDom1", null);
        assertTrue(access.getGranted());

        // user1 should be able to read resource 5(*) but not resource 6
        // (explicit DENY)

        access = zms.getAccess(rsrcCtx1, "READ", "AccessDom1:resource5",
                "AccessDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "READ", "AccessDom1:resource6",
                "AccessDom1", null);
        assertFalse(access.getGranted());

        // we should get an exception since access is not allowed to be called
        // with user cookie - this api is only for functions that require a 
        // service or user tokens
 
        try {
            zms.access("READ", "AccessDom1:resource5", principal1, "AccessDom1");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "AccessDom1", auditRef);
    }

    @Test
    public void testGetAccessWildcard() {

        final String domainName = "WildcardAccessDomain1";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, "Role1", null, "user.user1",
                "user.user3");
        zms.putRole(mockDomRsrcCtx, domainName, "Role1", auditRef, role1);

        Role role2 = createRoleObject(domainName, "Role2", null, "user.*",
                null);
        zms.putRole(mockDomRsrcCtx, domainName, "Role2", auditRef, role2);

        Role role3 = createRoleObject(domainName, "Role3", null, "*",
                null);
        zms.putRole(mockDomRsrcCtx, domainName, "Role3", auditRef, role3);
        
        Policy policy1 = createPolicyObject(domainName, "Policy1", "Role1",
                "UPDATE", domainName + ":resource1", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, domainName, "Policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject(domainName, "Policy2", "Role2",
                "CREATE", domainName + ":resource2", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, domainName, "Policy2", auditRef, policy2);

        Policy policy3 = createPolicyObject(domainName, "Policy3", "Role3",
                "DELETE", domainName + ":resource3", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, domainName, "Policy3", auditRef, policy3);

        // user1 and user3 have access to UPDATE/resource1

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        Principal principal2 = principalAuthority.authenticate("v=U1;d=user;n=user2;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx2 = createResourceContext(principal2);
        Principal principal3 = principalAuthority.authenticate("v=U1;d=user;n=user3;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx3 = createResourceContext(principal3);
        Principal principal4 = principalAuthority.authenticate("v=U1;d=user1;n=user4;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx4 = createResourceContext(principal4);
        
        Access access = zms.getAccess(rsrcCtx1, "UPDATE", domainName + ":resource1",
                domainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "UPDATE", domainName + ":resource1",
                domainName, null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "UPDATE", domainName + ":resource1",
                domainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx4, "UPDATE", domainName + ":resource1",
                domainName, null);
        assertFalse(access.getGranted());
        
        // all users have access to CREATE/resource2 but not user1 domain user

        access = zms.getAccess(rsrcCtx1, "CREATE", domainName + ":resource2",
                null, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "CREATE", domainName + ":resource2",
                null, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "CREATE", domainName + ":resource2",
                null, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx4, "CREATE", domainName + ":resource2",
                null, null);
        assertFalse(access.getGranted());
        
        // everyone has access to DELETE/resource3

        access = zms.getAccess(rsrcCtx1, "DELETE", domainName + ":resource3",
                domainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "DELETE", domainName + ":resource3",
                domainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "DELETE", domainName + ":resource3",
                domainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx4, "DELETE", domainName + ":resource3",
                domainName, null);
        assertTrue(access.getGranted());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetAccessCrossUser() {

        TopLevelDomain dom1 = createTopLevelDomainObject("CrossAllowDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("CrossAllowDom1", "Role1", null,
                "user.user1", "user.user3");
        zms.putRole(mockDomRsrcCtx, "CrossAllowDom1", "Role1", auditRef, role1);

        Role role2 = createRoleObject("CrossAllowDom1", "Role2", null,
                "user.user2", "user.user3");
        zms.putRole(mockDomRsrcCtx, "CrossAllowDom1", "Role2", auditRef, role2);

        Role role3 = createRoleObject("CrossAllowDom1", "Role3", null,
                "user.user1", null);
        zms.putRole(mockDomRsrcCtx, "CrossAllowDom1", "Role3", auditRef, role3);

        Policy policy1 = createPolicyObject("CrossAllowDom1", "Policy1",
                "Role1", "UPDATE", "CrossAllowDom1:resource1",
                AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "CrossAllowDom1", "Policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject("CrossAllowDom1", "Policy2",
                "Role2", "CREATE", "CrossAllowDom1:resource2",
                AssertionEffect.DENY);
        zms.putPolicy(mockDomRsrcCtx, "CrossAllowDom1", "Policy2", auditRef, policy2);

        Policy policy3 = createPolicyObject("CrossAllowDom1", "Policy3",
                "Role2", "*", "CrossAllowDom1:resource3", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "CrossAllowDom1", "Policy3", auditRef, policy3);

        Policy policy4 = createPolicyObject("CrossAllowDom1", "Policy4",
                "Role2", "DELETE", "CrossAllowDom1:*", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "CrossAllowDom1", "Policy4", auditRef, policy4);

        // verify we have allow access for access resource

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        Principal principal2 = principalAuthority.authenticate("v=U1;d=user;n=user2;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx2 = createResourceContext(principal2);
        Principal principal3 = principalAuthority.authenticate("v=U1;d=user;n=user3;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx3 = createResourceContext(principal3);

        // user1 and user3 have access to UPDATE/resource1

        Access access = zms.getAccess(rsrcCtx1, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user1");
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user.user1");
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user2");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user.user2");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user3");
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user.user3");
        assertTrue(access.getGranted());

        // all three have no access to CREATE action on resource1

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user1");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user.user1");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user2");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user.user2");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user3");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user.user3");
        assertFalse(access.getGranted());

        // all three have no access to invalid domain name on resource 1

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom2", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom2", "user1");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom2", "user.user1");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "CREATE", "CrossAllowDom1:resource1",
                "CrossAllowDom2", null);
        assertFalse(access.getGranted());

        // user2 and user3 have access to CREATE(*)/resource 3

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource3",
                "CrossAllowDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource3",
                "CrossAllowDom1", "user1");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource3",
                "CrossAllowDom1", "user.user1");
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "CREATE", "CrossAllowDom1:resource3",
                "CrossAllowDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource3",
                "CrossAllowDom1", "user2");
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource3",
                "CrossAllowDom1", "user.user2");
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "CREATE", "CrossAllowDom1:resource3",
                "CrossAllowDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource3",
                "CrossAllowDom1", "user3");
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx1, "CREATE", "CrossAllowDom1:resource3",
                "CrossAllowDom1", "user.user3");
        assertTrue(access.getGranted());

        // user2 and user3 are allowed to check each other's access

        access = zms.getAccess(rsrcCtx2, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user1");
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx2, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user.user1");
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user1");
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtx3, "UPDATE", "CrossAllowDom1:resource1",
                "CrossAllowDom1", "user.user1");
        assertTrue(access.getGranted());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "CrossAllowDom1", auditRef);
    }

    @Test
    public void testGetAccessHomeDomainEnabled() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN, "true");
        ZMSImpl zmsTest = zmsInit();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();

        Principal pJane = principalAuthority.authenticate("v=U1;d=user;n=jane;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtxJane = createResourceContext(pJane);
        
        Access access = zmsTest.getAccess(rsrcCtxJane, "READ", "user.jane:Resource1", null, null);
        assertTrue(access.getGranted());
        
        access = zmsTest.getAccess(rsrcCtxJane, "WRITE", "user.jane:Resource1", null, null);
        assertTrue(access.getGranted());

        access = zmsTest.getAccess(rsrcCtxJane, "UPDATE", "user.jane:Resource1", null, null);
        assertTrue(access.getGranted());

        // user id does not match domain - all should be failure
        
        Principal pJohn = principalAuthority.authenticate("v=U1;d=user;n=john;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtxJohn = createResourceContext(pJohn);
        
        try {
            zmsTest.getAccess(rsrcCtxJohn, "READ", "user.jane:Resource1", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zmsTest.getAccess(rsrcCtxJohn, "WRITE", "user.jane:Resource1", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }

        try {
            zmsTest.getAccess(rsrcCtxJohn, "UPDATE", "user.jane:Resource1", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN);
    }

    @Test
    public void testGetAccessHomeDomainDisabled() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN, "false");
        ZMSImpl zmsTest = zmsInit();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();

        Principal pJane = principalAuthority.authenticate("v=U1;d=user;n=jane;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtxJane = createResourceContext(pJane);

        try {
            zmsTest.getAccess(rsrcCtxJane, "READ", "user.jane:Resource1", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zmsTest.getAccess(rsrcCtxJane, "WRITE", "user.jane:Resource1", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zmsTest.getAccess(rsrcCtxJane, "UPDATE", "user.jane:Resource1", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN);
    }

    @Test
    public void testRetrieveAccessDomainValid() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("AccessDomain",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal pJane = principalAuthority.authenticate("v=U1;d=user;n=jane;s=signature",
                "10.11.12.13", "GET", null);
        
        AthenzDomain athenzDomain = zms.retrieveAccessDomain("accessdomain", pJane);
        assertNotNull(athenzDomain);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "AccessDomain", auditRef);
    }

    @Test
    public void testRetrieveAccessDomainVirtualValid() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN, "true");
        ZMSImpl zmsTest = zmsInit();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        
        AthenzDomain athenzDomain = zmsTest.retrieveAccessDomain("user.user1", principal);
        assertNotNull(athenzDomain);
        assertEquals(athenzDomain.getName(), "user.user1");
        
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN);
    }

    @Test
    public void testRetrieveAccessDomainVirtualDomainDisabled() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN, "false");
        ZMSImpl zmsTest = zmsInit();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        
        AthenzDomain athenzDomain = zmsTest.retrieveAccessDomain("user.user1", principal);
        assertNull(athenzDomain);
        
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN);
    }

    @Test
    public void testRetrieveAccessDomainPrincialNullDomain() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN, "true");
        ZMSImpl zmsTest = zmsInit();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create(null, "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        
        AthenzDomain athenzDomain = zmsTest.retrieveAccessDomain("user.user1", principal);
        assertNull(athenzDomain);
        
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN);
        
    }

    @Test
    public void testRetrieveAccessDomainMismatch() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN, "true");
        ZMSImpl zmsTest = zmsInit();

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "user2", "v=U1;d=user;n=user2;s=signature",
                0, principalAuthority);
        
        AthenzDomain athenzDomain = zmsTest.retrieveAccessDomain("user.user1", principal);
        assertNull(athenzDomain);
        
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN);
    }
    
    @Test
    public void testGetAccessCrossDomain() {

        setupTenantDomainProviderService("CrossDomainAccessDom1", "coretech", "storage",
                "http://localhost:8090/provider");

        Tenancy tenant = createTenantObject("CrossDomainAccessDom1", "coretech.storage");
        ProviderMockClient.setReturnTenantRoles(true);
        zms.putTenancy(mockDomRsrcCtx, "CrossDomainAccessDom1", "coretech.storage", auditRef, tenant);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction((String) f.value()));
        }
        TenantRoles tenantRoles = new TenantRoles().setDomain("coretech")
                .setService("storage").setTenant("CrossDomainAccessDom1")
                .setRoles(roleActions);

        zms.putTenantRoles(mockDomRsrcCtx, "coretech", "storage", "CrossDomainAccessDom1",
                auditRef, tenantRoles);

        Tenancy tenant1 = zms.getTenancy(mockDomRsrcCtx, "CrossDomainAccessDom1", "coretech.storage");
        assertNotNull(tenant1);

        // reset roles in the CrossDomainAccessDom1 domain with unique values

        Role role = createRoleObject("CrossDomainAccessDom1", "reader", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, "CrossDomainAccessDom1", "reader", auditRef, role);

        role = createRoleObject("CrossDomainAccessDom1", "writer", null, "user.john",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, "CrossDomainAccessDom1", "writer", auditRef, role);

        Policy policy = createPolicyObject("CrossDomainAccessDom1", "tenancy.coretech.storage.writer",
                "writer", "ASSUME_ROLE", "coretech:role.storage.tenant.CrossDomainAccessDom1.writer",
                AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "CrossDomainAccessDom1", "tenancy.coretech.storage.writer",
                auditRef, policy);

        policy = createPolicyObject("CrossDomainAccessDom1", "tenancy.coretech.storage.reader",
                "reader", "ASSUME_ROLE", "coretech:role.storage.tenant.CrossDomainAccessDom1.reader",
                AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "CrossDomainAccessDom1", "tenancy.coretech.storage.reader",
                auditRef, policy);

        // verify the ASSUME_ROLE check - with trust domain specified it should work and
        // without trust domain it will not work since the resource is pointing to the
        // provider's domain and not to the tenant's domain
        
        Access access = zms.getAccess(mockDomRsrcCtx, "ASSUME_ROLE", "coretech:role.storage.tenant.CrossDomainAccessDom1.reader",
                null, "user.jane");
        assertFalse(access.getGranted());
        
        access = zms.getAccess(mockDomRsrcCtx, "ASSUME_ROLE", "coretech:role.storage.tenant.CrossDomainAccessDom1.reader",
                "CrossDomainAccessDom1", "user.jane");
        assertTrue(access.getGranted());
        
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();

        Principal pJane = principalAuthority.authenticate("v=U1;d=user;n=jane;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtxJane = createResourceContext(pJane);
        Principal pJohn = principalAuthority.authenticate("v=U1;d=user;n=john;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtxJohn = createResourceContext(pJohn);
        Principal pJoe = principalAuthority.authenticate("v=U1;d=user;n=joe;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtxJoe = createResourceContext(pJoe);

        access = zms.getAccess(rsrcCtxJoe, "READ",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtxJane, "READ",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtxJohn, "READ",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtxJoe, "WRITE",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtxJane, "WRITE",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom1", null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtxJohn, "WRITE",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom1", null);
        assertTrue(access.getGranted());

        // unknown action should always fail

        access = zms.getAccess(rsrcCtxJoe, "UPDATE",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtxJane, "UPDATE",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom1", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtxJohn, "UPDATE",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom1", null);
        assertFalse(access.getGranted());

        // same set as above without trust domain field

        access = zms.getAccess(rsrcCtxJoe, "READ",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                null, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtxJane, "READ",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                null, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtxJohn, "READ",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                null, null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtxJoe, "WRITE",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                null, null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtxJane, "WRITE",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                null, null);
        assertTrue(access.getGranted());

        access = zms.getAccess(rsrcCtxJohn, "WRITE",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                null, null);
        assertTrue(access.getGranted());

        // failure with different domain name

        access = zms.getAccess(rsrcCtxJoe, "READ",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom2", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtxJane, "READ",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom2", null);
        assertFalse(access.getGranted());

        access = zms.getAccess(rsrcCtxJohn, "READ",
                "coretech:service.storage.tenant.CrossDomainAccessDom1.resource1",
                "CrossDomainAccessDom2", null);
        assertFalse(access.getGranted());

        zms.deleteTenancy(mockDomRsrcCtx, "CrossDomainAccessDom1", "coretech.storage", auditRef);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "CrossDomainAccessDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
    }

    @Test
    public void testGetAccessCrossDomainWildCardResources() {

        // create the netops domain
        
        TopLevelDomain dom = createTopLevelDomainObject("netops",
                "Test Netops", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        Role role = createRoleObject("netops", "users", null, null, null);
        zms.putRole(mockDomRsrcCtx, "netops", "users", auditRef, role);
        
        role = createRoleObject("netops", "superusers", null, "user.siteops_user_1",
                "user.siteops_user_2");
        zms.putRole(mockDomRsrcCtx, "netops", "superusers", auditRef, role);
        
        Policy policy = createPolicyObject("netops", "users",
                "users", "NODE_USER", "netops:node.",
                AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "netops", "users", auditRef, policy);

        policy = createPolicyObject("netops", "superusers",
                "superusers", "NODE_SUDO", "netops:node.",
                AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "netops", "superusers", auditRef, policy);

        policy = createPolicyObject("netops", "netops_superusers",
                "netops:role.superusers", false, "ASSUME_ROLE", "*:role.netops_superusers",
                AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "netops", "netops_superusers", auditRef, policy);

        // create the weather domain
        
        dom = createTopLevelDomainObject("weather",
                "Test weather", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        role = createRoleObject("weather", "users", null, null, null);
        zms.putRole(mockDomRsrcCtx, "weather", "users", auditRef, role);
        
        role = createRoleObject("weather", "superusers", null, "user.weather_admin_user",
                null);
        zms.putRole(mockDomRsrcCtx, "weather", "superusers", auditRef, role);

        role = createRoleObject("weather", "netops_superusers", "netops");
        zms.putRole(mockDomRsrcCtx, "weather", "netops_superusers", auditRef, role);
        
        policy = createPolicyObject("weather", "users",
                "users", "NODE_USER", "weather:node.",
                AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "weather", "users", auditRef, policy);

        policy = createPolicyObject("weather", "superusers",
                "superusers", "NODE_SUDO", "weather:node.*",
                AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "weather", "superusers", auditRef, policy);

        policy = createPolicyObject("weather", "netops_superusers",
                "netops_superusers", "NODE_SUDO", "weather:node.*",
                AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "weather", "netops_superusers", auditRef, policy);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();

        Principal pWeather = principalAuthority.authenticate("v=U1;d=user;n=weather_admin_user;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtxWeather = createResourceContext(pWeather);

        Access access = zms.getAccess(rsrcCtxWeather, "NODE_SUDO", "weather:node.x", null, null);
        assertTrue(access.getGranted());
        
        Principal pSiteOps = principalAuthority.authenticate("v=U1;d=user;n=siteops_user_1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtxSiteOps = createResourceContext(pSiteOps);

        access = zms.getAccess(rsrcCtxSiteOps, "NODE_SUDO", "weather:node.x", null, null);
        assertTrue(access.getGranted());
        
        Principal pRandom = principalAuthority.authenticate("v=U1;d=user;n=random_user;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtxRandom = createResourceContext(pRandom);

        access = zms.getAccess(rsrcCtxRandom, "NODE_SUDO", "weather:node.x", null, null);
        assertFalse(access.getGranted());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "weather", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "netops", auditRef);
    }

    @Test
    public void testGetAccessExt() {

        final String testDomainName = "AccessDomExt1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(testDomainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(testDomainName, "Role1", null, "user.user1",
                "user.user3");
        zms.putRole(mockDomRsrcCtx, testDomainName, "Role1", auditRef, role1);

        Role role2 = createRoleObject(testDomainName, "Role2", null, "user.user2",
                "user.user3");
        zms.putRole(mockDomRsrcCtx, testDomainName, "Role2", auditRef, role2);

        Policy policy1 = createPolicyObject(testDomainName, "Policy1", "Role1",
                "UPDATE", testDomainName + ":resource1/resource2", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, testDomainName, "Policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject(testDomainName, "Policy2", "Role2",
                "CREATE", testDomainName + ":resource2(resource3)", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, testDomainName, "Policy2", auditRef, policy2);

        Policy policy3 = createPolicyObject(testDomainName, "Policy3", "Role2",
                "*", testDomainName + ":resource3/*", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, testDomainName, "Policy3", auditRef, policy3);

        Policy policy4 = createPolicyObject(testDomainName, "Policy4", "Role1",
                "READ", testDomainName + ":resource4[*]/data1", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, testDomainName, "Policy4", auditRef, policy4);

        Policy policy5 = createPolicyObject(testDomainName, "Policy5", "Role2",
                "access", testDomainName + ":https://*.athenz.com/*", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, testDomainName, "Policy5", auditRef, policy5);
        
        // user1 and user3 have access to UPDATE/resource1

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        Principal principal2 = principalAuthority.authenticate("v=U1;d=user;n=user2;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx2 = createResourceContext(principal2);
        Principal principal3 = principalAuthority.authenticate("v=U1;d=user;n=user3;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx3 = createResourceContext(principal3);

        // user1 and user3 have update access to resource1/resource2
        
        Access access = zms.getAccessExt(rsrcCtx1, "UPDATE", testDomainName + ":resource1/resource2",
                testDomainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccessExt(rsrcCtx1, "UPDATE", testDomainName + ":resource1/resource3",
                testDomainName, null);
        assertFalse(access.getGranted());
        
        access = zms.getAccessExt(rsrcCtx2, "UPDATE", testDomainName + ":resource1/resource2",
                testDomainName, null);
        assertFalse(access.getGranted());

        access = zms.getAccessExt(rsrcCtx3, "UPDATE", testDomainName + ":resource1/resource2",
                testDomainName, null);
        assertTrue(access.getGranted());

        // all three have no access to CREATE action on resource1/resource2

        access = zms.getAccessExt(rsrcCtx1, "CREATE", testDomainName + ":resource1/resource2",
                testDomainName, null);
        assertFalse(access.getGranted());

        access = zms.getAccessExt(rsrcCtx2, "CREATE", testDomainName + ":resource1/resource2",
                testDomainName, null);
        assertFalse(access.getGranted());

        access = zms.getAccessExt(rsrcCtx3, "CREATE", testDomainName + ":resource1/resource2",
                testDomainName, null);
        assertFalse(access.getGranted());

        // user2 and user3 have create access to resource2(resource3)
        
        access = zms.getAccessExt(rsrcCtx1, "CREATE", testDomainName + ":resource2(resource3)",
                testDomainName, null);
        assertFalse(access.getGranted());

        access = zms.getAccessExt(rsrcCtx2, "CREATE", testDomainName + ":resource2(resource3)",
                testDomainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccessExt(rsrcCtx3, "CREATE", testDomainName + ":resource2(resource3)",
                testDomainName, null);
        assertTrue(access.getGranted());

        // user2 and user3 have access to CREATE(*)/resource3/*

        access = zms.getAccessExt(rsrcCtx1, "CREATE", testDomainName + ":resource3",
                testDomainName, null);
        assertFalse(access.getGranted());

        access = zms.getAccessExt(rsrcCtx2, "CREATE", testDomainName + ":resource3/test1",
                testDomainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccessExt(rsrcCtx3, "CREATE", testDomainName + ":resource3/anothertest",
                testDomainName, null);
        assertTrue(access.getGranted());

        // user2 and user3 have access to UPDATE(*)/resource3/*

        access = zms.getAccessExt(rsrcCtx1, "UPDATE", testDomainName + ":resource3",
                testDomainName, null);
        assertFalse(access.getGranted());

        access = zms.getAccessExt(rsrcCtx2, "UPDATE", testDomainName + ":resource3/(another value)",
                testDomainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccessExt(rsrcCtx3, "UPDATE", testDomainName + ":resource3/a",
                testDomainName, null);
        assertTrue(access.getGranted());

        // user1 and user3 have access to READ/resource6[*]/data1

        access = zms.getAccessExt(rsrcCtx1, "read", testDomainName + ":resource4[test1]/data1",
                testDomainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccessExt(rsrcCtx2, "read", testDomainName + ":resource4[test1]/data1",
                testDomainName, null);
        assertFalse(access.getGranted());

        access = zms.getAccessExt(rsrcCtx3, "read", testDomainName + ":resource4[test another]/data1",
                testDomainName, null);
        assertTrue(access.getGranted());

        // user2 and user3 have access to access/https://*.athenz.com/*

        access = zms.getAccessExt(rsrcCtx1, "access", testDomainName + ":https://web.athenz.com/data",
                testDomainName, null);
        assertFalse(access.getGranted());

        access = zms.getAccessExt(rsrcCtx2, "access", testDomainName + ":https://web.athenz.com/data",
                testDomainName, null);
        assertTrue(access.getGranted());

        access = zms.getAccessExt(rsrcCtx2, "access", testDomainName + ":https://web.athenz.org/data",
                testDomainName, null);
        assertFalse(access.getGranted());
        
        access = zms.getAccessExt(rsrcCtx3, "access", testDomainName + ":https://web-store.athenz.com/data/path",
                testDomainName, null);
        assertTrue(access.getGranted());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, testDomainName, auditRef);
    }
    
    @Test
    public void testValidateEntity() {
        int code = 400;
        String en = new String("entityOne");
        Entity entity = new Entity();
        String nonmatchName = new String("entityTwo");
        
        // tests the condition: if (!en.equals(entity.getName()))...
        try {
            entity.setName(nonmatchName);
            
            zms.validateEntity(en, entity);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), code);
        }
        
        // tests the condition: if (entity.getValue() == null)...
        try {
            entity.setName(en);
            
            zms.validateEntity(en, entity);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), code);
        }
    }
    
    @Test
    public void testValidateDomainTemplate() {
        DomainTemplate domainTemplate = new DomainTemplate();
        List<String> names = new ArrayList<>();
        names.add("vipng");
        domainTemplate.setTemplateNames(names);
        
        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("param_name_valid").setValue("param_value_valid"));
        domainTemplate.setParams(params);
        
        // our validation should be successful
        
        zms.validate(domainTemplate, "DomainTemplate", "testValidateDomainTemplate");
        
        // now let's add an invalid entry
        
        params.add(new TemplateParam().setName("param_name_invalid.test").setValue("param_value_valid"));
        try {
            zms.validate(domainTemplate, "DomainTemplate", "testValidateDomainTemplate");
            fail();
        } catch (ResourceException ex) {
        }

        // remove the second element and add another with invalid value
        
        params.remove(1);
        params.add(new TemplateParam().setName("param_name_valid").setValue("param_value_invalid(again)"));
        try {
            zms.validate(domainTemplate, "DomainTemplate", "testValidateDomainTemplate");
            fail();
        } catch (ResourceException ex) {
        }
    }
    
    @Test
    public void testValidateRole() {
        Role role = new Role();
        role.setName("athenz:role.role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        role.setRoleMembers(roleMembers);
        
        // first validation should be successful
        
        zms.validate(role, "Role", "testValidateRole");
        
        // now let's add invalid entry
        
        roleMembers.add(new RoleMember().setMemberName("user joe"));
        try {
            zms.validate(role, "Role", "testValidateRole");
            fail();
        } catch (ResourceException ex) {
        }
    }
    
    @Test
    public void testCheckReservedEntityName() {
        int code = 400;
        String reserved = new String("meta");
        try {
            zms.checkReservedEntityName(reserved);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), code);
        }
    }
    
    @Test
    public void testPutEntity() {
        int code = 404;
        String name = new String("entityOne");
        try {
            Entity entity = createEntityObject(name);
            
            // entityName will not match entity.name.
            zms.putEntity(mockDomRsrcCtx, "wrongDomainName", name, auditRef, entity);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), code);
        }
    }
    
    @Test
    public void testGetPublicKeyZMS() {
        
        String publicKey = zms.getPublicKey("sys.auth", "zms", "0");
        assertNotNull(publicKey);
        try {
            assertTrue(pubKey.equals(Crypto.ybase64(publicKey.getBytes("UTF-8"))));
        } catch (UnsupportedEncodingException e) {
            fail();
        }
        
        publicKey = zms.getPublicKey("sys.auth", "zms", "1");
        assertNotNull(publicKey);
        try {
            assertTrue(pubKeyK1.equals(Crypto.ybase64(publicKey.getBytes("UTF-8"))));
        } catch (UnsupportedEncodingException e) {
            fail();
        }
        
        publicKey = zms.getPublicKey("sys.auth", "zms", "2");
        assertNotNull(publicKey);
        try {
            assertTrue(pubKeyK2.equals(Crypto.ybase64(publicKey.getBytes("UTF-8"))));
        } catch (UnsupportedEncodingException e) {
            fail();
        }
    }
    
    @Test
    public void testGetPublicKeyInvalidService() {

        String pubKey = zms.getPublicKey("sys.auth", "sys.auth", "0");
        assertNull(pubKey);
    }

    @Test
    public void testGetPublicKeyService() {

        TopLevelDomain dom1 = createTopLevelDomainObject("GetPublicKeyDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("GetPublicKeyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "GetPublicKeyDom1", "Service1", auditRef, service);

        String publicKey = zms.getPublicKey("GetPublicKeyDom1", "Service1", "0");
        assertNull(publicKey);

        assertNull(zms.getPublicKey("GetPublicKeyDom1", null, "0"));
        assertNull(zms.getPublicKey("GetPublicKeyDom1", "Service1", null));
        
        publicKey = zms.getPublicKey("GetPublicKeyDom1", "Service1", "1");
        assertNotNull(publicKey);
        assertTrue(publicKey.equals(Crypto.ybase64DecodeString(pubKeyK1)));

        publicKey = zms.getPublicKey("GetPublicKeyDom1", "Service1", "2");
        assertNotNull(publicKey);
        assertTrue(publicKey.equals(Crypto.ybase64DecodeString(pubKeyK2)));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "GetPublicKeyDom1", auditRef);
    }
    
    @Test
    public void testPutTenancy() {

        setupTenantDomainProviderService("AddTenancyDom1", "coretech", "storage",
                "http://localhost:8090/provider");

        Tenancy tenant = createTenantObject("AddTenancyDom1", "coretech.storage");
        ProviderMockClient.setReturnTenantRoles(true);
        zms.putTenancy(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage", auditRef, tenant);
        
        // make sure our roles have been created
        
        Role role = zms.getRole(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage.admin", false, false);
        assertNotNull(role);
        
        role = zms.getRole(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage.reader", false, false);
        assertNotNull(role);
        
        role = zms.getRole(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage.writer", false, false);
        assertNotNull(role);
        
        // verify the policies have the correct roles
        
        Policy policy = zms.getPolicy(mockDomRsrcCtx, "AddTenancyDom1", "tenancy.coretech.storage.admin");
        assertNotNull(policy);

        // the admin is a special case where we are going to create the policy
        // before we call the provider's tenant controller service so we'll
        // end up with 4 assertions
        
        List<Assertion> assertList = policy.getAssertions();
        assertEquals(4, assertList.size());
        
        boolean domainAdminRoleCheck = false;
        boolean tenantAdminRoleCheck = false;
        boolean resourceAdminRoleCheck = false;
        boolean tenantUpdateCheck = false;
        for (Assertion obj : assertList) {
            assertEquals(AssertionEffect.ALLOW, obj.getEffect());
            if (obj.getRole().equals("addtenancydom1:role.admin")) {
                assertEquals(obj.getAction(), "assume_role");
                domainAdminRoleCheck = true;
            } else if (obj.getRole().equals("addtenancydom1:role.tenancy.coretech.storage.admin")) {
                if (obj.getAction().equals("assume_role")) {
                    tenantAdminRoleCheck = true;
                } else if (obj.getAction().equals("update")) {
                    tenantUpdateCheck = true;
                }
            } else if (obj.getRole().equals("addtenancydom1:role.coretech.storage.admin")) {
                assertEquals(obj.getAction(), "assume_role");
                resourceAdminRoleCheck = true;
            }
        }
        assertTrue(domainAdminRoleCheck);
        assertTrue(tenantAdminRoleCheck);
        assertTrue(resourceAdminRoleCheck);
        assertTrue(tenantUpdateCheck);

        policy = zms.getPolicy(mockDomRsrcCtx, "AddTenancyDom1", "tenancy.coretech.storage.reader");
        assertNotNull(policy);

        assertList = policy.getAssertions();
        assertEquals(assertList.size(), 1);
        assertEquals(assertList.get(0).getRole(), "addtenancydom1:role.coretech.storage.reader");
        
        policy = zms.getPolicy(mockDomRsrcCtx, "AddTenancyDom1", "tenancy.coretech.storage.writer");
        assertNotNull(policy);

        assertList = policy.getAssertions();
        assertEquals(assertList.size(), 1);
        assertEquals(assertList.get(0).getRole(), "addtenancydom1:role.coretech.storage.writer");
        
        // now add the tenant roles for our domain since our mock provider client
        // cannot connect to our zms instance
        
        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        TenantRoles tenantRoles = new TenantRoles().setDomain("coretech")
                .setService("storage").setTenant("AddTenancyDom1")
                .setRoles(roleActions);

        zms.putTenantRoles(mockDomRsrcCtx, "coretech", "storage", "AddTenancyDom1",
                auditRef, tenantRoles);
        
        Tenancy tenant1 = zms.getTenancy(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage");
        assertNotNull(tenant1);

        zms.deleteTenancy(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage", auditRef);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "AddTenancyDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
    }

    @Test
    public void testPutTenancyWithAuthorizedService() {

        String tenantDomain = "puttenancyauthorizedservice";
        String providerService  = "storage";
        String providerDomain = "coretech";
        String provider = providerDomain + "." + providerService;
        
        setupTenantDomainProviderService(tenantDomain, providerDomain, providerService, null);
        
        // tenant is setup so let's setup up policy to authorize access to tenants
        // without this role/policy we won't be authorized to add tenant roles
        // to the provider domain even with authorized service details
        
        Role role = createRoleObject(providerDomain, "self_serve", null,
                providerDomain + "." + providerService, null);
        zms.putRole(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, role);
        
        Policy policy = createPolicyObject(providerDomain, "self_serve",
                "self_serve", "update", providerDomain + ":tenant.*", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, policy);
        
        // we are going to create a principal object with authorized service
        // set to coretech.storage
        
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String userId = "user1";
        String unsignedCreds = "v=U1;d=user;u=" + userId;
        Principal principal = SimplePrincipal.create("user", userId, unsignedCreds + ";s=signature", 0, principalAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);
        ((SimplePrincipal) principal).setAuthorizedService(provider);
        ResourceContext ctx = createResourceContext(principal);
        
        // after this call we should have admin roles set for both provider and tenant
        
        Tenancy tenant = createTenantObject(tenantDomain, provider);
        zms.putTenancy(ctx, tenantDomain, provider, auditRef, tenant);

        // make sure our policy has been created
        
        policy = zms.getPolicy(mockDomRsrcCtx, tenantDomain, "tenancy." + provider + ".admin");
        assertNotNull(policy);
        
        String tenantRoleInProviderDomain = providerService + ".tenant." + tenantDomain + ".admin";
        
        List<Assertion> assertList = policy.getAssertions();
        assertEquals(3, assertList.size());
        boolean domainAdminRoleCheck = false;
        boolean tenantAdminRoleCheck = false;
        boolean tenantUpdateCheck = false;
        for (Assertion obj : assertList) {
            assertEquals(AssertionEffect.ALLOW, obj.getEffect());
            if (obj.getRole().equals(tenantDomain + ":role.admin")) {
                assertEquals("assume_role", obj.getAction());
                assertEquals("coretech:role.storage.tenant.puttenancyauthorizedservice.admin", obj.getResource());
                domainAdminRoleCheck = true;
            } else if (obj.getRole().equals(tenantDomain + ":role.tenancy." + provider + ".admin")) {
                if (obj.getAction().equals("assume_role")) {
                    assertEquals("coretech:role.storage.tenant.puttenancyauthorizedservice.admin", obj.getResource());
                    tenantAdminRoleCheck = true;
                } else if (obj.getAction().equals("update")) {
                    assertEquals(tenantDomain + ":tenancy." + provider, obj.getResource());
                    tenantUpdateCheck = true;
                }
            }
        }
        assertTrue(domainAdminRoleCheck);
        assertTrue(tenantAdminRoleCheck);
        assertTrue(tenantUpdateCheck);
        
        // now let's verify the provider side by using the get tenant roles call
        
        TenantRoles tRoles = zms.getTenantRoles(mockDomRsrcCtx, providerDomain, providerService, tenantDomain);
        assertNotNull(tRoles);
        assertEquals(1, tRoles.getRoles().size());
        TenantRoleAction roleAction = tRoles.getRoles().get(0);
        assertEquals("*", roleAction.getAction());
        assertEquals("admin", roleAction.getRole());
        
        role = zms.getRole(mockDomRsrcCtx, providerDomain, tenantRoleInProviderDomain, false, false);
        assertNotNull(role);
            
        // now let's call delete tenancy support with the same authorized service token
        
        zms.deleteTenancy(ctx, tenantDomain,  provider, auditRef);

        // verify that all roles and policies have been deleted
        
        try {
            zms.getPolicy(mockDomRsrcCtx, tenantDomain, "tenancy." + provider + ".admin");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        try {
            zms.getRole(mockDomRsrcCtx, providerDomain, tenantRoleInProviderDomain, false, false);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        // get tenant roles now returns an empty set
        
        tRoles = zms.getTenantRoles(mockDomRsrcCtx, providerDomain, providerService, tenantDomain);
        assertNotNull(tRoles);
        assertEquals(0, tRoles.getRoles().size());
        
        // clean up our domains
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
    }
    
    @Test
    public void testPutTenancyWithAuthorizedServiceMismatch() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_puttenancywithauthsvcmism";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String tenantDomain = "puttenancyauthorizedservicemismatch";
        String providerService  = "storage";
        String providerDomain = "coretech-test";
        String provider = providerDomain + "." + providerService;
        
        setupTenantDomainProviderService(zmsImpl, tenantDomain, providerDomain, providerService, null);
        
        // tenant is setup so let's setup up policy to authorize access to tenants
        // without this role/policy we won't be authorized to add tenant roles
        // to the provider domain even with authorized service details
        
        Role role = createRoleObject(providerDomain, "self_serve", null,
                providerDomain + "." + providerService, null);
        zmsImpl.putRole(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, role);
        
        Policy policy = createPolicyObject(providerDomain, "self_serve",
                "self_serve", "update", providerDomain + ":tenant.*", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, policy);
        
        // we are going to create a principal object with authorized service
        // set to coretech.storage
        
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String userId = "user1";
        String unsignedCreds = "v=U1;d=user;u=" + userId;
        Principal principal = SimplePrincipal.create("user", userId, unsignedCreds + ";s=signature", 0, principalAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);
        ((SimplePrincipal) principal).setAuthorizedService("coretech.storage"); // make provider mismatch
        ResourceContext ctx = createResourceContext(principal);
        
        // this should fail since the authorized service name does not
        // match to the provider and there is no endpoint specified for the provider
        
        Tenancy tenant = createTenantObject(tenantDomain, provider);
        try {
            zmsImpl.putTenancy(ctx, tenantDomain, provider, auditRef, tenant);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        // clean up our domains
        
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testPutTenancyWithoutTenantRoles() {

        setupTenantDomainProviderService("AddTenancyDom1", "coretech", "storage",
                "http://localhost:8090/provider");

        Tenancy tenant = createTenantObject("AddTenancyDom1", "coretech.storage");
        ProviderMockClient.setReturnTenantRoles(false);
        zms.putTenancy(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage", auditRef, tenant);
        
        // make sure our roles have not been created
        
        try {
            zms.getRole(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage.admin", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getRole(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage.reader", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getRole(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage.writer", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        // verify the admin policy has been successfully created
        
        Policy policy = zms.getPolicy(mockDomRsrcCtx, "AddTenancyDom1", "tenancy.coretech.storage.admin");
        assertNotNull(policy);

        // we should not have other policies for actions
        
        try {
            zms.getPolicy(mockDomRsrcCtx, "AddTenancyDom1", "tenancy.coretech.storage.reader");
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getPolicy(mockDomRsrcCtx, "AddTenancyDom1", "tenancy.coretech.storage.writer");
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        zms.deleteTenancy(mockDomRsrcCtx, "AddTenancyDom1", "coretech.storage", auditRef);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "AddTenancyDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
    }
    
    @Test
    public void testPutTenancyResourceGroup() {

        String domain = "addtenancyresourcegroupdom1";
        
        setupTenantDomainProviderService(domain, "coretech", "storage",
                "http://localhost:8090/provider");

        Tenancy tenant = createTenantObject(domain, "coretech.storage");
        ProviderMockClient.setReturnTenantRoles(false);
        zms.putTenancy(mockDomRsrcCtx, domain, "coretech.storage", auditRef, tenant);
        
        // make sure our roles have not been created
        
        try {
            zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.admin", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.reader", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.writer", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        // verify the admin policy has been successfully created
        
        Policy policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.admin");
        assertNotNull(policy);

        // we should not have other policies for actions
        
        try {
            zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.reader");
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.writer");
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        // now let's put a resource group
        
        TenancyResourceGroup detail = new TenancyResourceGroup();
        detail.setDomain(domain).setService("coretech.storage").setResourceGroup("hockey");
        zms.putTenancyResourceGroup(mockDomRsrcCtx, domain, "coretech.storage", "hockey", auditRef, detail);
        
        // now verify that roles were created successfully
        
        Role role = zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.hockey.reader", false, false);
        assertNotNull(role);
        
        role = zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.hockey.writer", false, false);
        assertNotNull(role);
        
        // verify the policies were created successfully
        
        policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.hockey.reader");
        assertNotNull(policy);

        List<Assertion> assertList = policy.getAssertions();
        assertEquals(assertList.size(), 1);
        assertEquals(assertList.get(0).getRole(), domain + ":role.coretech.storage.res_group.hockey.reader");
        
        policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.hockey.writer");
        assertNotNull(policy);

        assertList = policy.getAssertions();
        assertEquals(assertList.size(), 1);
        assertEquals(assertList.get(0).getRole(), domain + ":role.coretech.storage.res_group.hockey.writer");
        
        // now add the tenant roles for our domain since our mock provider client
        // cannot connect to our zms instance
        
        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : RESOURCE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        TenantResourceGroupRoles tenantRoles = new TenantResourceGroupRoles().setDomain("coretech")
                .setService("storage").setTenant(domain)
                .setRoles(roleActions).setResourceGroup("hockey");

        zms.putTenantResourceGroupRoles(mockDomRsrcCtx, "coretech", "storage", domain, "hockey",
                auditRef, tenantRoles);
        
        List<String> tenantResourceGroups = new ArrayList<>();
        tenantResourceGroups.add("hockey");
        ProviderMockClient.setResourceGroups(tenantResourceGroups);
        
        // let's verify that our get Tenancy returns the resource group
        
        Tenancy tenancy = zms.getTenancy(mockDomRsrcCtx, domain, "coretech.storage");
        assertNotNull(tenancy);
        assertEquals(1, tenancy.getResourceGroups().size());
        assertTrue(tenancy.getResourceGroups().contains("hockey"));
        ProviderMockClient.setResourceGroups(null);
        
        // now let's add another resource group
        
        detail = new TenancyResourceGroup();
        detail.setDomain(domain).setService("coretech.storage").setResourceGroup("baseball");
        zms.putTenancyResourceGroup(mockDomRsrcCtx, domain, "coretech.storage", "baseball", auditRef, detail);
        
        // now verify that roles were created successfully
        
        role = zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.baseball.reader", false, false);
        assertNotNull(role);
        
        role = zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.baseball.writer", false, false);
        assertNotNull(role);
        
        // verify the policies were created successfully
        
        policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.baseball.reader");
        assertNotNull(policy);

        assertList = policy.getAssertions();
        assertEquals(assertList.size(), 1);
        assertEquals(assertList.get(0).getRole(), domain + ":role.coretech.storage.res_group.baseball.reader");
        
        policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.baseball.writer");
        assertNotNull(policy);

        assertList = policy.getAssertions();
        assertEquals(assertList.size(), 1);
        assertEquals(assertList.get(0).getRole(), domain + ":role.coretech.storage.res_group.baseball.writer");
        
        // now add the tenant roles for our domain since our mock provider client
        // cannot connect to our zms instance
        
        tenantRoles = new TenantResourceGroupRoles().setDomain("coretech")
                .setService("storage").setTenant(domain)
                .setRoles(roleActions).setResourceGroup("baseball");

        zms.putTenantResourceGroupRoles(mockDomRsrcCtx, "coretech", "storage", domain, "baseball",
                auditRef, tenantRoles);
        
        tenantResourceGroups.add("baseball");
        ProviderMockClient.setResourceGroups(tenantResourceGroups);
        
        tenancy = zms.getTenancy(mockDomRsrcCtx, domain, "coretech.storage");
        assertNotNull(tenancy);
        assertEquals(2, tenancy.getResourceGroups().size());
        assertTrue(tenancy.getResourceGroups().contains("hockey"));
        assertTrue(tenancy.getResourceGroups().contains("baseball"));
        ProviderMockClient.setResourceGroups(null);
        
        // now we're going to let the provider an extra resource
        // that must be removed by zms since there are no policies
        // defined for that resource group
        
        tenantResourceGroups.add("basketball");
        ProviderMockClient.setResourceGroups(tenantResourceGroups);
        
        tenancy = zms.getTenancy(mockDomRsrcCtx, domain, "coretech.storage");
        assertNotNull(tenancy);
        assertEquals(2, tenancy.getResourceGroups().size());
        assertTrue(tenancy.getResourceGroups().contains("hockey"));
        assertTrue(tenancy.getResourceGroups().contains("baseball"));
        ProviderMockClient.setResourceGroups(null);
        
        zms.deleteTenancy(mockDomRsrcCtx, domain, "coretech.storage", auditRef);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
    }
    
    @Test
    public void testPutTenancyMissingAuditRef() {
        String tenantDomain    = "testPutTenancyMissingAuditRef";
        String providerDomain  = "providerTestPutTenancyMissingAuditRef";
        String providerService = "storage";

        // create tenant and provider domains
        //
        setupTenantDomainProviderService(tenantDomain, providerDomain, providerService,
                "http://localhost:8090/provider");

        // modify the tenant domain to require auditing
        //
        DomainMeta meta = createDomainMetaObject("Tenant Domain", null, true, true, null, 0);
        zms.putDomainMeta(mockDomRsrcCtx, tenantDomain, auditRef, meta);

        Tenancy tenant = createTenantObject(tenantDomain, providerDomain + "." + providerService);
        try {
            ProviderMockClient.setReturnTenantRoles(true);
            zms.putTenancy(mockDomRsrcCtx, tenantDomain, providerDomain + "." + providerService, null, tenant);
            fail("requesterror not thrown by putTenancy.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
            zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
        }
    }

    @Test
    public void testPutTenancyThrowException() {
        String domainName = "AddTenancyDom2";
        String tenantDomain = "coretech2";
        String tenantService = "storage";
        String service = tenantDomain + "." + tenantService;
        
        try {
            // use invalid provider-endpoint.
            setupTenantDomainProviderService(domainName, tenantDomain, tenantService, "");

            Tenancy tenant = createTenantObject(domainName, service);

            // should fail because do not have a valid provider-endpoint.
            ProviderMockClient.setReturnTenantRoles(true);
            zms.putTenancy(mockDomRsrcCtx, domainName, service, auditRef, tenant);
            fail("requesterror not thrown");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
    }

    @Test
    public void testDeleteTenancy() {
        String tenantDomain    = "testDeleteTenancy";
        String providerDomain  = "providerTestDeleteTenancy";
        String providerService = "storage";
        String provService = providerDomain + "." + providerService;
        
        // create tenant and provider domains
        //
        setupTenantDomainProviderService(tenantDomain, providerDomain, providerService,
                "http://localhost:8090/provider");

        // modify the tenant domain to require auditing
        //
        DomainMeta meta =
            createDomainMetaObject("Tenant Domain", null, true, true, null, 0);
        zms.putDomainMeta(mockDomRsrcCtx, tenantDomain, auditRef, meta);

        String testRoleName = providerDomain + ".testrole";
        Role role = createRoleObject(tenantDomain, testRoleName, null, "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, tenantDomain, testRoleName, auditRef, role);

        // setup tenancy
        //
        Tenancy tenant = createTenantObject(tenantDomain, provService);
        ProviderMockClient.setReturnTenantRoles(true);
        zms.putTenancy(mockDomRsrcCtx, tenantDomain, provService, auditRef, tenant);

        try {
            zms.deleteTenancy(mockDomRsrcCtx, tenantDomain,  provService, auditRef);
            
            // verify we didn't delete a role by mistake
            
            assertNotNull(zms.getRole(mockDomRsrcCtx, tenantDomain, testRoleName, false, false));
            
            // verify that all roles and policies have been deleted
            
            try {
                zms.getRole(mockDomRsrcCtx, tenantDomain, provService + ".admin", false, false);
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            
            try {
                zms.getRole(mockDomRsrcCtx, tenantDomain, provService + ".reader", false, false);
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            try {
                zms.getRole(mockDomRsrcCtx, tenantDomain, provService + ".writer", false, false);
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }

            try {
                zms.getPolicy(mockDomRsrcCtx, tenantDomain, "tenancy." + provService + ".admin");
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            
            try {
                zms.getPolicy(mockDomRsrcCtx, tenantDomain, "tenancy." + provService + ".reader");
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            
            try {
                zms.getPolicy(mockDomRsrcCtx, tenantDomain, "tenancy." + provService + ".writer");
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
            
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
            zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
        }
    }

    @Test
    public void testDeleteTenancyResourceGroup() {

        String domain = "deletetenancyresourcegroupdom1";
        
        setupTenantDomainProviderService(domain, "coretech", "storage",
                "http://localhost:8090/provider");

        Tenancy tenant = createTenantObject(domain, "coretech.storage");
        ProviderMockClient.setReturnTenantRoles(false);
        zms.putTenancy(mockDomRsrcCtx, domain, "coretech.storage", auditRef, tenant);
        
        // verify the admin policy has been successfully created
        
        Policy policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.admin");
        assertNotNull(policy);
        
        // now let's put a resource group
        
        TenancyResourceGroup detail = new TenancyResourceGroup();
        detail.setDomain(domain).setService("coretech.storage").setResourceGroup("hockey");
        zms.putTenancyResourceGroup(mockDomRsrcCtx, domain, "coretech.storage", "hockey", auditRef, detail);
        
        // now let's add another resource group
        
        detail = new TenancyResourceGroup();
        detail.setDomain(domain).setService("coretech.storage").setResourceGroup("baseball");
        zms.putTenancyResourceGroup(mockDomRsrcCtx, domain, "coretech.storage", "baseball", auditRef, detail);
        
        // now let's delete our initial hockey resource group
        
        zms.deleteTenancyResourceGroup(mockDomRsrcCtx, domain, "coretech.storage", "hockey", auditRef);
        
        // verify the admin policy is still present
        
        policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.admin");
        assertNotNull(policy);
        
        // now verify that baseball roles are still around
        
        Role role = zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.baseball.reader", false, false);
        assertNotNull(role);
        
        role = zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.baseball.writer", false, false);
        assertNotNull(role);
        
        // verify the policies also exist for baseball group
        
        policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.baseball.reader");
        assertNotNull(policy);

        List<Assertion> assertList = policy.getAssertions();
        assertEquals(assertList.size(), 1);
        assertEquals(assertList.get(0).getRole(), domain + ":role.coretech.storage.res_group.baseball.reader");
        
        policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.baseball.writer");
        assertNotNull(policy);

        assertList = policy.getAssertions();
        assertEquals(assertList.size(), 1);
        assertEquals(assertList.get(0).getRole(), domain + ":role.coretech.storage.res_group.baseball.writer");
        
        // now verify that the hockey roles and policies were indeed removed
        
        try {
            zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.hockey.reader", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.hockey.writer", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        // we should not have other policies for actions
        
        try {
            zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.hockey.reader");
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.hockey.writer");
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        // now let's delete the baseball resource group as well
        
        zms.deleteTenancyResourceGroup(mockDomRsrcCtx, domain, "coretech.storage", "baseball", auditRef);

        // now verify that the admin policy is still around
        
        policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.admin");
        assertNotNull(policy);
        
       // now verify that the baseball roles and policies were indeed removed
        
        try {
            zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.baseball.reader", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getRole(mockDomRsrcCtx, domain, "coretech.storage.res_group.baseball.writer", false, false);
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        // we should not have other policies for actions
        
        try {
            zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.baseball.reader");
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        try {
            zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.res_group.baseball.writer");
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        // now let's just delete some invalid resource group which should not
        // affect anything since we have no roles/policies to delete
        
        zms.deleteTenancyResourceGroup(mockDomRsrcCtx, domain, "coretech.storage", "basketball", auditRef);

        // now verify that the admin policy is still around
        
        policy = zms.getPolicy(mockDomRsrcCtx, domain, "tenancy.coretech.storage.admin");
        assertNotNull(policy);
        
        zms.deleteTenancy(mockDomRsrcCtx, domain, "coretech.storage", auditRef);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef);
    }
    
    @Test
    public void testDeleteTenancyMissingService() {
        String tenantDomain    = "testDeleteTenancy";
        String providerDomain  = "providerTestDeleteTenancy";
        String providerService = "storage";
        String provService = providerDomain + "." + providerService;

        // create tenant and provider domains
        //
        setupTenantDomainProviderService(tenantDomain, providerDomain, providerService,
                "http://localhost:8090/provider");

        // modify the tenant domain to require auditing
        //
        DomainMeta meta =
            createDomainMetaObject("Tenant Domain", null, true, true, null, 0);
        zms.putDomainMeta(mockDomRsrcCtx, tenantDomain, auditRef, meta);

        // setup tenancy
        //
        Tenancy tenant = createTenantObject(tenantDomain, provService);
        ProviderMockClient.setReturnTenantRoles(true);
        zms.putTenancy(mockDomRsrcCtx, tenantDomain, provService, auditRef, tenant);

        // delete the provider service
        
        zms.deleteServiceIdentity(mockDomRsrcCtx, providerDomain, providerService, auditRef);
        
        try {
            zms.deleteTenancy(mockDomRsrcCtx, tenantDomain, provService, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("service does not exist"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
            zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
        }
    }
    
    @Test
    public void testDeleteTenancyMissingEndpoint() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_deltenancymissendpoint";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String tenantDomain    = "testDeleteTenancyMissEnd";
        String providerDomain  = "providerTestDeleteTenancyMissEnd";
        String providerService = "storage";
        String provService = providerDomain + "." + providerService;

        // create tenant and provider domains
        //
        setupTenantDomainProviderService(zmsImpl, tenantDomain, providerDomain, providerService,
                "http://localhost:8090/provider");

        // modify the tenant domain to require auditing
        //
        DomainMeta meta =
            createDomainMetaObject("Tenant Domain", null, true, true, null, 0);
        zmsImpl.putDomainMeta(mockDomRsrcCtx, tenantDomain, auditRef, meta);

        // setup tenancy
        //
        Tenancy tenant = createTenantObject(tenantDomain, provService);
        ProviderMockClient.setReturnTenantRoles(true);
        zmsImpl.putTenancy(mockDomRsrcCtx, tenantDomain, provService, auditRef, tenant);

        // delete the provider service endpoint
        
        ServiceIdentity service = createServiceObject(
                providerDomain, providerService, null,
                "/usr/bin/java", "root", "users", "localhost");

        zmsImpl.putServiceIdentity(mockDomRsrcCtx, providerDomain, providerService, auditRef, service);
        
        try {
            zmsImpl.deleteTenancy(mockDomRsrcCtx, tenantDomain, provService, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("service does not have endpoint configured"));
        } finally {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
            FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
        }
    }
    
    @Test
    public void testDeleteTenancyMissingAuditRef() {
        String tenantDomain    = "testDeleteTenancyMissingAuditRef";
        String providerDomain  = "providerTestDeleteTenancyMissingAuditRef";
        String providerService = "storage";

        // create tenant and provider domains
        //
        setupTenantDomainProviderService(tenantDomain, providerDomain, providerService,
                "http://localhost:8090/provider");

        // modify the tenant domain to require auditing
        //
        DomainMeta meta =
            createDomainMetaObject("Tenant Domain", null, true, true, null, 0);
        zms.putDomainMeta(mockDomRsrcCtx, tenantDomain, auditRef, meta);

        // setup tenancy
        //
        Tenancy tenant = createTenantObject(tenantDomain, providerDomain + "." + providerService);
        ProviderMockClient.setReturnTenantRoles(true);
        zms.putTenancy(mockDomRsrcCtx, tenantDomain, providerDomain + "." + providerService, auditRef, tenant);

        try {
            zms.deleteTenancy(mockDomRsrcCtx, tenantDomain,  providerDomain + "." + providerService, null);
            fail("requesterror not thrown by deleteTenancy.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
            zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
        }
    }

    @Test
    public void testPutTenantRoles() {

        String domain = "testPutTenantRoles";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String serviceName  = "storage";
        String tenantDomain = "tenantTestPutTenantRoles";
        TenantRoles tenantRoles = new TenantRoles().setDomain(domain)
                .setService(serviceName).setTenant(tenantDomain)
                .setRoles(roleActions);
        zms.putTenantRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain, auditRef, tenantRoles);

        TenantRoles tRoles = zms.getTenantRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain);
        assertNotNull(tRoles);
        assertEquals(tRoles.getDomain(), domain.toLowerCase());
        assertEquals(tRoles.getService(), serviceName.toLowerCase());
        assertEquals(tRoles.getTenant(), tenantDomain.toLowerCase());
        assertEquals(tRoles.getRoles().size(), TABLE_PROVIDER_ROLE_ACTIONS.size());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
    }

    @Test
    public void testPutTenantRolesMissingAuditRef() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_puttenantrolesmissauditref";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domain = "testPutTenantRoles";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String serviceName  = "storage";
        String tenantDomain = "tenantTestPutTenantRoles";
        TenantRoles tenantRoles = new TenantRoles().setDomain(domain)
                .setService(serviceName).setTenant(tenantDomain)
                .setRoles(roleActions);
        try {
            zmsImpl.putTenantRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain, null, tenantRoles);
            fail("requesterror not thrown by putTenantRoles.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
            FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
        }
    }

    @Test
    public void testPutTenantRolesThrowException() {
        String domainName = "AddTenancyDom3";
        String tenantDomain = "coretech3";
        String tenantService = "storage";
        String providerEndpoint = "http://localhost:8090/provider";
        String service = tenantDomain + "." + tenantService;
        
        // Should FAIL validate() as we are passing null for the tenant role action list.
        try {
            setupTenantDomainProviderService(domainName, tenantDomain, tenantService, providerEndpoint);

            Tenancy tenant = createTenantObject(domainName, service);
            ProviderMockClient.setReturnTenantRoles(true);
            zms.putTenancy(mockDomRsrcCtx, domainName, service, auditRef, tenant);
            
            zms.putTenantRoles(mockDomRsrcCtx, tenantDomain, tenantService, domainName, auditRef, null);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        } finally {
            zms.deleteTenancy(mockDomRsrcCtx, domainName, service, auditRef);
            
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
            zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        }
        
        // Should FAIL validate() as we are passing an empty tenantroles.
        try {
            setupTenantDomainProviderService(domainName, tenantDomain, tenantService, providerEndpoint);

            Tenancy tenant = createTenantObject(domainName, service);
            ProviderMockClient.setReturnTenantRoles(true);
            zms.putTenancy(mockDomRsrcCtx, domainName, service, auditRef, tenant);
            
            TenantRoles tenantRoles = new TenantRoles();
            
            zms.putTenantRoles(mockDomRsrcCtx, tenantDomain, tenantService, domainName, auditRef, tenantRoles);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        } finally {
            zms.deleteTenancy(mockDomRsrcCtx, domainName, service, auditRef);
            
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
            zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        }
        
        // Should FAIL as we are passing a tenantrole with empty actions list.
        try {
            setupTenantDomainProviderService(domainName, tenantDomain, tenantService, providerEndpoint);

            Tenancy tenant = createTenantObject(domainName, service);
            ProviderMockClient.setReturnTenantRoles(true);
            zms.putTenancy(mockDomRsrcCtx, domainName, service, auditRef, tenant);
            
            List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
            TenantRoles tenantRoles = new TenantRoles().setDomain(tenantDomain)
                    .setService(tenantService).setTenant(domainName).setRoles(roleActions);
            
            zms.putTenantRoles(mockDomRsrcCtx, tenantDomain, tenantService, domainName, auditRef, tenantRoles);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        } finally {
            zms.deleteTenancy(mockDomRsrcCtx, domainName, service, auditRef);
            
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
            zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        }
    }
    
    @Test
    public void testPutTenantRolesWithResourceGroup() {

        String domain = "testPutTenantRoles";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String serviceName  = "storage";
        String tenantDomain = "tenantTestPutTenantRoles";
        String resourceGroup = "Group1";
        
        TenantResourceGroupRoles tenantRoles = new TenantResourceGroupRoles().setDomain(domain)
                .setService(serviceName).setTenant(tenantDomain)
                .setRoles(roleActions).setResourceGroup(resourceGroup);
        zms.putTenantResourceGroupRoles(mockDomRsrcCtx, domain, serviceName, tenantDomain, resourceGroup,
                auditRef, tenantRoles);

        TenantResourceGroupRoles tRoles = zms.getTenantResourceGroupRoles(mockDomRsrcCtx, domain, serviceName,
                tenantDomain, resourceGroup);
        assertNotNull(tRoles);
        assertEquals(domain.toLowerCase(), tRoles.getDomain());
        assertEquals(serviceName.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(TABLE_PROVIDER_ROLE_ACTIONS.size(), tRoles.getRoles().size());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
    }

     @Test
    public void testGetDomainDataCheck() {

        String tenantDomainName = "testGetDomainDataCheck";
        TopLevelDomain tenDom = createTopLevelDomainObject(tenantDomainName,
                "Test Provider Domain", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, tenDom);
        // create roles
        Role role1 = createRoleObject(tenantDomainName, "Role1", null, "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, tenantDomainName, "Role1", auditRef, role1);

        Role role2 = createRoleObject(tenantDomainName, "Role2", null, "user.phil", "user.gil");
        zms.putRole(mockDomRsrcCtx, tenantDomainName, "Role2", auditRef, role2);

        // create policies
        Policy policy1 = createPolicyObject(tenantDomainName, "Policy1", "Role1",
                "UPDATE", tenantDomainName + ":resource1", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, tenantDomainName, "Policy1", auditRef, policy1);
        Policy policy2 = createPolicyObject(tenantDomainName, "Policy2", "Role2",
                "READ", tenantDomainName + ":resource1", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, tenantDomainName, "Policy2", auditRef, policy2);
        //
        // test valid setup domain
        DomainDataCheck ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(3, ddc.getPolicyCount());
        assertEquals(3, ddc.getAssertionCount());
        assertEquals(0, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertNull(ddc.getDanglingPolicies());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // set valid wildcard role
        Assertion assertion = new Assertion();
        assertion.setAction("MANAGE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(tenantDomainName + ":wildlife");
        assertion.setRole(tenantDomainName + ":role.Role*");
        
        Policy policy = zms.getPolicy(mockDomRsrcCtx, tenantDomainName, "Policy2");
        List<Assertion> assertList = policy.getAssertions();
        assertList.add(assertion);
        policy.setAssertions(assertList);
        zms.putPolicy(mockDomRsrcCtx, tenantDomainName, "Policy2", auditRef, policy);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(3, ddc.getPolicyCount());
        assertEquals(4, ddc.getAssertionCount());
        assertEquals(1, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertNull(ddc.getDanglingPolicies());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // test dangling policy with wildcard role
        assertion = new Assertion();
        assertion.setAction("MANAGE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(tenantDomainName + ":wildlife");
        assertion.setRole(tenantDomainName + ":role.Wild*");
        
        policy = zms.getPolicy(mockDomRsrcCtx, tenantDomainName, "Policy2");
        assertList = policy.getAssertions();
        assertList.add(assertion);
        policy.setAssertions(assertList);
        zms.putPolicy(mockDomRsrcCtx, tenantDomainName, "Policy2", auditRef, policy);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(3, ddc.getPolicyCount());
        assertEquals(5, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertEquals(1, ddc.getDanglingPolicies().size());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // add a dangling role 
        Role role3 = createRoleObject(tenantDomainName, "Role3", null, "user.user1", "user.user3");
        zms.putRole(mockDomRsrcCtx, tenantDomainName, "Role3", auditRef, role3);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(3, ddc.getPolicyCount());
        assertEquals(5, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(1, ddc.getDanglingRoles().size());
        assertEquals(1, ddc.getDanglingPolicies().size());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // test more dangling policies
        // create policy with assertion using unknown role
        assertion = new Assertion();
        assertion.setAction("snorkel");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(tenantDomainName + ":molokoni");
        assertion.setRole(tenantDomainName + ":role.snorkeler");
        
        policy = zms.getPolicy(mockDomRsrcCtx, tenantDomainName, "Policy2");
        assertList = policy.getAssertions();
        assertList.add(assertion);
        policy.setAssertions(assertList);
        zms.putPolicy(mockDomRsrcCtx, tenantDomainName, "Policy2", auditRef, policy);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(3, ddc.getPolicyCount());
        assertEquals(6, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(1, ddc.getDanglingRoles().size());
        assertEquals(2, ddc.getDanglingPolicies().size());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // create provider domain
        String provDomainTop = "testGetDomainDataCheckProvider";
        TopLevelDomain provDom = createTopLevelDomainObject(provDomainTop,
                "Test Provider Domain", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, provDom);

        String provDomainSub = provDomainTop + ".sub";
        SubDomain subDom = createSubDomainObject("sub", provDomainTop, null, null, adminUser);
        subDom.setAuditEnabled(true);
        zms.postSubDomain(mockDomRsrcCtx, provDomainTop, auditRef, subDom);

        // test incomplete tenancy setup
        // put tenancy for provider
        String provEndPoint = "http://localhost:8090/provider";
        String provSvc      = "storage";
        ServiceIdentity service = createServiceObject(
                provDomainSub, provSvc, provEndPoint,
                "/usr/bin/java", "root", "users", "localhost");

        zms.putServiceIdentity(mockDomRsrcCtx, provDomainSub, provSvc, auditRef, service);

        ProviderMockClient.setReturnTenantRoles(true);
        Tenancy tenant = createTenantObject(tenantDomainName, provDomainSub + "." + provSvc);
        zms.putTenancy(mockDomRsrcCtx, tenantDomainName, provDomainSub + "." + provSvc, auditRef, tenant);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(6, ddc.getPolicyCount());
        assertEquals(12, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(1, ddc.getDanglingRoles().size());
        assertEquals(2, ddc.getDanglingPolicies().size());
        assertTrue(ddc.getDanglingRoles().contains("role3"));
        boolean danglingPolicy1Found = false;
        boolean danglingPolicy2Found = false;
        for (DanglingPolicy danglingPolicy : ddc.getDanglingPolicies()) {
            if (danglingPolicy.getPolicyName().equals("policy2") && danglingPolicy.getRoleName().equals("wild*")) {
                danglingPolicy1Found = true;
            } else if (danglingPolicy.getPolicyName().equals("policy2") && danglingPolicy.getRoleName().equals("snorkeler")) {
                danglingPolicy2Found = true;
            }
        }
        assertTrue(danglingPolicy1Found);
        assertTrue(danglingPolicy2Found);
        assertEquals(1, ddc.getProvidersWithoutTrust().size());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // test that now all is hunky dory between the tenant and provider
        // provider gets the trust role(s)
        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction((String) f.value()));
        }

        TenantRoles tenantRoles = new TenantRoles().setDomain(provDomainSub)
                .setService(provSvc).setTenant(tenantDomainName)
                .setRoles(roleActions);

        zms.putTenantRoles(mockDomRsrcCtx, provDomainSub, provSvc, tenantDomainName,
                auditRef, tenantRoles);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(6, ddc.getPolicyCount());
        assertEquals(12, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(1, ddc.getDanglingRoles().size());
        assertEquals(2, ddc.getDanglingPolicies().size());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, provDomainSub);
        assertNotNull(ddc);
        assertEquals(4, ddc.getPolicyCount());
        assertEquals(4, ddc.getAssertionCount());
        assertEquals(0, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertNull(ddc.getDanglingPolicies());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // test provider should report tenant is missing
        // remove the assume_role policies from the tenant
        zms.deleteTenancy(mockDomRsrcCtx, tenantDomainName,  provDomainSub + "." + provSvc, auditRef);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, provDomainSub);
        assertNotNull(ddc);
        assertEquals(4, ddc.getPolicyCount());
        assertEquals(4, ddc.getAssertionCount());
        assertEquals(0, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertNull(ddc.getDanglingPolicies());
        assertNull(ddc.getProvidersWithoutTrust());
        assertTrue(ddc.getTenantsWithoutAssumeRole().size() == 1);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(3, ddc.getPolicyCount());
        assertEquals(6, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(2, ddc.getDanglingRoles().size());
        assertEquals(2, ddc.getDanglingPolicies().size());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // test service name with resource group
        // setup up the top level domain+service with resource group
        String provSvcTop = "shelter";
        service = createServiceObject(
                provDomainTop, provSvcTop, provEndPoint,
                "/usr/bin/java", "root", "users", "localhost");

        zms.putServiceIdentity(mockDomRsrcCtx, provDomainTop, provSvcTop, auditRef, service);

        TenantResourceGroupRoles tenantGroupRoles = new TenantResourceGroupRoles()
                .setDomain(provDomainTop)
                .setService(provSvcTop).setTenant(tenantDomainName)
                .setRoles(roleActions).setResourceGroup("ravers");
        // put the trust roles with resource group into top level provider domain
        // - tenant is not yet supporting the top level domain
        zms.putTenantResourceGroupRoles(mockDomRsrcCtx, provDomainTop, provSvcTop, tenantDomainName, "ravers",
                auditRef, tenantGroupRoles);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, provDomainTop);
        assertNotNull(ddc);
        assertEquals(4, ddc.getPolicyCount());
        assertEquals(4, ddc.getAssertionCount());
        assertEquals(0, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertNull(ddc.getDanglingPolicies());
        assertNull(ddc.getProvidersWithoutTrust());
        assertEquals(1, ddc.getTenantsWithoutAssumeRole().size());

        // now set up the tenant for the sub domain provider
        ProviderResourceGroupRoles providerRoles = new ProviderResourceGroupRoles()
                .setDomain(provDomainSub).setService(provSvc)
                .setTenant(tenantDomainName).setRoles(roleActions)
                .setResourceGroup("ravers");
        // this sets up the assume roles in the tenant for the sub domain
        // if it is an authorized service, then it will setup the provider roles too
        zms.putProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomainName, provDomainSub, provSvc,
                "ravers", auditRef, providerRoles);

        // tenant sees that the subdomain provider isnt provisioned yet
        // for the resource group: testgetdomaindatacheckprovider.sub.storage.ravers
        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc, ddc.toString());
        assertEquals(7, ddc.getPolicyCount());
        assertEquals(12, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(1, ddc.getDanglingRoles().size());
        assertEquals(2, ddc.getDanglingPolicies().size());
        assertEquals(1, ddc.getProvidersWithoutTrust().size());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // setup tenancy in the tenant domain for the provider subdomain
        zms.putTenancy(mockDomRsrcCtx, tenantDomainName, provDomainSub + "." + provSvc, auditRef, tenant);

        // the subdomain provider believes it is in sync with tenant
        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, provDomainSub);
        assertNotNull(ddc);
        assertEquals(4, ddc.getPolicyCount());
        assertEquals(4, ddc.getAssertionCount());
        assertEquals(0, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertNull(ddc.getDanglingPolicies());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // but the tenant sees the sub provider is not setup 
        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(9, ddc.getPolicyCount());
        assertEquals(15, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(1, ddc.getDanglingRoles().size());
        assertEquals(2, ddc.getDanglingPolicies().size());
        assertEquals(1, ddc.getProvidersWithoutTrust().size());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // now set up the sub domain provider for the tenant with resource groups
        // so tenant and the sub domain provider are in sync again
        // add resource groups to provider
        tenantGroupRoles = new TenantResourceGroupRoles()
                .setDomain(provDomainSub)
                .setService(provSvc).setTenant(tenantDomainName)
                .setRoles(roleActions).setResourceGroup("ravers");
        // put the trust roles into sub domain provider
        zms.putTenantResourceGroupRoles(mockDomRsrcCtx, provDomainSub, provSvc, tenantDomainName, "ravers",
                auditRef, tenantGroupRoles);

        // now tenant sees the sub domain has provisioned it
        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(9, ddc.getPolicyCount());
        assertEquals(15, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(1, ddc.getDanglingRoles().size());
        assertEquals(2, ddc.getDanglingPolicies().size());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // now set up the tenant for the top level domain provider
        // so tenant and the top level domain provider are in sync again
        providerRoles = new ProviderResourceGroupRoles()
                .setDomain(provDomainTop).setService(provSvcTop)
                .setTenant(tenantDomainName).setRoles(roleActions)
                .setResourceGroup("ravers");
        // this sets up the assume roles in the tenant for the top level domain
        zms.putProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomainName, provDomainTop, provSvcTop,
                "ravers", auditRef, providerRoles);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(13, ddc.getPolicyCount());
        assertEquals(21, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(1, ddc.getDanglingRoles().size());
        assertEquals(2, ddc.getDanglingPolicies().size());
        assertEquals(1, ddc.getProvidersWithoutTrust().size());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // delete the resource group tenancy support from sub domain
        // this means the tenant domain should show both the sub domain and
        // the top domain is without trust roles
        zms.deleteTenantResourceGroupRoles(mockDomRsrcCtx, provDomainSub, provSvc,
                tenantDomainName, "ravers", auditRef);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(13, ddc.getPolicyCount());
        assertEquals(21, ddc.getAssertionCount());
        assertEquals(2, ddc.getRoleWildCardCount());
        assertEquals(1, ddc.getDanglingRoles().size());
        assertEquals(2, ddc.getDanglingPolicies().size());
        assertEquals(2, ddc.getProvidersWithoutTrust().size());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // delete the dangling policies and dangling role
        zms.deletePolicy(mockDomRsrcCtx, tenantDomainName, "Policy2", auditRef);
        zms.deleteRole(mockDomRsrcCtx, tenantDomainName, "Role3", auditRef);
        zms.deleteRole(mockDomRsrcCtx, tenantDomainName, "Role2", auditRef);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(12, ddc.getPolicyCount());
        assertEquals(17, ddc.getAssertionCount());
        assertEquals(0, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertNull(ddc.getDanglingPolicies());
        assertEquals(2, ddc.getProvidersWithoutTrust().size());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // add the tenancy support for top domain
        // - now tenant will see that it is all setup
        tenantRoles = new TenantRoles().setDomain(provDomainTop)
                .setService(provSvcTop).setTenant(tenantDomainName)
                .setRoles(roleActions);

        zms.putTenantRoles(mockDomRsrcCtx, provDomainTop, provSvcTop, tenantDomainName,
                auditRef, tenantRoles);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(12, ddc.getPolicyCount());
        assertEquals(17, ddc.getAssertionCount());
        assertEquals(0, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertNull(ddc.getDanglingPolicies());
        assertEquals(1, ddc.getProvidersWithoutTrust().size());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        // delete the provider resource group roles for the sub domain provider
        // then everything in sync for this tenant
        zms.deleteProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomainName, provDomainSub, provSvc,
                "ravers", auditRef);

        ddc = zms.getDomainDataCheck(mockDomRsrcCtx, tenantDomainName);
        assertNotNull(ddc);
        assertEquals(9, ddc.getPolicyCount());
        assertEquals(14, ddc.getAssertionCount());
        assertEquals(0, ddc.getRoleWildCardCount());
        assertNull(ddc.getDanglingRoles());
        assertNull(ddc.getDanglingPolicies());
        assertNull(ddc.getProvidersWithoutTrust());
        assertNull(ddc.getTenantsWithoutAssumeRole());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomainName, auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, provDomainTop, "sub", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, provDomainTop, auditRef);
    }

    @Test
    public void testGetServicePrincipal() {
        
        PrivateKey privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        SimpleServiceIdentityProvider provider = new SimpleServiceIdentityProvider("coretech",
                "storage", privateKey, "0");
        
        Principal testPrincipal = provider.getIdentity("coretech", "storage");
        assertNotNull(testPrincipal);
        ResourceContext rsrcCtxTest = createResourceContext(testPrincipal);
        ServicePrincipal principal = zms.getServicePrincipal(rsrcCtxTest);
        assertNotNull(principal);
        assertTrue(principal.getService().equals("storage"));
        assertTrue(principal.getDomain().equals("coretech"));
    }
    
    @Test
    public void testEmitMonmetricError() {
        int errorCode = 403;
        String caller = "forbiddenError";
        boolean isEmitMonmetricError;

        // negative tests
        isEmitMonmetricError = ZMSUtils.emitMonmetricError(errorCode, null);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZMSUtils.emitMonmetricError(errorCode, "");
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZMSUtils.emitMonmetricError(errorCode, new String());
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZMSUtils.emitMonmetricError(0, caller);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZMSUtils.emitMonmetricError(-100, caller);
        assertFalse(isEmitMonmetricError);

        // positive tests
        isEmitMonmetricError = ZMSUtils.emitMonmetricError(errorCode, caller);
        assertTrue(isEmitMonmetricError);

        isEmitMonmetricError = ZMSUtils.emitMonmetricError(errorCode, " " + caller + " ");
        assertTrue(isEmitMonmetricError);
    }
    
    @Test
    public void testCheckKerberosAuthorityAuthorization() {
        Authority authority = new com.yahoo.athenz.auth.impl.KerberosAuthority();
        Principal principal = SimplePrincipal.create("krb", "user1", "v=U1;d=user;n=user1;s=signature",
                0, authority);
        assertTrue(zms.authorityAuthorizationAllowed(principal));
    }
    
    @Test
    public void testCheckNullAuthorityAuthorization() {
        Principal principal = SimplePrincipal.create("user", "joe", "v=U1;d=user;n=user1;s=signature",
                0, null);
        assertTrue(zms.authorityAuthorizationAllowed(principal));
    }
    
    @Test
    public void testValidRoleTokenAccessTrustDomain() {
        assertFalse(zms.validRoleTokenAccess("TrustDomain", "Domain1", "Domain1"));
    }
    
    @Test
    public void testValidRoleTokenAccessMismatchNames() {
        assertFalse(zms.validRoleTokenAccess(null, "Domain1", "Domain2"));
    }
    
    @Test
    public void testValidRoleTokenAccessValid() {
        assertTrue(zms.validRoleTokenAccess(null, "Domain1", "Domain1"));
    }
    
    @Test
    public void testIsVirtualDomain() {
        
        assertTrue(zms.isVirtualDomain("user.user1"));
        assertTrue(zms.isVirtualDomain("user.user2"));
        assertTrue(zms.isVirtualDomain("user.user1.sub1"));
        assertTrue(zms.isVirtualDomain("user.user1.sub2.sub3"));
        
        assertFalse(zms.isVirtualDomain("user"));
        assertFalse(zms.isVirtualDomain("usertest"));
        assertFalse(zms.isVirtualDomain("coretech.api"));
    }

    @Test
    public void testHasExceededVirtualSubDomainLimitUnderLimitOneLevel() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT, "2");
        ZMSImpl zmsTest = zmsInit();

        assertFalse(zmsTest.hasExceededVirtualSubDomainLimit("user.user1"));
        
        SubDomain dom = createSubDomainObject("sub1", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom = zms.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        assertFalse(zmsTest.hasExceededVirtualSubDomainLimit("user.user1"));
        
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub1", auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT);
    }
    
    @Test
    public void testHasExceededVirtualSubDomainLimitOverLimitOneLevel() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT, "2");
        ZMSImpl zmsTest = zmsInit();
        
        SubDomain dom = createSubDomainObject("sub1", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom = zms.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub2", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zms.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        assertTrue(zmsTest.hasExceededVirtualSubDomainLimit("user.user1"));
        
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub1", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub2", auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT);
    }
    
    @Test
    public void testHasExceededVirtualSubDomainLimitUnderLimitMultipleLevel() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT, "3");
        ZMSImpl zmsTest = zmsInit();

        assertFalse(zmsTest.hasExceededVirtualSubDomainLimit("user.user1"));
        
        SubDomain dom = createSubDomainObject("sub1", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom = zms.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub2", "user.user1.sub1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zms.postSubDomain(mockDomRsrcCtx, "user.user1.sub1", auditRef, dom);
        assertNotNull(resDom);
        
        assertFalse(zmsTest.hasExceededVirtualSubDomainLimit("user.user1.sub1"));
        
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1.sub1", "sub2", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub1", auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT);
    }
    
    @Test
    public void testHasExceededVirtualSubDomainLimitOverLimitMultipleLevel() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT, "2");
        ZMSImpl zmsTest = zmsInit();
        
        SubDomain dom = createSubDomainObject("sub1", "user.user1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom = zms.postSubDomain(mockDomRsrcCtx, "user.user1", auditRef, dom);
        assertNotNull(resDom);
        
        dom = createSubDomainObject("sub2", "user.user1.sub1",
                "Test Domain2", "testOrg", adminUser);
        resDom = zms.postSubDomain(mockDomRsrcCtx, "user.user1.sub1", auditRef, dom);
        assertNotNull(resDom);
        
        assertTrue(zmsTest.hasExceededVirtualSubDomainLimit("user.user1.sub1"));
        assertTrue(zmsTest.hasExceededVirtualSubDomainLimit("user.user1"));
        
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1.sub1", "sub2", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "user.user1", "sub1", auditRef);
        System.clearProperty(ZMSConsts.ZMS_PROP_VIRTUAL_DOMAIN_LIMIT);
    }

    @Test
    public void testGetNormalizedMemberNoSplit() {
        
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("user.user")).getMemberName(), "user.user");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("user.user2")).getMemberName(), "user.user2");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("user.user1")).getMemberName(), "user.user1");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("coretech.storage")).getMemberName(), "coretech.storage");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("user1")).getMemberName(), "user1");
    }
    
    @Test
    public void testGetNormalizedMemberInvalidFormat() {
        
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("user:user:user1")).getMemberName(), "user:user:user1");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("user:")).getMemberName(), "user:");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("coretech:storage:api")).getMemberName(), "coretech:storage:api");
    }
    
    @Test
    public void testGetNormalizedMemberUsersWithSplit() {
        
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("user:user")).getMemberName(), "user.user");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("user:user2")).getMemberName(), "user.user2");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("user:user1")).getMemberName(), "user.user1");
    }
    
    @Test
    public void testGetNormalizedMemberServiceWithSplit() {
        
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("coretech:service.storage")).getMemberName(), "coretech.storage");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("weather:service.storage.api")).getMemberName(), "weather.storage.api");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("weather.storage:service.api")).getMemberName(), "weather.storage.api");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("weather.storage:entity.api")).getMemberName(), "weather.storage:entity.api");
        assertEquals(zms.getNormalizedMember(
                new RoleMember().setMemberName("weather.storage:service.")).getMemberName(), "weather.storage.");
    }
    
    @Test
    public void testNormalizeRoleMembersUsers() {

        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user:joe"));
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("user:joe"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        
        Role role = createRoleObject("TestRole", "Role1", null, roleMembers);
        zms.normalizeRoleMembers(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 2);
        
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkRoleMember(checkList, members);
    }
    
    @Test
    public void testNormalizeRoleMembersServices() {

        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("coretech.storage"));
        roleMembers.add(new RoleMember().setMemberName("coretech:service.storage"));
        roleMembers.add(new RoleMember().setMemberName("weather:service.storage"));
        
        Role role = createRoleObject("TestRole", "Role1", null, roleMembers);
        zms.normalizeRoleMembers(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 2);
        
        List<String> checkList = new ArrayList<>();
        checkList.add("coretech.storage");
        checkList.add("weather.storage");
        checkRoleMember(checkList, members);
    }
    
    @Test
    public void testNormalizeRoleMembersCombined() {

        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user:joe"));
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("user:joe"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        roleMembers.add(new RoleMember().setMemberName("coretech.storage"));
        roleMembers.add(new RoleMember().setMemberName("coretech:service.storage"));
        roleMembers.add(new RoleMember().setMemberName("weather:service.storage"));
        roleMembers.add(new RoleMember().setMemberName("weather.api.access"));
        
        Role role = createRoleObject("TestRole", "Role1", null, roleMembers);
        zms.normalizeRoleMembers(role);

        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 5);
        
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("weather.api.access");
        checkList.add("coretech.storage");
        checkList.add("weather.storage");
        checkRoleMember(checkList, members);
    }
    
    @Test
    public void testNormalizeRoleMembersInvalid() {

        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("user2"));
        
        Role role = createRoleObject("TestRole", "Role1", null, roleMembers);
        zms.normalizeRoleMembers(role);
        
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 2);
        
        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user2");
        checkRoleMember(checkList, members);
    }
    
    @Test
    public void testHasExceededListLimitNullLimit() {
        assertFalse(zms.hasExceededListLimit(null, 10));
    }
    
    @Test
    public void testHasExceededListLimitNotValidLimit() {
        assertFalse(zms.hasExceededListLimit(0, 10));
        assertFalse(zms.hasExceededListLimit(-1, 10));
    }
    
    @Test
    public void testHasExceededListLimitYes() {
        assertTrue(zms.hasExceededListLimit(10, 11));
    }
    
    @Test
    public void testHasExceededListLimitNo() {
        assertFalse(zms.hasExceededListLimit(10, 9));
        assertFalse(zms.hasExceededListLimit(10, 10));
    }
    
    @Test
    public void testVerifyServicePublicKeysNoKeys() {
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName(ZMSUtils.serviceResourceName("ServiceAddInvalidCertDom1", "Service1"));

        // New Service need not have any public keys
        assertTrue(zms.verifyServicePublicKeys(service));
    }
    
    @Test
    public void testVerifyServicePublicKeysInvalidPublicKeys() {
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName(ZMSUtils.serviceResourceName("ServiceDom1", "Service1"));
        
        List<PublicKeyEntry> publicKeyList = new ArrayList<PublicKeyEntry>();
        PublicKeyEntry publicKeyEntry1 = new PublicKeyEntry();
        publicKeyEntry1.setKey("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTk");
        publicKeyEntry1.setId("1");
        publicKeyList.add(publicKeyEntry1);
        service.setPublicKeys(publicKeyList);
        
        assertFalse(zms.verifyServicePublicKeys(service));
    }
    
    @Test
    public void testVerifyServicePublicKeyInvalidPublicKey() {
        assertFalse(zms.verifyServicePublicKey("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1B"));
        assertFalse(zms.verifyServicePublicKey("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTk"));
        assertFalse(zms.verifyServicePublicKey(privKeyK1));
        assertFalse(zms.verifyServicePublicKey(privKeyK2));
    }
    
    @Test
    public void testVerifyServicePublicKeyValidPublicKey() {
        assertTrue(zms.verifyServicePublicKey(pubKeyK1));
        assertTrue(zms.verifyServicePublicKey(pubKeyK2));
    }
    
    @Test
    public void testVerifyServicePublicKeysValidKeysOnly() {
        ServiceIdentity service = createServiceObject("ServiceAddDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        assertTrue(zms.verifyServicePublicKeys(service));
    }

    @Test
    public void testShouldRunDelegatedTrustCheckNullTrust() {
        assertFalse(zms.shouldRunDelegatedTrustCheck(null, "TrustDomain"));
    }
    @Test
    public void testShouldRunDelegatedTrustCheckNullTrustDomain() {
        assertTrue(zms.shouldRunDelegatedTrustCheck("TrustDomain", null));
    }
    @Test
    public void testShouldRunDelegatedTrustCheckMatch() {
        assertTrue(zms.shouldRunDelegatedTrustCheck("TrustDomain", "TrustDomain"));
    }
    @Test
    public void testShouldRunDelegatedTrustCheckNoMatch() {
        assertFalse(zms.shouldRunDelegatedTrustCheck("TrustDomain1", "TrustDomain"));
    }

    @Test
    public void testIsValidUserTokenRequestNoAuthority() {
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature");
        assertFalse(zms.isValidUserTokenRequest(principal, "user1"));
    }
    
    @Test
    public void testIsValidUserTokenRequestNotuserAuthority() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        
        assertFalse(zms.isValidUserTokenRequest(principal, "user1"));
    }
    
    @Test
    public void testIsValidUserTokenRequestNullPrincipal() {
        assertFalse(zms.isValidUserTokenRequest(null, "user1"));
    }
    
    @Test
    public void testMatchDelegatedTrustPolicyNullAssertions() {
        Policy policy = new Policy();
        assertFalse(zms.matchDelegatedTrustPolicy(policy, "testRole", "testMember", null));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionInvalidAction() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("READ");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain:*");
        assertion.setRole("domain:role.Role");

        assertFalse(zms.matchDelegatedTrustAssertion(assertion, null, null, null));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoResPatternMatchWithOutPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain:role.Role");
        assertion.setRole("domain:role.Role");

        assertFalse(zms.matchDelegatedTrustAssertion(assertion, "domain:role.Role2", null, null));
        assertFalse(zms.matchDelegatedTrustAssertion(assertion, "coretech:role.Role", null, null));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoResPatternMatchWithPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("domain:role.Role");

        assertFalse(zms.matchDelegatedTrustAssertion(assertion, "domain:role.Role2", null, null));
        assertFalse(zms.matchDelegatedTrustAssertion(assertion, "coretech:role.Role2", null, null));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoRoleMatchWithPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.*");
        
        Role role = null;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("coretech",  "readers", null);
        roles.add(role);

        role = createRoleObject("coretech",  "writers", null);
        roles.add(role);

        role = createRoleObject("coretech",  "updaters", null);
        roles.add(role);
        
        assertFalse(zms.matchDelegatedTrustAssertion(assertion, "coretech:role.Role", null, roles));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoRoleMatchWithOutPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.Role");
        
        Role role = null;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("coretech",  "Role1", null);
        roles.add(role);

        role = createRoleObject("coretech",  "Role2", null);
        roles.add(role);
        
        assertFalse(zms.matchDelegatedTrustAssertion(assertion, "weather:role.Role1", null, roles));
        assertFalse(zms.matchDelegatedTrustAssertion(assertion, "coretech:role.Role", null, roles));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoMemberMatch() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.Role");
        
        Role role = null;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("weather",  "Role1", null, "user.user1", null);
        roles.add(role);

        role = createRoleObject("weather",  "Role", null, "user.user2", null);
        roles.add(role);
        
        assertFalse(zms.matchDelegatedTrustAssertion(assertion, "weather:role.Role", "user.user1", roles));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionValidWithPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.*");
        
        Role role = null;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("weather",  "Role1", null, "user.user1", null);
        roles.add(role);

        role = createRoleObject("weather",  "Role", null, "user.user2", null);
        roles.add(role);
        
        assertTrue(zms.matchDelegatedTrustAssertion(assertion, "weather:role.Role", "user.user2", roles));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionValidWithOutPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.Role");
        
        Role role = null;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("weather",  "Role1", null, "user.user1", null);
        roles.add(role);

        role = createRoleObject("weather",  "Role", null, "user.user2", null);
        roles.add(role);
        
        assertTrue(zms.matchDelegatedTrustAssertion(assertion, "weather:role.Role", "user.user2", roles));
    }
    
    @Test
    public void testMatchPrincipalInRoleStdMemberMatch() {
        
        Role role = createRoleObject("weather",  "Role", null, "user.user2", null);
        assertTrue(zms.matchPrincipalInRole(role, null, "user.user2", null));
    }
    
    @Test
    public void testMatchPrincipalInRoleStdMemberNoMatch() {
        
        Role role = createRoleObject("weather",  "Role", null, "user.user2", null);
        assertFalse(zms.matchPrincipalInRole(role, null, "user.user23", null));
    }
    
    @Test
    public void testMatchPrincipalInRoleNoDelegatedTrust() {
        Role role = createRoleObject("weather",  "Role", null);
        assertFalse(zms.matchPrincipalInRole(role, null, null, null));
        assertFalse(zms.matchPrincipalInRole(role, null, null, "weather"));
    }
    
    @Test
    public void testMatchPrincipalInRoleDelegatedTrustNoMatch() {
        Role role = createRoleObject("weather",  "Role", "coretech_not_present");
        assertFalse(zms.matchPrincipalInRole(role, "Role", "user.user1", "coretech_not_present"));
    }

    @Test
    public void testMatchPrincipalInRoleDelegatedTrustMatch() {

        String domainName = "coretechtrust";
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add("user.user2");
        zms.dbService.makeDomain(mockDomRsrcCtx, domainName, "Test Domain", "org",
                true, adminUsers, null, 0, null, null, auditRef);

        Policy policy = createPolicyObject(domainName, "trust", "coretechtrust:role.role1",
                false, "ASSUME_ROLE", "weather:role.role1", AssertionEffect.ALLOW);
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, "trust",
                policy, auditRef, "unitTest");
        
        Role role1 = createRoleObject(domainName,  "role1", null, "user.user1", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1",
                role1, auditRef, "unittest");

        Role role2 = createRoleObject(domainName,  "role2", null, "user.user2", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2",
                role2, auditRef, "unittest");
        
        Role role = createRoleObject("weather",  "role1", domainName);
        assertTrue(zms.matchPrincipalInRole(role, "weather:role.role1", "user.user1", "coretechtrust"));
        assertFalse(zms.matchPrincipalInRole(role, "weather:role.role1", "user.user1", "coretechtrust2"));
        assertFalse(zms.matchPrincipalInRole(role, "weather:role.role1", "user.user3", "coretechtrust"));
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "unittest");
    }
    
    @Test
    public void testProcessListRequestNoCollection() {
        
        String domainName = "listrequest";
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add("user.user");
        zms.dbService.makeDomain(mockDomRsrcCtx, domainName, "Test Domain", "org",
                true, adminUsers, null, 0, null, null, auditRef);
        
        Role role1 = createRoleObject(domainName,  "role1", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1",
                role1, auditRef, "unittest");

        Role role2 = createRoleObject(domainName,  "role2", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2",
                role2, auditRef, "unittest");
        
        Role role3 = createRoleObject(domainName,  "role3", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3",
                role3, auditRef, "unittest");
        
        zms.dbService.executeDeletePolicy(mockDomRsrcCtx, domainName, "admin", auditRef, "unittest");
        
        List<String> names = new ArrayList<>();
        assertNull(zms.processListRequest(domainName, AthenzObject.POLICY, null, null, names));
        assertEquals(names.size(), 0);
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "unittest");
    }
    
    @Test
    public void testProcessListRequestCollectionEmpty() {
        
        String domainName = "listrequest";
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add("user.user");
        zms.dbService.makeDomain(mockDomRsrcCtx, domainName, "Test Domain", "org",
                true, adminUsers, null, 0, null, null, auditRef);
        
        zms.dbService.executeDeleteRole(mockDomRsrcCtx, domainName, "admin", auditRef, "unittest");
        
        List<String> names = new ArrayList<>();
        assertNull(zms.processListRequest(domainName, AthenzObject.ROLE, null, null, names));
        assertEquals(names.size(), 0);
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "unittest");
    }
    
    @Test
    public void testProcessListRequestUnknownType() {
        
        List<String> names = new ArrayList<>();
        assertNull(zms.processListRequest("testdomain", AthenzObject.ASSERTION, null, null, names));
        assertEquals(names.size(), 0);
    }
    
    @Test
    public void testProcessListRequestSkipNoMatch() {
        
        String domainName = "listrequestskipnomatch";
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add("user.user");
        zms.dbService.makeDomain(mockDomRsrcCtx, domainName, "Test Domain", "org",
                true, adminUsers, null, 0, null, null, auditRef);
        
        Role role1 = createRoleObject(domainName,  "role1", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1",
                role1, auditRef, "unittest");

        Role role2 = createRoleObject(domainName,  "role2", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2",
                role2, auditRef, "unittest");
        
        Role role3 = createRoleObject(domainName,  "role3", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3",
                role3, auditRef, "unittest");
        
        List<String> names = new ArrayList<>();
        assertNull(zms.processListRequest(domainName, AthenzObject.ROLE, null, "role4", names));
        
        // our response is going to get the admin role
        
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("role1"));
        assertTrue(names.contains("role2"));
        assertTrue(names.contains("role3"));
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "unittest");
    }
    
    @Test
    public void testProcessListRequestSkipMatch() {
        
        String domainName = "listrequestskipmatch";
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add("user.user");
        zms.dbService.makeDomain(mockDomRsrcCtx, domainName, "Test Domain", "org",
                true, adminUsers, null, 0, null, null, auditRef);
        
        Role role1 = createRoleObject(domainName,  "role1", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1",
                role1, auditRef, "unittest");

        Role role2 = createRoleObject(domainName,  "role2", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2",
                role2, auditRef, "unittest");
        
        Role role3 = createRoleObject(domainName,  "role3", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3",
                role3, auditRef, "unittest");
        
        List<String> names = new ArrayList<>();
        assertNull(zms.processListRequest(domainName, AthenzObject.ROLE, null, "role2", names));
        assertEquals(names.size(), 1);
        assertTrue(names.contains("role3"));
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "unittest");
    }
    
    @Test
    public void testProcessListRequestLimitExceeded() {
        
        String domainName = "listrequestlimitexceeded";
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add("user.user");
        zms.dbService.makeDomain(mockDomRsrcCtx, domainName, "Test Domain", "org",
                true, adminUsers, null, 0, null, null, auditRef);
        
        Role role1 = createRoleObject(domainName,  "role1", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1",
                role1, auditRef, "unittest");

        Role role2 = createRoleObject(domainName,  "role2", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2",
                role2, auditRef, "unittest");
        
        Role role3 = createRoleObject(domainName,  "role3", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3",
                role3, auditRef, "unittest");
        
        List<String> names = new ArrayList<>();
        String next = zms.processListRequest(domainName, AthenzObject.ROLE, 2, null, names);
        assertEquals("role1", next);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("role1"));
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "unittest");
    }
    
    @Test
    public void testProcessListRequestLimitNotExceeded() {

        String domainName = "listrequestlimitnotexceeded";
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add("user.user");
        zms.dbService.makeDomain(mockDomRsrcCtx, domainName, "Test Domain", "org",
                true, adminUsers, null, 0, null, null, auditRef);
        
        Role role1 = createRoleObject(domainName,  "role1", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1",
                role1, auditRef, "unittest");

        Role role2 = createRoleObject(domainName,  "role2", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2",
                role2, auditRef, "unittest");
        
        Role role3 = createRoleObject(domainName,  "role3", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3",
                role3, auditRef, "unittest");
        
        List<String> names = new ArrayList<>();
        zms.processListRequest(domainName, AthenzObject.ROLE, 5, null, names);
        
        // make sure to account for the admin role
        
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("role1"));
        assertTrue(names.contains("role2"));
        assertTrue(names.contains("role3"));
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "unittest");
    }
    
    @Test
    public void testProcessListRequestLimitAndSkip() {
        
        String domainName = "listrequestlimitandskip";
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add("user.user");
        zms.dbService.makeDomain(mockDomRsrcCtx, domainName, "Test Domain", "org",
                true, adminUsers, null, 0, null, null, auditRef);
        
        Role role1 = createRoleObject(domainName,  "role1", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1",
                role1, auditRef, "unittest");

        Role role2 = createRoleObject(domainName,  "role2", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2",
                role2, auditRef, "unittest");
        
        Role role3 = createRoleObject(domainName,  "role3", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3",
                role3, auditRef, "unittest");
        
        Role role4 = createRoleObject(domainName,  "role4", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role4",
                role4, auditRef, "unittest");
        
        Role role5 = createRoleObject(domainName,  "role5", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role5",
                role5, auditRef, "unittest");
        
        List<String> names = new ArrayList<>();
        String next = zms.processListRequest(domainName, AthenzObject.ROLE, 2, "role2", names);
        assertEquals(next, "role4");
        assertEquals(names.size(), 2);
        assertTrue(names.contains("role3"));
        assertTrue(names.contains("role4"));
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "unittest");
    }
    
    @Test
    public void testProcessListRequestLimitAndSkipLessThanLimitLeft() {
        
        String domainName = "listrequestlimitskiplessthanlimitleft";
        List<String> adminUsers = new ArrayList<>();
        adminUsers.add("user.user");
        zms.dbService.makeDomain(mockDomRsrcCtx, domainName, "Test Domain", "org",
                true, adminUsers, null, 0, null, null, auditRef);
        
        Role role1 = createRoleObject(domainName,  "role1", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1",
                role1, auditRef, "unittest");

        Role role2 = createRoleObject(domainName,  "role2", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2",
                role2, auditRef, "unittest");
        
        Role role3 = createRoleObject(domainName,  "role3", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3",
                role3, auditRef, "unittest");
        
        Role role4 = createRoleObject(domainName,  "role4", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role4",
                role4, auditRef, "unittest");
        
        Role role5 = createRoleObject(domainName,  "role5", null, "user.user", null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role5",
                role5, auditRef, "unittest");
        
        List<String> names = new ArrayList<>();
        assertNull(zms.processListRequest(domainName, AthenzObject.ROLE, 2, "role4", names));
        assertEquals(names.size(), 1);
        assertTrue(names.contains("role5"));
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "unittest");
    }
    
    @Test
    public void testAccessInvalidResourceDomain() {
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature");
        try {
            zms.access("read", "domain:invalid:entity", principal, null);
            fail();
        } catch (com.yahoo.athenz.common.server.rest.ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }
    
    @Test
    public void testHasAccessInvalidRoleTokenAccess() {

        final String domainName = "coretech";
        TopLevelDomain dom = createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);
        
        List<String> authRoles = new ArrayList<>();
        authRoles.add("role1");
        Principal principal = SimplePrincipal.create(domainName, "v=U1;d=user;n=user1;s=signature", authRoles, null);
        AthenzDomain domain = zms.retrieveAccessDomain(domainName, principal);
        assertEquals(zms.hasAccess(domain, "read", domainName + ":entity", principal, "trustdomain"),
                AccessStatus.DENIED_INVALID_ROLE_TOKEN);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testAccessNotFoundDomain() {
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature");
        try {
            zms.access("read", "domain_not_found:entity", principal, null);
            fail();
        } catch (com.yahoo.athenz.common.server.rest.ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }
    
    @Test
    public void testHasAccessValidMember() {

        TopLevelDomain dom1 = createTopLevelDomainObject("HasAccessDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("HasAccessDom1", "Role1", null, "user.user1",
                "user.user3");
        zms.putRole(mockDomRsrcCtx, "HasAccessDom1", "Role1", auditRef, role1);

        Policy policy1 = createPolicyObject("HasAccessDom1", "Policy1", "Role1",
                "UPDATE", "HasAccessDom1:resource1", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "HasAccessDom1", "Policy1", auditRef, policy1);

        // user1 and user3 have access to UPDATE/resource1

        Principal principal1 = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature");
        AthenzDomain domain = zms.retrieveAccessDomain("hasaccessdom1", principal1);

        assertEquals(zms.hasAccess(domain, "update", "hasaccessdom1:resource1",
                principal1, null), AccessStatus.ALLOWED);
        
        Principal principal3 = SimplePrincipal.create("user", "user3", "v=U1;d=user;n=user3;s=signature");
        assertEquals(zms.hasAccess(domain, "update", "hasaccessdom1:resource1",
                principal3, null), AccessStatus.ALLOWED);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "HasAccessDom1", auditRef);
    }
    
    @Test
    public void testHasAccessInValidMember() {

        TopLevelDomain dom1 = createTopLevelDomainObject("HasAccessDom2",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject("HasAccessDom2", "Role1", null, "user.user1",
                "user.user3");
        zms.putRole(mockDomRsrcCtx, "HasAccessDom2", "Role1", auditRef, role1);

        Policy policy1 = createPolicyObject("HasAccessDom2", "Policy1", "Role1",
                "UPDATE", "HasAccessDom2:resource1", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, "HasAccessDom2", "Policy1", auditRef, policy1);

        // user2 does not have access to UPDATE/resource1

        Principal principal2 = SimplePrincipal.create("user", "user2", "v=U1;d=user;n=user2;s=signature");
        
        // this is internal zms function so the values passed have already been converted to lower
        // case so we need to handle the test case accordingly.
        
        AthenzDomain domain = zms.retrieveAccessDomain("hasaccessdom2", principal2);
        assertEquals(AccessStatus.DENIED, zms.hasAccess(domain, "update",
                "hasaccessdom2:resource1", principal2, null));
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "HasAccessDom2", auditRef);
    }
    
    @Test
    public void testEvaluateAccessNoAssertions() {
        
        AthenzDomain domain = new AthenzDomain("coretech");
        Role role = new Role().setName("coretech:role.role1");
        domain.getRoles().add(role);
        Policy policy = new Policy().setName("coretech:policy.policy1");
        domain.getPolicies().add(policy);
        assertEquals(zms.evaluateAccess(domain, null, null, null, null, null), AccessStatus.DENIED);
    }
    
    @Test
    public void testEvaluateAccessAssertionDeny() {
        
        AthenzDomain domain = new AthenzDomain("coretech");
        Role role = createRoleObject("coretech", "role1", null, "user.user1", null);
        domain.getRoles().add(role);

        Policy policy = new Policy().setName("coretech:policy.policy1");
        Assertion assertion = new Assertion();
        assertion.setAction("read");
        assertion.setEffect(AssertionEffect.DENY);
        assertion.setResource("coretech:*");
        assertion.setRole("coretech:role.role1");
        policy.setAssertions(new ArrayList<Assertion>());
        policy.getAssertions().add(assertion);
        domain.getPolicies().add(policy);
        
        assertEquals(zms.evaluateAccess(domain, "user.user1", "read", "coretech:resource1",
                null, null), AccessStatus.DENIED);
    }
    
    @Test
    public void testEvaluateAccessAssertionAllow() {
        
        AthenzDomain domain = new AthenzDomain("coretech");
        Role role = createRoleObject("coretech", "role1", null, "user.user1", null);
        domain.getRoles().add(role);

        Policy policy = new Policy().setName("coretech:policy.policy1");
        Assertion assertion = new Assertion();
        assertion.setAction("read");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("coretech:*");
        assertion.setRole("coretech:role.role1");
        policy.setAssertions(new ArrayList<Assertion>());
        policy.getAssertions().add(assertion);
        domain.getPolicies().add(policy);
        
        assertEquals(zms.evaluateAccess(domain, "user.user1", "read", "coretech:resource1", null, null), AccessStatus.ALLOWED);
    }
    
    @Test
    public void testHasExceededDepthLimitNullLimit() {
        assertFalse(zms.hasExceededDepthLimit(null, "domain"));
    }
    
    @Test
    public void testHasExceededDepthLimitNotValidLimit() {
        assertTrue(zms.hasExceededDepthLimit(-1, "domain"));
        assertTrue(zms.hasExceededDepthLimit(-1, "domain.sub1"));
    }
    
    @Test
    public void testHasExceededDepthLimitYes() {
        assertTrue(zms.hasExceededDepthLimit(0, "domain.sub1"));
        assertTrue(zms.hasExceededDepthLimit(1, "domain.sub1.sub2"));
        assertTrue(zms.hasExceededDepthLimit(1, "domain.sub1.sub2.sub3"));
        assertTrue(zms.hasExceededDepthLimit(2, "domain.sub1.sub2.sub3"));
    }
    
    @Test
    public void testHasExceededDepthLimitNo() {
        assertFalse(zms.hasExceededDepthLimit(1, "domain.sub1"));
        assertFalse(zms.hasExceededDepthLimit(2, "domain.sub1"));
        assertFalse(zms.hasExceededDepthLimit(2, "domain.sub1.sub2"));
        assertFalse(zms.hasExceededDepthLimit(3, "domain.sub1.sub2"));
        assertFalse(zms.hasExceededDepthLimit(3, "domain.sub1.sub2.sub3"));
        assertFalse(zms.hasExceededDepthLimit(4, "domain.sub1.sub2.sub3"));
    }

    @Test
    public void testIsZMSServiceYes() {
        
        assertTrue(zms.isZMSService("sys.auth", "zms"));
        assertTrue(zms.isZMSService("sys.Auth", "ZMS"));
        assertTrue(zms.isZMSService("SYS.AUTH", "ZMS"));
    }
    
    @Test
    public void testIsZMSServiceNo() {
        
        assertFalse(zms.isZMSService("sys.auth2", "zms"));
        assertFalse(zms.isZMSService("sys.auth", "zts"));
    }
    
    @Test
    public void testRetrieveServiceIdentityInvalidServiceName() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceRetrieveDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceRetrieveDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceRetrieveDom1", "Service1", auditRef, service);

        try {
            zms.getServiceIdentity(mockDomRsrcCtx, "ServiceRetrieveDom1", "Service");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        try {
            zms.getServiceIdentity(mockDomRsrcCtx, "ServiceRetrieveDom1", "Service2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        try {
            zms.getServiceIdentity(mockDomRsrcCtx, "ServiceRetrieveDom1", "Service11");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceRetrieveDom1", auditRef);
    }
    
    @Test
    public void testRetriveServiceIdentityValid() {
        
        String domainName = "serviceretrievedom2";
        String serviceName = "service1";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "Service1", auditRef, service);

        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getProviderEndpoint().toString(), "http://localhost");
        assertEquals(serviceRes.getUser(), "root");

        List<String> hosts = serviceRes.getHosts();
        assertNotNull(hosts);
        assertEquals(hosts.size(), 1);
        assertEquals(hosts.get(0), "host1");

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetProviderRoleActionPolicyNotFound() {
        
        String domainName = "coretech";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Assertion assertion = new Assertion();
        assertion.setAction("read");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("coretech:*");
        assertion.setRole("coretech:role.role1");

        Policy policy = new Policy().setName("coretech:policy.provider");
        policy.setAssertions(new ArrayList<Assertion>());
        policy.getAssertions().add(assertion);
        
        zms.putPolicy(mockDomRsrcCtx, domainName, "provider", auditRef, policy);

        assertEquals(zms.getProviderRoleAction(domainName, "policy1"), "");
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetProviderRoleActionAssertionNoMatch() {
        
        String domainName = "coretech";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Assertion assertion = new Assertion();
        assertion.setAction("read");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("coretech:*");
        assertion.setRole("coretech:role.role1");

        Policy policy = new Policy().setName("coretech:policy.provider");
        policy.setAssertions(new ArrayList<Assertion>());
        policy.getAssertions().add(assertion);
        
        zms.putPolicy(mockDomRsrcCtx, domainName, "provider", auditRef, policy);

        assertEquals(zms.getProviderRoleAction(domainName, "provider"), "");
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetProviderRoleActionAssertionActionNull() {
        
        String domainName = "coretech";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        Assertion assertion = new Assertion();
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("coretech:*");
        assertion.setRole("coretech:role.provider");
        
        Policy policy = new Policy().setName("coretech:policy.provider");
        policy.setAssertions(new ArrayList<Assertion>());
        policy.getAssertions().add(assertion);
        
        try {
            zms.putPolicy(mockDomRsrcCtx, domainName, "provider", auditRef, policy);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        assertEquals(zms.getProviderRoleAction(domainName, "provider"), "");
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetProviderRoleActionValid() {
        
        String domainName = "coretech";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        Assertion assertion = new Assertion();
        assertion.setAction("read");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("coretech:*");
        assertion.setRole("coretech:role.provider");
        
        Policy policy = new Policy().setName("coretech:policy.provider");
        policy.setAssertions(new ArrayList<Assertion>());
        policy.getAssertions().add(assertion);
        
        zms.putPolicy(mockDomRsrcCtx, domainName, "provider", auditRef, policy);
        
        assertEquals(zms.getProviderRoleAction(domainName, "provider"), "read");
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testListDomains() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ListDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("ListDom2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        DomainList domList = zms.listDomains(null, null, null, null, 0);
        assertNotNull(domList);

        assertTrue(domList.getNames().contains("ListDom1".toLowerCase()));
        assertTrue(domList.getNames().contains("ListDom2".toLowerCase()));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDom2", auditRef);
    }

    @Test
    public void testListDomainsParamsLimit() {

        TopLevelDomain dom1 = createTopLevelDomainObject("LimitDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("LimitDom2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        DomainList domList = zms.listDomains(1, null, null, null, 0);
        assertTrue(domList.getNames().size() == 1);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "LimitDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "LimitDom2", auditRef);
    }

    @Test
    public void testListDomainsParamsSkip() {

        TopLevelDomain dom1 = createTopLevelDomainObject("SkipDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("SkipDom2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        TopLevelDomain dom3 = createTopLevelDomainObject("SkipDom3",
                "Test Domain3", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom3);

        DomainList domList = zms.listDomains(null, null, null, null, 0);
        int size = domList.getNames().size();
        assertTrue(size > 3);

        // ask for only for 2 domains back
        domList = zms.listDomains(2, null, null, null, 0);
        assertEquals(domList.getNames().size(), 2);

        // ask for the remaining domains
        DomainList remList = zms.listDomains(null, domList.getNext(), null, null, 0);
        assertEquals(remList.getNames().size(), size - 2);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "SkipDom1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "SkipDom2", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "SkipDom3", auditRef);
    }

    @Test
    public void testListDomainsParamsPrefix() {

        String noPrefixDom = "noprefixdom1";
        String prefixDom = "prefixdom2";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(noPrefixDom,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject(prefixDom,
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        DomainList domList = zms.listDomains(null, null, "prefix", null, 0);

        assertFalse(domList.getNames().contains(noPrefixDom));
        assertTrue(domList.getNames().contains(prefixDom));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, noPrefixDom, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, prefixDom, auditRef);
    }

    @Test
    public void testListDomainsParamsDepth() {

        TopLevelDomain dom1 = createTopLevelDomainObject("DepthDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        SubDomain dom2 = createSubDomainObject("DepthDom2", "DepthDom1",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "DepthDom1", auditRef, dom2);

        SubDomain dom3 = createSubDomainObject("DepthDom3",
                "DepthDom1.DepthDom2", "Test Domain3", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "DepthDom1.DepthDom2", auditRef, dom3);

        DomainList domList = zms.listDomains(null, null, null, 1, 0);

        assertTrue(domList.getNames().contains("DepthDom1".toLowerCase()));
        assertTrue(domList.getNames().contains("DepthDom1.DepthDom2".toLowerCase()));
        assertFalse(domList.getNames().contains("DepthDom1.DepthDom2.DepthDom3".toLowerCase()));

        zms.deleteSubDomain(mockDomRsrcCtx, "DepthDom1.DepthDom2", "DepthDom3", auditRef);
        zms.deleteSubDomain(mockDomRsrcCtx, "DepthDom1", "DepthDom2", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "DepthDom1", auditRef);
    }
    
    @Test
    public void testListModifiedDomains() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ListDomMod1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("ListDomMod2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        DomainModifiedList domModList = zms.dbService.listModifiedDomains(0);
        assertNotNull(domModList);
        assertTrue(domModList.getNameModList().size() > 1);

        boolean dom1Found = false;
        boolean dom2Found = false;
        for (DomainModified domName : domModList.getNameModList()) {
            if (domName.getName().equalsIgnoreCase("ListDomMod1")) {
                dom1Found = true;
            } else if (domName.getName().equalsIgnoreCase("ListDomMod2")) {
                dom2Found = true;
            }
        }

        assertTrue(dom1Found);
        assertTrue(dom2Found);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDomMod1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDomMod2", auditRef);
    }

    @Test
    public void testListModifiedDomainsMillis() {

        long timestamp = System.currentTimeMillis() - 1001;

        TopLevelDomain dom1 = createTopLevelDomainObject("ListDomMod1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("ListDomMod2",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);

        DomainModifiedList domModList = zms.dbService.listModifiedDomains(timestamp);
        assertNotNull(domModList);
        assertTrue(domModList.getNameModList().size() > 1);

        boolean dom1Found = false;
        boolean dom2Found = false;
        for (DomainModified domName : domModList.getNameModList()) {
            if (domName.getName().equalsIgnoreCase("ListDomMod1")) {
                dom1Found = true;
            } else if (domName.getName().equalsIgnoreCase("ListDomMod2")) {
                dom2Found = true;
            }
        }

        assertTrue(dom1Found);
        assertTrue(dom2Found);

        timestamp += 10000; // add 10 seconds
        domModList = zms.dbService.listModifiedDomains(timestamp);
        assertNotNull(domModList);
        assertTrue(domModList.getNameModList().size() == 0);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDomMod1", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ListDomMod2", auditRef);
    }
    
    @Test
    public void testVirtualHomeDomain() {
        
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        
        AthenzDomain virtualDomain = zms.virtualHomeDomain(principal, "user.user1");
        assertNotNull(virtualDomain);
        
        List<Role> roles = virtualDomain.getRoles();
        assertNotNull(roles);
        Role adminRole = null;
        for (Role role : roles) {
            if (role.getName().equals("user.user1:role.admin")) {
                adminRole = role;
                break;
            }
        }
        assertNotNull(adminRole);
        List<RoleMember> roleMembers = adminRole.getRoleMembers();
        assertEquals(roleMembers.size(), 1);
        assertEquals(roleMembers.get(0).getMemberName(), "user.user1");
        
        List<Policy> policies = virtualDomain.getPolicies();
        assertNotNull(policies);
        Policy adminPolicy = null;
        for (Policy policy : policies) {
            if (policy.getName().equals("user.user1:policy.admin")) {
                adminPolicy = policy;
                break;
            }
        }
        assertNotNull(adminPolicy);
    }

    @Test
    public void testVirtualHomeDomainDifferentUserHome() {
        
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        
        Principal principal = SimplePrincipal.create("user", "john.smith", "v=U1;d=user;n=john.smith;s=signature",
                0, principalAuthority);
        
        AthenzDomain virtualDomain = zms.virtualHomeDomain(principal, "home.john-smith");
        assertNotNull(virtualDomain);
        
        List<Role> roles = virtualDomain.getRoles();
        assertNotNull(roles);
        Role adminRole = null;
        for (Role role : roles) {
            if (role.getName().equals("home.john-smith:role.admin")) {
                adminRole = role;
                break;
            }
        }
        assertNotNull(adminRole);
        List<RoleMember> roleMembers = adminRole.getRoleMembers();
        assertEquals(roleMembers.size(), 1);
        assertEquals(roleMembers.get(0).getMemberName(), "user.john.smith");
        
        List<Policy> policies = virtualDomain.getPolicies();
        assertNotNull(policies);
        Policy adminPolicy = null;
        for (Policy policy : policies) {
            if (policy.getName().equals("home.john-smith:policy.admin")) {
                adminPolicy = policy;
                break;
            }
        }
        assertNotNull(adminPolicy);
    }
    
    @Test
    public void testDeletePublicKeyEntry() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceDelPubKeyDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceDelPubKeyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceDelPubKeyDom1", "Service1", auditRef, service);

        zms.deletePublicKeyEntry(mockDomRsrcCtx, "ServiceDelPubKeyDom1", "Service1", "1", auditRef);
        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, "ServiceDelPubKeyDom1", "Service1");
        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        boolean found = false;
        for (PublicKeyEntry entry : keyList) {
            if (entry.getId().equals("1")) {
                found = true;
            }
        }
        assertFalse(found);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceDelPubKeyDom1", auditRef);
    }
 
    @Test
    public void testDeletePublicKeyEntryMissingAuditRef() {
        String domain = "testDeletePublicKeyEntryMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        ServiceIdentity service = createServiceObject(
            domain,
            "Service1", "http://localhost", "/usr/bin/java", "root",
            "users", "host1");
        zms.putServiceIdentity(mockDomRsrcCtx, domain, "Service1", auditRef, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey(pubKeyK2);
        zms.putPublicKeyEntry(mockDomRsrcCtx, domain, "Service1", "zone1", auditRef, keyEntry);
        try {
            zms.deletePublicKeyEntry(mockDomRsrcCtx, domain, "Service1", "1", null);
            fail("requesterror not thrown by deletePublicKeyEntry.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }

    @Test
    public void testDeletePublicKeyEntryDomainNotFound() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceDelPubKeyDom2",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceDelPubKeyDom2",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceDelPubKeyDom2", "Service1", auditRef, service);

        // this should throw a not found exception
        try {
            zms.deletePublicKeyEntry(mockDomRsrcCtx, "UnknownPublicKeyDomain", "Service1", "1", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceDelPubKeyDom2", auditRef);
    }
    
    @Test
    public void testDeletePublicKeyEntryInvalidService() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_delpubkeyinvalidsvc";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceDelPubKeyDom2InvalidService",
                "Test Domain1", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceDelPubKeyDom2InvalidService",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(mockDomRsrcCtx, "ServiceDelPubKeyDom2InvalidService",
                "Service1", auditRef, service);

        // this should throw an invalid request exception
        try {
            zmsImpl.deletePublicKeyEntry(mockDomRsrcCtx, "ServiceDelPubKeyDom2InvalidService",
                    "Service1.Service2", "1", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceDelPubKeyDom2InvalidService", auditRef);
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testDeletePublicKeyEntryServiceNotFound() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceDelPubKeyDom3",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceDelPubKeyDom3",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceDelPubKeyDom3", "Service1", auditRef, service);

        // this should throw a not found exception
        try {
            zms.deletePublicKeyEntry(mockDomRsrcCtx, "ServiceDelPubKeyDom3", "ServiceNotFound", "1", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceDelPubKeyDom3", auditRef);
    }
    
    @Test
    public void testDeletePublicKeyEntryIdNotFound() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceDelPubKeyDom4",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServiceDelPubKeyDom4",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServiceDelPubKeyDom4", "Service1", auditRef, service);

        // process invalid keys
        
        try {
            zms.deletePublicKeyEntry(mockDomRsrcCtx, "ServiceDelPubKeyDom4", "Service1", "zone", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        // make sure both 1 and 2 keys are still valid
        
        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, "ServiceDelPubKeyDom4", "Service1");
        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        boolean foundKey1 = false;
        boolean foundKey2 = false;
        for (PublicKeyEntry entry : keyList) {
            if (entry.getId().equals("1")) {
                foundKey1 = true;
            } else if (entry.getId().equals("2")) {
                foundKey2 = true;
            }
        }
        assertTrue(foundKey1);
        assertTrue(foundKey2);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceDelPubKeyDom4", auditRef);
    }
    
    @Test
    public void testGetPublicKeyEntry() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePubKeyDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePubKeyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePubKeyDom1", "Service1", auditRef, service);

        PublicKeyEntry entry = zms.getPublicKeyEntry(mockDomRsrcCtx, "ServicePubKeyDom1", "Service1", "1");
        assertNotNull(entry);
        assertEquals(entry.getId(), "1");
        assertEquals(entry.getKey(), pubKeyK1);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePubKeyDom1", auditRef);
    }
    
    @Test
    public void testGetPublicKeyEntryInvalidService() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePubKeyDom2Invalid",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePubKeyDom2Invalid",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePubKeyDom2Invalid", "Service1", auditRef, service);

        // this should throw an invalid request exception
        try {
            zms.getPublicKeyEntry(mockDomRsrcCtx, "ServicePubKeyDom2Invalid", "Service1.Service2", "1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePubKeyDom2Invalid", auditRef);
    }
    
    @Test
    public void testGetPublicKeyEntryDomainNotFound() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePubKeyDom2",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePubKeyDom2",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePubKeyDom2", "Service1", auditRef, service);

        // this should throw a not found exception
        try {
            zms.getPublicKeyEntry(mockDomRsrcCtx, "UnknownPublicKeyDomain", "Service1", "1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePubKeyDom2", auditRef);
    }
    
    @Test
    public void testGetPublicKeyEntryServiceNotFound() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePubKeyDom3",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePubKeyDom3",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePubKeyDom3", "Service1", auditRef, service);

        // this should throw a not found exception
        try {
            zms.getPublicKeyEntry(mockDomRsrcCtx, "ServicePubKeyDom3", "ServiceNotFound", "1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePubKeyDom3", auditRef);
    }
    
    @Test
    public void testGetPublicKeyEntryIdNotFound() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePubKeyDom4",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePubKeyDom4",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePubKeyDom4", "Service1", auditRef, service);

        // this should throw a not found exception
        try {
            zms.getPublicKeyEntry(mockDomRsrcCtx, "ServicePubKeyDom4", "Service1", "zone");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePubKeyDom4", auditRef);
    }
    
    @Test
    public void testPutPublicKeyEntryNew() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePutPubKeyDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePutPubKeyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePutPubKeyDom1", "Service1", auditRef, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey(pubKeyK2);
        
        zms.putPublicKeyEntry(mockDomRsrcCtx, "ServicePutPubKeyDom1", "Service1", "zone1", auditRef, keyEntry);
        
        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, "ServicePutPubKeyDom1", "Service1");
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
        
        PublicKeyEntry entry = zms.getPublicKeyEntry(mockDomRsrcCtx, "ServicePutPubKeyDom1", "Service1", "zone1");
        assertNotNull(entry);
        assertEquals(entry.getId(), "zone1");
        assertEquals(entry.getKey(), pubKeyK2);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePutPubKeyDom1", auditRef);
    }

    @Test
    public void testPutPublicKeyEntryMissingAuditRef() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_putpubkeyentrymissauditref";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String domain = "testPutPublicKeyEntryMissingAuditRef";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        ServiceIdentity service = createServiceObject(
            domain,
            "Service1", "http://localhost", "/usr/bin/java", "root",
            "users", "host1");
        zmsImpl.putServiceIdentity(mockDomRsrcCtx, domain, "Service1", auditRef, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey(pubKeyK2);
        
        try {
            zmsImpl.putPublicKeyEntry(mockDomRsrcCtx, domain, "Service1", "zone1", null, keyEntry);
            fail("requesterror not thrown by putPublicKeyEntry.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
            FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
        }
    }

    @Test
    public void testPutPublicKeyEntryInvalidService() {
        
        String domain = "testPutPublicKeyEntryInvalidService";
        TopLevelDomain dom = createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        ServiceIdentity service = createServiceObject(
            domain,
            "Service1", "http://localhost", "/usr/bin/java", "root",
            "users", "host1");
        zms.putServiceIdentity(mockDomRsrcCtx, domain, "Service1", auditRef, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey(pubKeyK2);
        
        try {
            zms.putPublicKeyEntry(mockDomRsrcCtx, domain, "Service1.Service2", "zone1", null, keyEntry);
            fail("requesterror not thrown by putPublicKeyEntry.");
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == 400);
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef);
        }
    }
    
    @Test
    public void testPutPublicKeyEntryUpdate() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePutPubKeyDom1A",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePutPubKeyDom1A",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePutPubKeyDom1A", "Service1", auditRef, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("1");
        keyEntry.setKey(pubKeyK2);
        
        zms.putPublicKeyEntry(mockDomRsrcCtx, "ServicePutPubKeyDom1A", "Service1", "1", auditRef, keyEntry);
        
        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, "ServicePutPubKeyDom1A", "Service1");
        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        assertEquals(keyList.size(), 2);
        
        boolean foundKey1 = false;
        boolean foundKey2 = false;
        for (PublicKeyEntry entry : keyList) {
            if (entry.getId().equals("1")) {
                foundKey1 = true;
            } else if (entry.getId().equals("2")) {
                foundKey2 = true;
            }
        }
        
        assertTrue(foundKey1);
        assertTrue(foundKey2);
        
        PublicKeyEntry entry = zms.getPublicKeyEntry(mockDomRsrcCtx, "ServicePutPubKeyDom1A", "Service1", "1");
        assertNotNull(entry);
        assertEquals(entry.getId(), "1");
        assertEquals(entry.getKey(), pubKeyK2);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePutPubKeyDom1A", auditRef);
    }
    
    @Test
    public void testPutPublicKeyEntryDomainNotFound() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePutPubKeyDom2",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePutPubKeyDom2",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePutPubKeyDom2", "Service1", auditRef, service);

        // this should throw a not found exception
        try {
            PublicKeyEntry keyEntry = new PublicKeyEntry();
            keyEntry.setId("zone1");
            keyEntry.setKey(pubKeyK2);
            
            zms.putPublicKeyEntry(mockDomRsrcCtx, "UnknownPublicKeyDomain", "Service1", "zone1", auditRef, keyEntry);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePutPubKeyDom2", auditRef);
    }
    
    @Test
    public void testPutPublicKeyEntryServiceNotFound() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePutPubKeyDom3",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePutPubKeyDom3",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePutPubKeyDom3", "Service1", auditRef, service);

        // this should throw a not found exception
        try {
            PublicKeyEntry keyEntry = new PublicKeyEntry();
            keyEntry.setId("zone1");
            keyEntry.setKey(pubKeyK2);
            
            zms.putPublicKeyEntry(mockDomRsrcCtx, "ServicePutPubKeyDom3", "ServiceNotFound", "zone1", auditRef, keyEntry);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePutPubKeyDom3", auditRef);
    }

    @Test
    public void testDeletePublicKeyEntryIdNoMatch() {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServicePutPubKeyDom4",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service = createServiceObject("ServicePutPubKeyDom4",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, "ServicePutPubKeyDom4", "Service1", auditRef, service);

        // this should throw invalid request exception
        
        try {
            PublicKeyEntry keyEntry = new PublicKeyEntry();
            keyEntry.setId("zone1");
            keyEntry.setKey(pubKeyK2);
            
            zms.putPublicKeyEntry(mockDomRsrcCtx, "ServicePutPubKeyDom4", "Service1", "zone2", auditRef, keyEntry);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServicePutPubKeyDom4", auditRef);
    }
    
    @Test
    public void testSleepBeforeRetryingRequestExpireZero() {
        
        long timeStamp = System.currentTimeMillis();
        zms.sleepBeforeRetryingRequest(0, 2000, "testSleep");
        assertTrue(System.currentTimeMillis() - timeStamp < 1000);
    }
    
    @Test
    public void testSleepBeforeRetryingRequestExpireNegative() {
        
        long timeStamp = System.currentTimeMillis();
        zms.sleepBeforeRetryingRequest(-1, 2000, "testSleep");
        assertTrue(System.currentTimeMillis() - timeStamp < 1000);
    }
    
    @Test
    public void testSleepBeforeRetryingRequest() {
        
        long timeStamp = System.currentTimeMillis();
        zms.sleepBeforeRetryingRequest(50, 2000, "testSleep");
        
        // let's assume we'll never get interrupted
        assertTrue(System.currentTimeMillis() - timeStamp >= 2000);
    }
    
    @Test
    public void testConverToLowerCaseAssertion() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("Read");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("coreTech:VIP.*");
        assertion.setRole("coretech:role.Role1");
        
        AthenzObject.ASSERTION.convertToLowerCase(assertion);
        assertEquals(assertion.getRole(), "coretech:role.role1");
        assertEquals(assertion.getAction(), "read");
        assertEquals(assertion.getResource(), "coretech:vip.*");
    }
        
    @Test
    public void testRemoveQuotes() {
        
        assertEquals(zms.removeQuotes("abc"), "abc");
        assertEquals(zms.removeQuotes("\"abc"), "abc");
        assertEquals(zms.removeQuotes("abc\""), "abc");
        assertEquals(zms.removeQuotes("\"abc\""), "abc");
        assertEquals(zms.removeQuotes("\"a\"bc\""), "a\"bc");
    }
    
    @Test
    public void testConvertToLowerCaseList() {
        
        AthenzObject.LIST.convertToLowerCase(null);
        
        List<String> list = new ArrayList<>();
        list.add("item1");
        list.add("Item2");
        list.add("ITEM3");
        
        AthenzObject.LIST.convertToLowerCase(list);
        assertTrue(list.contains("item1"));
        assertTrue(list.contains("item2"));
        assertTrue(list.contains("item3"));
        assertEquals(list.size(), 3);
    }
    
    @Test
    public void testConvertToLowerCaseSubdomain() {
        
        SubDomain dom = createSubDomainObject("DepthDom2", "DepthDom1",
                "Test Domain2", "testOrg", "user.user3A");
        AthenzObject.SUB_DOMAIN.convertToLowerCase(dom);
        assertEquals(dom.getName(), "depthdom2");
        assertEquals(dom.getParent(), "depthdom1");
        assertTrue(dom.getAdminUsers().contains("user.user3a"));

        SubDomain dom2 = createSubDomainObject("DepthDom2", "DepthDom1",
                "Test Domain2", "testOrg", "user.user3B");
        DomainTemplateList templates = new DomainTemplateList();
        List<String> list = new ArrayList<>();
        list.add("platforms");
        list.add("vipNg");
        list.add("ATHENZ");
        templates.setTemplateNames(list);
        dom2.setTemplates(templates);
        AthenzObject.SUB_DOMAIN.convertToLowerCase(dom2);
        assertEquals(dom2.getName(), "depthdom2");
        assertEquals(dom2.getParent(), "depthdom1");
        assertTrue(dom2.getAdminUsers().contains("user.user3b"));
        templates = dom2.getTemplates();
        list = templates.getTemplateNames();
        assertEquals(3, list.size());
        assertTrue(list.contains("platforms"));
        assertTrue(list.contains("vipng"));
        assertTrue(list.contains("athenz"));
    }
    
    @Test
    public void testConvertToLowerCaseTopLeveldomain() {
        
        TopLevelDomain dom = createTopLevelDomainObject("TopLevelDomain",
                "Test Domain1", "testOrg", "user.USER3A");
        AthenzObject.TOP_LEVEL_DOMAIN.convertToLowerCase(dom);
        assertEquals(dom.getName(), "topleveldomain");
        assertTrue(dom.getAdminUsers().contains("user.user3a"));

        TopLevelDomain dom2 = createTopLevelDomainObject("TopLevelDomain",
                "Test Domain1", "testOrg", "user.USER3B");
        DomainTemplateList templates = new DomainTemplateList();
        List<String> list = new ArrayList<>();
        list.add("platforms");
        list.add("vipNg");
        list.add("ATHENZ");
        templates.setTemplateNames(list);
        dom2.setTemplates(templates);
        AthenzObject.TOP_LEVEL_DOMAIN.convertToLowerCase(dom2);
        assertEquals(dom2.getName(), "topleveldomain");
        assertTrue(dom2.getAdminUsers().contains("user.user3b"));
        templates = dom2.getTemplates();
        list = templates.getTemplateNames();
        assertEquals(3, list.size());
        assertTrue(list.contains("platforms"));
        assertTrue(list.contains("vipng"));
        assertTrue(list.contains("athenz"));
    }
    
    @Test
    public void testConvertToLowerCaseUserdomain() {
        
        UserDomain dom = createUserDomainObject("USER3A",
                "Test Domain1", "testOrg");
        AthenzObject.USER_DOMAIN.convertToLowerCase(dom);
        assertEquals(dom.getName(), "user3a");

        UserDomain dom2 = createUserDomainObject("USER3B",
                "Test Domain1", "testOrg");
        DomainTemplateList templates = new DomainTemplateList();
        List<String> list = new ArrayList<>();
        list.add("platforms");
        list.add("vipNg");
        list.add("ATHENZ");
        templates.setTemplateNames(list);
        dom2.setTemplates(templates);

        AthenzObject.USER_DOMAIN.convertToLowerCase(dom2);
        assertEquals(dom2.getName(), "user3b");
        templates = dom2.getTemplates();
        list = templates.getTemplateNames();
        assertEquals(3, list.size());
        assertTrue(list.contains("platforms"));
        assertTrue(list.contains("vipng"));
        assertTrue(list.contains("athenz"));
    }
    
    @Test
    public void testConvertToLowerCasePublicKeyEntry() {
        PublicKeyEntry keyEntry = new PublicKeyEntry().setKey("KEY").setId("ZONE1");
        AthenzObject.PUBLIC_KEY_ENTRY.convertToLowerCase(keyEntry);
        assertEquals(keyEntry.getKey(), "KEY");
        assertEquals(keyEntry.getId(), "zone1");
    }
    
    @Test
    public void testConvertToLowerCaseQuota() {
        Quota quota = new Quota().setName("UpperCaseDomain");
        AthenzObject.QUOTA.convertToLowerCase(quota);
        assertEquals(quota.getName(), "uppercasedomain");
    }
    
    @Test
    public void testConvertToLowerCaseEntity() {
        Entity entity = createEntityObject("ABcEntity");
        AthenzObject.ENTITY.convertToLowerCase(entity);
        assertEquals(entity.getName(), "abcentity");
    }
    
    @Test
    public void testConvertToLowerCaseTemplate() {
        DomainTemplate template = new DomainTemplate();
        List<String> names = new ArrayList<>();
        names.add("Burbank");
        names.add("santa_Monica");
        names.add("playa");
        template.setTemplateNames(names);
        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("Name1").setValue("value1"));
        params.add(new TemplateParam().setName("name2").setValue("Value2"));
        template.setParams(params);
        
        AthenzObject.DOMAIN_TEMPLATE.convertToLowerCase(template);
        assertEquals(template.getTemplateNames().size(), 3);
        assertTrue(template.getTemplateNames().contains("burbank"));
        assertTrue(template.getTemplateNames().contains("playa"));
        assertTrue(template.getTemplateNames().contains("santa_monica"));
        assertEquals(template.getParams().size(), 2);
        boolean param1Check = false;
        boolean param2Check = false;
        TemplateParam param1 = new TemplateParam().setName("name1").setValue("value1");
        TemplateParam param2 = new TemplateParam().setName("name2").setValue("value2");
        for (TemplateParam param : template.getParams()) {
            if (param.equals(param1)) {
                param1Check = true;
            } else if (param.equals(param2)) {
                param2Check = true;
            }
        }
        assertTrue(param1Check);
        assertTrue(param2Check);
    }
    
    @Test
    public void testConvertToLowerCaseTenancy() {
        Tenancy tenancy = createTenantObject("CoretecH", "STorage");
        List<String> groups = new ArrayList<>();
        groups.add("Burbank");
        groups.add("santa_monica");
        tenancy.setResourceGroups(groups);
        AthenzObject.TENANCY.convertToLowerCase(tenancy);
        assertEquals(tenancy.getDomain(), "coretech");
        assertEquals(tenancy.getService(), "storage");
        assertTrue(tenancy.getResourceGroups().contains("burbank"));
        assertTrue(tenancy.getResourceGroups().contains("santa_monica"));
    }
    
    @Test
    public void testConvertToLowerCaseTenancyResourceGroup() {
        TenancyResourceGroup tenancyResourceGroup = new TenancyResourceGroup();
        tenancyResourceGroup.setDomain("CoretecH").setService("STorage").setResourceGroup("Group1");
        AthenzObject.TENANCY_RESOURCE_GROUP.convertToLowerCase(tenancyResourceGroup);
        assertEquals("coretech", tenancyResourceGroup.getDomain());
        assertEquals("storage", tenancyResourceGroup.getService());
        assertEquals("group1", tenancyResourceGroup.getResourceGroup());
    }
    
    @Test
    public void testConvertToLowerCaseDefaultAdmins() {
        
        List<String> adminList = new ArrayList<String>();
        adminList.add("user.User1");
        adminList.add("user.user2");
        DefaultAdmins admins = new DefaultAdmins();
        admins.setAdmins(adminList);
        
        AthenzObject.DEFAULT_ADMINS.convertToLowerCase(admins);
        assertTrue(admins.getAdmins().contains("user.user1"));
        assertTrue(admins.getAdmins().contains("user.user2"));
    }
    
    @Test
    public void testConvertToLowerCaseTenantRolesNoActions() {

        TenantRoles tenantRoles = new TenantRoles().setDomain("coreTech")
                .setService("storaGe").setTenant("DelTenantRolesDom1");
        AthenzObject.TENANT_ROLES.convertToLowerCase(tenantRoles);
        assertEquals(tenantRoles.getDomain(), "coretech");
        assertEquals(tenantRoles.getService(), "storage");
        assertEquals(tenantRoles.getTenant(), "deltenantrolesdom1");
    }
    
    @Test
    public void testConvertToLowerCaseTenantResourceGroupRolesNoActions() {

        TenantResourceGroupRoles tenantRoles = new TenantResourceGroupRoles()
                .setDomain("coreTech").setService("storaGe")
                .setTenant("DelTenantRolesDom1").setResourceGroup("Hockey");
        AthenzObject.TENANT_RESOURCE_GROUP_ROLES.convertToLowerCase(tenantRoles);
        assertEquals(tenantRoles.getDomain(), "coretech");
        assertEquals(tenantRoles.getService(), "storage");
        assertEquals(tenantRoles.getTenant(), "deltenantrolesdom1");
        assertEquals(tenantRoles.getResourceGroup(), "hockey");
    }
    
    @Test
    public void testConvertToLowerCaseProviderResourceGroupRolesNoActions() {

        ProviderResourceGroupRoles tenantRoles = new ProviderResourceGroupRoles()
                .setDomain("coreTech").setService("storaGe")
                .setTenant("DelTenantRolesDom1").setResourceGroup("Hockey");
        AthenzObject.PROVIDER_RESOURCE_GROUP_ROLES.convertToLowerCase(tenantRoles);
        assertEquals(tenantRoles.getDomain(), "coretech");
        assertEquals(tenantRoles.getService(), "storage");
        assertEquals(tenantRoles.getTenant(), "deltenantrolesdom1");
        assertEquals(tenantRoles.getResourceGroup(), "hockey");
    }
    
    @Test
    public void testConvertToLowerCaseGroupRole() {
        Role role = createRoleObject("RoleDomain", "roleName", null, "user.USER1", "user.user2");
        AthenzObject.ROLE.convertToLowerCase(role);
        assertEquals(role.getName(), "roledomain:role.rolename");
        List<String> checkList = new ArrayList<>();
        checkList.add("user.user1");
        checkList.add("user.user2");
        checkRoleMember(checkList, role.getRoleMembers());
    }
    
    @Test
    public void testConvertToLowerCaseTrustRole() {
        Role role = createRoleObject("RoleDomain", "roleName", "TRUSTDomain");
        AthenzObject.ROLE.convertToLowerCase(role);
        assertEquals(role.getName(), "roledomain:role.rolename");
        assertEquals(role.getTrust(), "trustdomain");
    }
    
    @Test
    public void testConvertToLowerCaseMembershipWithRole() {
        Membership membership = new Membership().setMemberName("user.member1").setRoleName("ROLE1");
        AthenzObject.MEMBERSHIP.convertToLowerCase(membership);
        assertEquals(membership.getMemberName(), "user.member1");
        assertEquals(membership.getRoleName(), "role1");
    }
    
    @Test
    public void testConvertToLowerCaseRole() {
        
        Role role = new Role().setName("Role1");
        
        List<String> list = new ArrayList<>();
        list.add("item1");
        list.add("Item2");
        list.add("ITEM3");
        role.setMembers(list);
        
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("item1"));
        roleMembers.add(new RoleMember().setMemberName("Item2"));
        roleMembers.add(new RoleMember().setMemberName("ITEM3"));
        role.setRoleMembers(roleMembers);
        
        AthenzObject.ROLE.convertToLowerCase(role);
        
        assertEquals(role.getName(), "role1");
        list = role.getMembers();
        assertTrue(list.contains("item1"));
        assertTrue(list.contains("item2"));
        assertTrue(list.contains("item3"));
        assertEquals(list.size(), 3);
        
        roleMembers = role.getRoleMembers();
        assertEquals(roleMembers.size(), 3);
        boolean item1 = false;
        boolean item2 = false;
        boolean item3 = false;
        for (RoleMember member : roleMembers) {
            switch (member.getMemberName()) {
                case "item1":
                    item1 = true;
                    break;
                case "item2":
                    item2 = true;
                    break;
                case "item3":
                    item3 = true;
                    break;
            }
        }
        assertTrue(item1);
        assertTrue(item2);
        assertTrue(item3);
    }
    
    @Test
    public void testConvertToLowerCaseMembershipWithoutRole() {
        Membership membership = new Membership().setMemberName("user.member1");
        AthenzObject.MEMBERSHIP.convertToLowerCase(membership);
        assertEquals(membership.getMemberName(), "user.member1");
    }
    
    @Test
    public void testConvertToLowerCaseServciceWithKeys() {
        ServiceIdentity service = createServiceObject("CoreTECH", "STORage",
                "http://localhost:4080", "jetty", "user", "group", "HOST1");
        List<PublicKeyEntry> publicKeyList = new ArrayList<PublicKeyEntry>();
        PublicKeyEntry publicKeyEntry1 = new PublicKeyEntry();
        publicKeyEntry1.setKey(pubKeyK1);
        publicKeyEntry1.setId("ZONE1");
        publicKeyList.add(publicKeyEntry1);
        PublicKeyEntry publicKeyEntry2 = new PublicKeyEntry();
        publicKeyEntry2.setKey(pubKeyK2);
        publicKeyEntry2.setId("2");
        publicKeyList.add(publicKeyEntry2);
        service.setPublicKeys(publicKeyList);
        AthenzObject.SERVICE_IDENTITY.convertToLowerCase(service);
        assertEquals(service.getName(), "coretech.storage");
        assertTrue(service.getHosts().contains("host1"));
        assertEquals(service.getPublicKeys().get(0).getId(), "zone1");
        assertEquals(service.getPublicKeys().get(1).getId(), "2");
    }
    
    @Test
    public void testConvertToLowerCaseTenantRolesWithActions() {
        
        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        roleActions.add(new TenantRoleAction().setRole("Role").setAction("WRITE"));
        
        TenantRoles tenantRoles = new TenantRoles().setDomain("CORETECH")
                .setService("storage").setTenant("DelTenantRolesDom1")
                .setRoles(roleActions);
        
        AthenzObject.TENANT_ROLES.convertToLowerCase(tenantRoles);
        assertEquals(tenantRoles.getDomain(), "coretech");
        assertEquals(tenantRoles.getService(), "storage");
        assertEquals(tenantRoles.getTenant(), "deltenantrolesdom1");
        TenantRoleAction roleAction = tenantRoles.getRoles().get(0);
        assertEquals(roleAction.getAction(), "write");
        assertEquals(roleAction.getRole(), "role");
    }
    
    @Test
    public void testConvertToLowerCaseTenantRoleAction() {
        
        TenantRoleAction roleAction = new TenantRoleAction().setRole("ReaDer").setAction("READ");
        
        AthenzObject.TENANT_ROLE_ACTION.convertToLowerCase(roleAction);
        assertEquals(roleAction.getAction(), "read");
        assertEquals(roleAction.getRole(), "reader");
    }
    
    @Test
    public void testConvertToLowerCasePolicyNoAssertion() {
        
        Policy policy = new Policy();
        policy.setName(ZMSUtils.policyResourceName("CoreTech", "policy"));
        
        AthenzObject.POLICY.convertToLowerCase(policy);
        assertEquals(policy.getName(), "coretech:policy.policy");
        
        policy.setName(ZMSUtils.policyResourceName("newtech", "Policy"));
        
        AthenzObject.POLICY.convertToLowerCase(policy);
        assertEquals(policy.getName(), "newtech:policy.policy");
    }
    
    @Test
    public void testConvertToLowerCasePolicyMultipleAssertion() {
        
        Policy policy = new Policy();
        policy.setName(ZMSUtils.policyResourceName("CoreTech", "policy"));
        
        Assertion assertion1 = new Assertion();
        assertion1.setAction("Read");
        assertion1.setEffect(AssertionEffect.ALLOW);
        assertion1.setResource("coreTech:VIP.*");
        assertion1.setRole("coretech:role.Role1");
        
        Assertion assertion2 = new Assertion();
        assertion2.setAction("UPDATE");
        assertion2.setEffect(AssertionEffect.ALLOW);
        assertion2.setResource("CoreTech:VIP.*");
        assertion2.setRole("coretech:role.RoleAB");
        
        List<Assertion> assertList = new ArrayList<Assertion>();
        assertList.add(assertion1);
        assertList.add(assertion2);
        
        policy.setAssertions(assertList);
        
        AthenzObject.POLICY.convertToLowerCase(policy);
        assertEquals(policy.getName(), "coretech:policy.policy");
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getRole(), "coretech:role.role1");
        assertEquals(assertion.getAction(), "read");
        assertEquals(assertion.getResource(), "coretech:vip.*");
        
        assertion = policy.getAssertions().get(1);
        assertEquals(assertion.getRole(), "coretech:role.roleab");
        assertEquals(assertion.getAction(), "update");
        assertEquals(assertion.getResource(), "coretech:vip.*");
    }
    
    @Test
    public void testConvertToLowerCasePolicyOneAssertion() {
        
        Policy policy = createPolicyObject("CoreTech", "NewPolicy");
        AthenzObject.POLICY.convertToLowerCase(policy);
        assertEquals(policy.getName(), "coretech:policy.newpolicy");
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getRole(), "coretech:role.role1");
    }
    
    @Test
    public void testConvertToLowerCaseDomainTemplateList() {
        DomainTemplateList templates = new DomainTemplateList();
        List<String> list = new ArrayList<>();
        list.add("platforms");
        list.add("vipNg");
        list.add("ATHENZ");
        templates.setTemplateNames(list);
        AthenzObject.DOMAIN_TEMPLATE_LIST.convertToLowerCase(templates);

        list = templates.getTemplateNames();
        assertEquals(3, list.size());
        assertTrue(list.contains("platforms"));
        assertTrue(list.contains("vipng"));
        assertTrue(list.contains("athenz"));
    }

    @Test
    public void testProviderServiceDomain() {
        assertEquals(zms.providerServiceDomain("coretech.storage"), "coretech");
        assertEquals(zms.providerServiceDomain("coretech.hosted.storage"), "coretech.hosted");
        assertNull(zms.providerServiceDomain("coretech"));
        assertNull(zms.providerServiceDomain(".coretech"));
        assertNull(zms.providerServiceDomain("coretech."));
    }
    
    @Test
    public void testProviderServiceName() {
        assertEquals(zms.providerServiceName("coretech.storage"), "storage");
        assertEquals(zms.providerServiceName("coretech.hosted.storage"), "storage");
        assertNull(zms.providerServiceName("coretech"));
        assertNull(zms.providerServiceName(".coretech"));
        assertNull(zms.providerServiceName("coretech."));
    }
    
    @Test
    public void testIsAuthorizedProviderServiceInvalidService() {
        
        // null authorized service argument
        
        assertFalse(zms.isAuthorizedProviderService(null, "coretech", "storage", "sports", auditRef));
        
        // service does not match provider details
        
        assertFalse(zms.isAuthorizedProviderService("coretech.storage", "coretech", "storage2", "sports", auditRef));
        assertFalse(zms.isAuthorizedProviderService("coretech.storage", "coretech2", "storage", "sports", auditRef));
        
        // domain does not exist in zms
        
        assertFalse(zms.isAuthorizedProviderService("not_present_domain.storage", "not_present_domain",
                "storage", "sports", auditRef));
    }
    
    @Test
    public void testIsAuthorizedProviderServiceAuthorized() {
        
        String tenantDomain = "AuthorizedProviderDom1";
        String providerDomain = "coretech";
        setupTenantDomainProviderService(tenantDomain, providerDomain, "storage",
                "http://localhost:8090/tableprovider");

        // tenant is setup so let's setup up policy to authorize access to tenants
        
        Role role = createRoleObject(providerDomain, "self_serve", null, providerDomain + ".storage", null);
        zms.putRole(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, role);
        
        Policy policy = createPolicyObject(providerDomain, "self_serve",
                "self_serve", "update", providerDomain + ":tenant.*", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, policy);
        
        assertTrue(zms.isAuthorizedProviderService(providerDomain + ".storage", providerDomain,
                "storage", tenantDomain, auditRef));
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
    }
    
    @Test
    public void testIsAuthorizedProviderServiceNotAuthorized() {
        
        String tenantDomain = "AuthorizedProviderDom2";
        String providerDomain = "coretech";
        setupTenantDomainProviderService(tenantDomain, providerDomain, "storage",
                "http://localhost:8090/tableprovider");

        // tenant is setup but no policy to authorize access to tenants
        
        assertFalse(zms.isAuthorizedProviderService(providerDomain + ".storage", providerDomain,
                "storage", tenantDomain, auditRef));
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
    }
    
    @Test
    public void testVerifyAuthorizedServiceOperation() {
        
        // null authorized service means it's all good
        
        zms.verifyAuthorizedServiceOperation(null, "putrole");
        
        // our test resource json file includes two services:
        // coretech.storage - allowed for putrole and putpolicy
        // sports.hockey - allowed for all ops 
        
        zms.verifyAuthorizedServiceOperation("coretech.storage", "putrole");
        zms.verifyAuthorizedServiceOperation("coretech.storage", "putpolicy");
        try {
            zms.verifyAuthorizedServiceOperation("coretech.storage", "postdomain");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        try {
            zms.verifyAuthorizedServiceOperation("coretech.storage", "deleterole");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        
        zms.verifyAuthorizedServiceOperation("sports.hockey", "putrole");
        zms.verifyAuthorizedServiceOperation("sports.hockey", "putpolicy");
        zms.verifyAuthorizedServiceOperation("sports.hockey", "deleterole");
        zms.verifyAuthorizedServiceOperation("sports.hockey", "putserviceidentity");
        
        // ATHENZ-1528
        // Try passing along operationItem key + value to see if verification works
        
        // First, try with AllowAll operation
        zms.verifyAuthorizedServiceOperation("coretech.newsvc", "putrole"); // putrole has no restriction. This should pass.
        
        // Second, try with restricted operation. Currently, putmembership only allow single operation item.
        zms.verifyAuthorizedServiceOperation("coretech.newsvc", "putmembership", "role", "platforms_deployer");
        zms.verifyAuthorizedServiceOperation("coretech.newsvc", "putmembership", "role", "platforms_different_deployer");
        zms.verifyAuthorizedServiceOperation("coretech.newsvc", "putmembership", "not_role", "platforms_role_deployer");
        
        // Third, try with restriction operation, with not-specified operation item.
        boolean errorThrown = false;
        int code = -1;
        try {
            zms.verifyAuthorizedServiceOperation("coretech.newsvc", "putmembership", "role", "platforms_deployer_new");
        } catch (ResourceException ex) {
            errorThrown = true;
            code = ex.getCode();
        }
        assertEquals(403, code);
        assertTrue(errorThrown);
        errorThrown = false;
        code = -1;
        
        try {
            zms.verifyAuthorizedServiceOperation("coretech.newsvc", "putmembership", "not_role", "platforms_deployer_new_new");
        } catch (ResourceException ex) {
            errorThrown = true;
            code = ex.getCode();
        }
        assertEquals(403, code);
        assertTrue(errorThrown);
        errorThrown = false;
        code = -1;
        
        
        try {
            zms.verifyAuthorizedServiceOperation("coretech.storage2", "postdomain");
        } catch (ResourceException ex) {
            errorThrown = true;
            code = ex.getCode();
        }
        assertEquals(403, code);
        assertTrue(errorThrown);
        errorThrown = false;
        code = -1;
        
        try {
            zms.verifyAuthorizedServiceOperation("media.storage", "deleterole");
        } catch (ResourceException ex) {
            errorThrown = true;
            code = ex.getCode();
        }
        assertEquals(403, code);
        assertTrue(errorThrown);
        errorThrown = false;
        code = -1;
    }
    
    @Test
    public void testPutProviderResourceGroupRoles() {

        String tenantDomain = "putproviderresourcegrouproles";
        TopLevelDomain dom = createTopLevelDomainObject(tenantDomain, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : RESOURCE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String providerService  = "storage";
        String providerDomain = "coretech";
        String resourceGroup = "hockey";
        
        ProviderResourceGroupRoles providerRoles = new ProviderResourceGroupRoles()
                .setDomain(providerDomain).setService(providerService)
                .setTenant(tenantDomain).setRoles(roleActions)
                .setResourceGroup(resourceGroup);
        zms.putProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup, auditRef, providerRoles);

        ProviderResourceGroupRoles tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup);
        
        assertNotNull(tRoles);
        assertEquals(providerDomain.toLowerCase(), tRoles.getDomain());
        assertEquals(providerService.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(RESOURCE_PROVIDER_ROLE_ACTIONS.size(), tRoles.getRoles().size());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
    }
    
    @Test
    public void testPutProviderResourceGroupMultipleRoles() {

        String tenantDomain = "putproviderresourcegroupmultipleroles";
        TopLevelDomain dom = createTopLevelDomainObject(tenantDomain, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : RESOURCE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String providerService  = "storage";
        String providerDomain = "coretech";
        String resourceGroup1 = "hockey";
        String resourceGroup2 = "baseball";
        
        // add resource group1 roles
        
        ProviderResourceGroupRoles providerRoles = new ProviderResourceGroupRoles()
                .setDomain(providerDomain).setService(providerService)
                .setTenant(tenantDomain).setRoles(roleActions)
                .setResourceGroup(resourceGroup1);
        zms.putProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup1, auditRef, providerRoles);

        // add resource group2 roles
        
        providerRoles = new ProviderResourceGroupRoles()
                .setDomain(providerDomain).setService(providerService)
                .setTenant(tenantDomain).setRoles(roleActions)
                .setResourceGroup(resourceGroup1);
        zms.putProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup2, auditRef, providerRoles);
        
        // verify group 1 roles
        
        ProviderResourceGroupRoles tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup1);
        
        assertNotNull(tRoles);
        assertEquals(providerDomain.toLowerCase(), tRoles.getDomain());
        assertEquals(providerService.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup1.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(RESOURCE_PROVIDER_ROLE_ACTIONS.size(), tRoles.getRoles().size());

        // verify group 2 roles
        
        tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup2);
        
        assertNotNull(tRoles);
        assertEquals(providerDomain.toLowerCase(), tRoles.getDomain());
        assertEquals(providerService.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup2.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(RESOURCE_PROVIDER_ROLE_ACTIONS.size(), tRoles.getRoles().size());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
    }
    
    @Test
    public void testDeleteProviderResourceGroupRoles() {

        String tenantDomain = "deleteproviderresourcegrouproles";
        TopLevelDomain dom = createTopLevelDomainObject(tenantDomain, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : RESOURCE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String providerService  = "storage";
        String providerDomain = "coretech";
        String resourceGroup = "hockey";
        
        ProviderResourceGroupRoles providerRoles = new ProviderResourceGroupRoles()
                .setDomain(providerDomain).setService(providerService)
                .setTenant(tenantDomain).setRoles(roleActions)
                .setResourceGroup(resourceGroup);
        zms.putProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup, auditRef, providerRoles);

        ProviderResourceGroupRoles tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup);
        
        assertNotNull(tRoles);
        assertEquals(providerDomain.toLowerCase(), tRoles.getDomain());
        assertEquals(providerService.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(RESOURCE_PROVIDER_ROLE_ACTIONS.size(), tRoles.getRoles().size());

        // now let's delete our resource group
        
        zms.deleteProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup, auditRef);
        
        // now let's retrieve our resource group and verify we got 0 roles
        
        tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup);
        
        assertNotNull(tRoles);
        assertEquals(providerDomain.toLowerCase(), tRoles.getDomain());
        assertEquals(providerService.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(0, tRoles.getRoles().size());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
    }
    
    @Test
    public void testDeleteProviderResourceGroupMultipleRoles() {

        String tenantDomain = "deleteproviderresourcegroupmultipleroles";
        TopLevelDomain dom = createTopLevelDomainObject(tenantDomain, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : RESOURCE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String providerService  = "storage";
        String providerDomain = "coretech";
        String resourceGroup1 = "hockey";
        String resourceGroup2 = "baseball";
        
        // add resource group1 roles
        
        ProviderResourceGroupRoles providerRoles = new ProviderResourceGroupRoles()
                .setDomain(providerDomain).setService(providerService)
                .setTenant(tenantDomain).setRoles(roleActions)
                .setResourceGroup(resourceGroup1);
        zms.putProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup1, auditRef, providerRoles);

        // add resource group2 roles
        
        providerRoles = new ProviderResourceGroupRoles()
                .setDomain(providerDomain).setService(providerService)
                .setTenant(tenantDomain).setRoles(roleActions)
                .setResourceGroup(resourceGroup1);
        zms.putProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup2, auditRef, providerRoles);
        
        // now let's delete our resource group 1
        
        zms.deleteProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup1, auditRef);
        
        // verify group 1 roles and it's size of 0
        
        ProviderResourceGroupRoles tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup1);
        
        assertNotNull(tRoles);
        assertEquals(providerDomain.toLowerCase(), tRoles.getDomain());
        assertEquals(providerService.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup1.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(0, tRoles.getRoles().size());
        
        // verify group 2 roles with valid size of roles
        
        tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup2);
        
        assertNotNull(tRoles);
        assertEquals(providerDomain.toLowerCase(), tRoles.getDomain());
        assertEquals(providerService.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup2.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(RESOURCE_PROVIDER_ROLE_ACTIONS.size(), tRoles.getRoles().size());
        
        // now let's delete our resource group 2
        
        zms.deleteProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup2, auditRef);
        
        // now both get operations must return 0 for the size
        
        tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup1);
        
        assertNotNull(tRoles);
        assertEquals(0, tRoles.getRoles().size());
        
        tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup2);
        
        assertNotNull(tRoles);
        assertEquals(0, tRoles.getRoles().size());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
    }
    
    @Test
    public void testGetProviderResourceGroupRoles() {

        String tenantDomain = "getproviderresourcegrouproles";
        TopLevelDomain dom = createTopLevelDomainObject(tenantDomain, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : RESOURCE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        String providerService  = "storage";
        String providerDomain = "coretech";
        String resourceGroup = "hockey";
        
        ProviderResourceGroupRoles providerRoles = new ProviderResourceGroupRoles()
                .setDomain(providerDomain).setService(providerService)
                .setTenant(tenantDomain).setRoles(roleActions)
                .setResourceGroup(resourceGroup);
        zms.putProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain, providerService,
                resourceGroup, auditRef, providerRoles);

        ProviderResourceGroupRoles tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup);
        
        assertNotNull(tRoles);
        assertEquals(providerDomain.toLowerCase(), tRoles.getDomain());
        assertEquals(providerService.toLowerCase(), tRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), tRoles.getTenant());
        assertEquals(resourceGroup.toLowerCase(), tRoles.getResourceGroup());
        assertEquals(RESOURCE_PROVIDER_ROLE_ACTIONS.size(), tRoles.getRoles().size());
        List<TenantRoleAction> traList = tRoles.getRoles();
        List<String> roles = new ArrayList<>();
        for (TenantRoleAction ra : traList) {
            roles.add(ra.getRole());
        }
        assertTrue(roles.contains("reader"));
        assertTrue(roles.contains("writer"));
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
    }
    
    @Test
    public void testGetProviderResourceGroupRolesInvalid() {

        String tenantDomain = "getproviderresourcegrouprolesinvalid";
        TopLevelDomain dom = createTopLevelDomainObject(tenantDomain, "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom);

        // all invalid input with provider domain, resource and resource group
        // just returns an empty list for role actions.

        ProviderResourceGroupRoles tRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, "test1", "invalid", "hockey");
        
        assertNotNull(tRoles);
        assertEquals(0, tRoles.getRoles().size());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
    }
    
    @Test
    public void testPutProviderResourceGroupRolesWithAuthorizedService() {

        String tenantDomain = "providerresourcegrouprolesauthorizedservice";
        String providerService  = "storage";
        String providerDomain = "coretech";
        String resourceGroup = "hockey";
        
        setupTenantDomainProviderService(tenantDomain, providerDomain, providerService,
                "http://localhost:8090/tableprovider");

        // tenant is setup so let's setup up policy to authorize access to tenants
        // without this role/policy we won't be authorized to add tenant roles
        // to the provider domain even with authorized service details
        
        Role role = createRoleObject(providerDomain, "self_serve", null,
                providerDomain + "." + providerService, null);
        zms.putRole(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, role);
        
        Policy policy = createPolicyObject(providerDomain, "self_serve",
                "self_serve", "update", providerDomain + ":tenant.*", AssertionEffect.ALLOW);
        zms.putPolicy(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, policy);
        
        // now we're going to setup our provider role call
        
        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : RESOURCE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        
        ProviderResourceGroupRoles providerRoles = new ProviderResourceGroupRoles()
                .setDomain(providerDomain).setService(providerService)
                .setTenant(tenantDomain).setRoles(roleActions)
                .setResourceGroup(resourceGroup);
        
        // we are going to create a principal object with authorized service
        // set to coretech.storage
        
        String userId = "user1";
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=" + userId;
        Principal principal = SimplePrincipal.create("user", userId, unsignedCreds + ";s=signature",
                0, principalAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);
        ((SimplePrincipal) principal).setAuthorizedService("coretech.storage");
        ResourceContext ctx = createResourceContext(principal);
        
        // after this call we should have roles set for both provider and tenant
        
        zms.putProviderResourceGroupRoles(ctx, tenantDomain, providerDomain, providerService,
                resourceGroup, auditRef, providerRoles);

        ProviderResourceGroupRoles pRoles = zms.getProviderResourceGroupRoles(ctx,
                tenantDomain, providerDomain, providerService, resourceGroup);
        
        assertNotNull(pRoles);
        assertEquals(providerDomain.toLowerCase(), pRoles.getDomain());
        assertEquals(providerService.toLowerCase(), pRoles.getService());
        assertEquals(tenantDomain.toLowerCase(), pRoles.getTenant());
        assertEquals(resourceGroup.toLowerCase(), pRoles.getResourceGroup());
        assertEquals(RESOURCE_PROVIDER_ROLE_ACTIONS.size(), pRoles.getRoles().size());
        List<TenantRoleAction> traList = pRoles.getRoles();
        List<String> roles = new ArrayList<>();
        for (TenantRoleAction ra : traList) {
            roles.add(ra.getRole());
        }
        assertTrue(roles.contains("reader"));
        assertTrue(roles.contains("writer"));
        
        // now get the tenant roles for the provider
        
        TenantResourceGroupRoles tRoles = zms.getTenantResourceGroupRoles(mockDomRsrcCtx, providerDomain,
                providerService, tenantDomain, resourceGroup);
        assertNotNull(tRoles);
        assertEquals(tRoles.getDomain(), providerDomain);
        assertEquals(tRoles.getService(), providerService);
        assertEquals(tRoles.getTenant(), tenantDomain);
        assertEquals(tRoles.getResourceGroup(), resourceGroup);
        assertEquals(RESOURCE_PROVIDER_ROLE_ACTIONS.size(), tRoles.getRoles().size());
        traList = pRoles.getRoles();
        roles = new ArrayList<>();
        for (TenantRoleAction ra : traList) {
            roles.add(ra.getRole());
        }
        assertTrue(roles.contains("reader"));
        assertTrue(roles.contains("writer"));
        
        // now we're going to delete the provider roles using the standard
        // resource object without the authorized service. in this case
        // the provider roles are going to be deleted but not the tenant
        // roles from the provider domain
        
        zms.deleteProviderResourceGroupRoles(mockDomRsrcCtx, tenantDomain, providerDomain,
                providerService, resourceGroup, auditRef);
        
        // so for tenant we're going to 0 provider roles
        
        pRoles = zms.getProviderResourceGroupRoles(mockDomRsrcCtx,
                tenantDomain, providerDomain, providerService, resourceGroup);
        
        assertNotNull(pRoles);
        assertEquals(0, pRoles.getRoles().size());
        
        // but for provider we're still going to get full set of roles
        
        tRoles = zms.getTenantResourceGroupRoles(mockDomRsrcCtx, providerDomain,
                providerService, tenantDomain, resourceGroup);
        assertNotNull(tRoles);
        assertEquals(2, tRoles.getRoles().size());
        
        // now this time we're going to delete with the principal with the
        // authorized service token
        
        zms.deleteProviderResourceGroupRoles(ctx, tenantDomain, providerDomain,
                providerService, resourceGroup, auditRef);
        
        // so for tenant we're still going to 0 provider roles
        
        pRoles = zms.getProviderResourceGroupRoles(ctx,
                tenantDomain, providerDomain, providerService, resourceGroup);
        
        assertNotNull(pRoles);
        assertEquals(0, pRoles.getRoles().size());
        
        // and for provider we're now going to get 0 tenant roles as well
        
        tRoles = zms.getTenantResourceGroupRoles(mockDomRsrcCtx, providerDomain,
                providerService, tenantDomain, resourceGroup);
        assertNotNull(tRoles);
        assertEquals(0, tRoles.getRoles().size());
        
        // clean up our domains
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
    }
    
    @Test
    public void testProviderResourceGroupRolesWithAuthorizedServiceNoAccess() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_putprovrsrcdomnoaccess";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);

        String tenantDomain = "provrscgrprolesauthorizedservicenoaccess";
        String providerService  = "index";
        String providerDomain = "coretech";
        String resourceGroup = "hockey";
        
        setupTenantDomainProviderService(zmsImpl, tenantDomain, providerDomain, providerService,
                "http://localhost:8090/tableprovider");

        // tenant is setup so let's setup up policy to authorize access to tenants
        // without this role/policy we won't be authorized to add tenant roles
        // to the provider domain even with authorized service details
        
        Role role = createRoleObject(providerDomain, "self_serve", null,
                providerDomain + "." + providerService, null);
        zmsImpl.putRole(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, role);
        
        Policy policy = createPolicyObject(providerDomain, "self_serve",
                "self_serve", "update", providerDomain + ":tenant.*", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(mockDomRsrcCtx, providerDomain, "self_serve", auditRef, policy);
        
        // now we're going to setup our provider role call
        
        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : RESOURCE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name()).setAction(
                    (String) f.value()));
        }
        
        ProviderResourceGroupRoles providerRoles = new ProviderResourceGroupRoles()
                .setDomain(providerDomain).setService(providerService)
                .setTenant(tenantDomain).setRoles(roleActions)
                .setResourceGroup(resourceGroup);
        
        // we are going to create a principal object with authorized service
        // set to coretech.index
        
        String userId = "user1";
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=" + userId;
        Principal principal = SimplePrincipal.create("user", userId, unsignedCreds + ";s=signature",
                0, principalAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);
        ((SimplePrincipal) principal).setUnsignedCreds(unsignedCreds);
        ((SimplePrincipal) principal).setAuthorizedService("coretech.index");
        ResourceContext ctx = createResourceContext(principal);
        
        // this call should return an exception since we can't execute
        // the putproviderresourcegrouproles operation with our chained token
        
        try {
            zmsImpl.putProviderResourceGroupRoles(ctx, tenantDomain, providerDomain, providerService,
                    resourceGroup, auditRef, providerRoles);
            fail();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
        }

        // clean up our domains
        
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef);
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef);
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testOptionsUserTokenInvalidService() {
        
        // null service must return 400
        
        try {
            zms.optionsUserToken(mockDomRsrcCtx, "user1", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        // empty service must return 400
        
        try {
            zms.optionsUserToken(mockDomRsrcCtx, "user1", "");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        // unknown registered service must return 400
        try {
            zms.optionsUserToken(mockDomRsrcCtx, "user1", "unknown_service_name");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        // in a list all services must be valid - any invalid must return 400
        
        try {
            zms.optionsUserToken(mockDomRsrcCtx, "user1", "coretech.storage,unknown_service_name");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testOptionsUserToken() {
        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = new MockHttpServletResponse();
        ResourceContext ctx = new RsrcCtxWrapper(servletRequest, servletResponse, null, null);
        
        zms.optionsUserToken(ctx, "user", "coretech.storage");
        assertEquals("GET", servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_METHODS));
        assertEquals("2592000", servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_MAX_AGE));
        assertEquals("true", servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS));
        
        // using default values where we'll get back null for origin and no allow headers
        
        assertNull(servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN));
        assertNull(servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_HEADERS));
    }

    @Test
    public void testOptionsUserTokenRequestHeaders() {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        ResourceContext ctx = new RsrcCtxWrapper(servletRequest, servletResponse, null, null);
        
        String origin = "https://zms.origin.athenzcompany.com";
        String requestHeaders = "X-Forwarded-For,Content-Type";
        servletRequest.addHeader(ZMSConsts.HTTP_ORIGIN, origin);
        servletRequest.addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_REQUEST_HEADERS, requestHeaders);
        
        // this time we're going to try with multiple services
        
        zms.optionsUserToken(ctx, "user", "coretech.storage,coretech.index");
        assertEquals("GET", servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_METHODS));
        assertEquals("2592000", servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_MAX_AGE));
        assertEquals("true", servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS));
        
        assertEquals(origin, servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN));
        assertEquals(requestHeaders, servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_HEADERS));
    }

    @Test
    public void testSetStandardCORSHeaders() {
        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = new MockHttpServletResponse();
        ResourceContext ctx = new RsrcCtxWrapper(servletRequest, servletResponse, null, null);
        
        zms.setStandardCORSHeaders(ctx);
        assertEquals("true", servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS));
        
        // using default values where we'll get back null for origin and no allow headers
        
        assertNull(servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN));
        assertNull(servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_HEADERS));
    }

    @Test
    public void testSetStandardCORSHeadersRequestHeaders() {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        ResourceContext ctx = new RsrcCtxWrapper(servletRequest, servletResponse, null, null);
        
        String origin = "https://zms.origin.athenzcompany.com";
        String requestHeaders = "X-Forwarded-For,Content-Type";
        servletRequest.addHeader(ZMSConsts.HTTP_ORIGIN, origin);
        servletRequest.addHeader(ZMSConsts.HTTP_ACCESS_CONTROL_REQUEST_HEADERS, requestHeaders);
        
        zms.setStandardCORSHeaders(ctx);
        assertEquals("true", servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS));
        
        assertEquals(origin, servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_ORIGIN));
        assertEquals(requestHeaders, servletResponse.getHeader(ZMSConsts.HTTP_ACCESS_CONTROL_ALLOW_HEADERS));
    }
    
    @Test
    public void testVerifyProviderEndpoint() {
        
        // http successful test cases (localhost or *.athenzcompany.com)
        assertTrue(zms.verifyProviderEndpoint("http://localhost"));
        assertTrue(zms.verifyProviderEndpoint("http://localhost:4080"));
        assertTrue(zms.verifyProviderEndpoint("http://localhost:4080/"));
        assertTrue(zms.verifyProviderEndpoint("http://localhost:4080/test1"));
        assertTrue(zms.verifyProviderEndpoint("http://host1.athenzcompany.com"));
        assertTrue(zms.verifyProviderEndpoint("http://host1.athenzcompany.com:4080"));
        assertTrue(zms.verifyProviderEndpoint("http://host1.athenzcompany.com:4080/"));
        assertTrue(zms.verifyProviderEndpoint("http://host1.athenzcompany.com:4080/test1"));
        
        // https successful test cases (localhost or *.athenzcompany.com)
        assertTrue(zms.verifyProviderEndpoint("https://localhost"));
        assertTrue(zms.verifyProviderEndpoint("https://localhost:4080"));
        assertTrue(zms.verifyProviderEndpoint("https://localhost:4080/"));
        assertTrue(zms.verifyProviderEndpoint("https://localhost:4080/test1"));
        assertTrue(zms.verifyProviderEndpoint("https://host1.athenzcompany.com"));
        assertTrue(zms.verifyProviderEndpoint("https://host1.athenzcompany.com:4080"));
        assertTrue(zms.verifyProviderEndpoint("https://host1.athenzcompany.com:4080/"));
        assertTrue(zms.verifyProviderEndpoint("https://host1.athenzcompany.com:4080/test1"));
        
        // class successful test case
        assertTrue(zms.verifyProviderEndpoint("class://com.yahoo.athenz.zms.ZMS"));
        
        // http invalid cases - not *.athenzcompany.com
        assertFalse(zms.verifyProviderEndpoint("http://host1.server.com"));
        assertFalse(zms.verifyProviderEndpoint("http://host1.server.com:4080"));
        assertFalse(zms.verifyProviderEndpoint("http://host1.server.com:4080/"));
        assertFalse(zms.verifyProviderEndpoint("http://host1.server.yahoo:4080/test1"));
        assertFalse(zms.verifyProviderEndpoint("http://host1.athenz.server.com:4080/test1"));
        assertFalse(zms.verifyProviderEndpoint("http://host1.athenz.ch:4080/test1"));
        
        // non-http scheme test cases
        assertFalse(zms.verifyProviderEndpoint("file://host1.athenz.com"));
        
        // other null test cases
        assertTrue(zms.verifyProviderEndpoint(null));
    }
    
    @Test
    public void testGetServerTemplateList() {

        ServerTemplateList list = zms.getServerTemplateList(mockDomRsrcCtx);
        assertNotNull(list);
        assertTrue(list.getTemplateNames().contains("platforms"));
        assertTrue(list.getTemplateNames().contains("vipng"));
        assertTrue(list.getTemplateNames().contains("user_provisioning"));
    }
    
    @Test
    public void testGetTemplateInvalid() {
        try {
            zms.getTemplate(mockDomRsrcCtx, "platforms test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        try {
            zms.getTemplate(mockDomRsrcCtx, "invalid");
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
    }
    
    @Test
    public void testGetTemplate() {
        
        Template template = zms.getTemplate(mockDomRsrcCtx, "user_provisioning");
        assertNotNull(template);
        
        List<Role> roles = template.getRoles();
        assertNotNull(roles);
        assertEquals(3, roles.size());
        
        Role user_role = null;
        Role superuser_role = null;
        Role openstack_readers_role = null;
        for (Role role : roles) {
            if (role.getName().equals("_domain_:role.user")) {
                user_role = role;
            } else if (role.getName().equals("_domain_:role.superuser")) {
                superuser_role = role;
            } else if (role.getName().equals("_domain_:role.openstack_readers")) {
                openstack_readers_role = role;
            }
        }
        
        assertNotNull(user_role);
        assertNotNull(superuser_role);
        assertNotNull(openstack_readers_role);
        
        // openstack_readers role has 2 members
        
        assertEquals(2, openstack_readers_role.getRoleMembers().size());
        List<String> checkList = new ArrayList<>();
        checkList.add("sys.builder");
        checkList.add("sys.openstack");
        checkRoleMember(checkList, openstack_readers_role.getRoleMembers());
        
        // other roles have no members
        
        assertNull(user_role.getRoleMembers());
        assertNull(superuser_role.getRoleMembers());

        List<Policy> policies = template.getPolicies();
        assertNotNull(policies);
        assertEquals(3, policies.size());
        
        Policy user_policy = null;
        Policy superuser_policy = null;
        Policy openstack_readers_policy = null;
        for (Policy policy : policies) {
            if (policy.getName().equals("_domain_:policy.user")) {
                user_policy = policy;
            } else if (policy.getName().equals("_domain_:policy.superuser")) {
                superuser_policy = policy;
            } else if (policy.getName().equals("_domain_:policy.openstack_readers")) {
                openstack_readers_policy = policy;
            }
        }
        
        assertNotNull(user_policy);
        assertNotNull(superuser_policy);
        assertNotNull(openstack_readers_policy);
        
        assertEquals(1, user_policy.getAssertions().size());
        assertEquals(1, superuser_policy.getAssertions().size());
        assertEquals(2, openstack_readers_policy.getAssertions().size());
        
        template = zms.getTemplate(mockDomRsrcCtx, "vipng");
        assertNotNull(template);
        
        template = zms.getTemplate(mockDomRsrcCtx, "platforms");
        assertNotNull(template);
        
        template = zms.getTemplate(mockDomRsrcCtx, "VipNg");
        assertNotNull(template);
    }
    
    @Test
    public void testValidateSolutionTemplates() {
        final String caller = "testValidateDomainTemplates";
        List<String> templateNames = new ArrayList<>();
        templateNames.add("platforms");
        zms.validateSolutionTemplates(templateNames, caller);
        
        templateNames.add("vipng");
        zms.validateSolutionTemplates(templateNames, caller);

        templateNames.add("athenz");
        try {
            zms.validateSolutionTemplates(templateNames, caller);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
            assertTrue(ex.getMessage().contains("athenz"));
        }
    }

    @Test
    public void testPutDomainTemplateInvalidTemplate() {

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_putdomtempllistinvalid";
        ZMSImpl zmsImpl = getZmsImpl(storeFile, alogger);
        
        String domainName = "templatelist-invalid";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zmsImpl.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        DomainTemplate templateList = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add("test validate");
        templateList.setTemplateNames(templates);
        try {
            zmsImpl.putDomainTemplate(mockDomRsrcCtx, domainName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        zmsImpl.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testPutDomainTemplateNotFoundTemplate() {
        
        String domainName = "templatelist-invalid";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        DomainTemplate templateList = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add("InvalidTemplate");
        templateList.setTemplateNames(templates);
        try {
            zms.putDomainTemplate(mockDomRsrcCtx, domainName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }

    @Test
    public void testPutDomainTemplateSingleTemplate() {
        
        String domainName = "templatelist-single";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        DomainTemplate domTemplate = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        domTemplate.setTemplateNames(templates);
        
        zms.putDomainTemplate(mockDomRsrcCtx, domainName, auditRef, domTemplate);
        
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

        // delete an applied service template
        //
        String templateName = "vipng";
        zms.deleteDomainTemplate(mockDomRsrcCtx, domainName, templateName, auditRef);
        
        // verify that our role collection does NOT include the roles defined in template
        
        names = zms.dbService.listRoles(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        names = zms.dbService.listPolicies(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testPutDomainTemplateMultipleTemplates() {
        
        String domainName = "templatelist-multiple";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        DomainTemplate domTemplate = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        templates.add("platforms");
        templates.add("user_provisioning");
        domTemplate.setTemplateNames(templates);
        
        zms.putDomainTemplate(mockDomRsrcCtx, domainName, auditRef, domTemplate);
        
        // verify that our role collection includes the roles defined in template
        
        List<String> names = zms.dbService.listRoles(domainName);
        assertEquals(7, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        Role role = zms.dbService.getRole(domainName, "openstack_readers", false, false);
        assertEquals(domainName + ":role.openstack_readers", role.getName());
        assertNull(role.getTrust());
        assertEquals(2, role.getRoleMembers().size());
        
        List<String> checkList = new ArrayList<>();
        checkList.add("sys.builder");
        checkList.add("sys.openstack");
        checkRoleMember(checkList, role.getRoleMembers());
        
        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());
        
        // verify that our policy collections includes the policies defined in the template
        
        names = zms.dbService.listPolicies(domainName);
        assertEquals(7, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));
        
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

        // delete applied service template
        //
        String templateName = "vipng";
        zms.deleteDomainTemplate(mockDomRsrcCtx, domainName, templateName, auditRef);
        
        // verify that our role collection does NOT include the vipng roles defined in template
        
        names = zms.dbService.listRoles(domainName);
        assertEquals(5, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zms.dbService.listPolicies(domainName);
        assertEquals(5, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        // delete applied service template
        //
        templateName = "platforms";
        zms.deleteDomainTemplate(mockDomRsrcCtx, domainName, templateName, auditRef);;
        
        // verify that our role collection does NOT include the platforms roles defined in template
        
        names = zms.dbService.listRoles(domainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zms.dbService.listPolicies(domainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        // delete last applied service template
        //
        templateName = "user_provisioning";
        zms.deleteDomainTemplate(mockDomRsrcCtx, domainName, templateName, auditRef);
        
        // verify that our role collection does NOT include the user_provisioning roles defined in template
        
        names = zms.dbService.listRoles(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        names = zms.dbService.listPolicies(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetDomainTemplateListInvalid() {
        
        try {
            zms.getDomainTemplateList(mockDomRsrcCtx, "invalid_domain name");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        try {
            zms.getDomainTemplateList(mockDomRsrcCtx, "not_found_domain_name");
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
    }

    @Test
    public void testGetDomainTemplateList() {
        
        String domainName = "domaintemplatelist-valid";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        // initially no templates
        
        DomainTemplateList domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, domainName);
        List<String> templates = domaintemplateList.getTemplateNames();
        assertEquals(0, templates.size());
        
        // add a single template
        
        DomainTemplate domTemplate = new DomainTemplate();
        templates = new ArrayList<>();
        templates.add("vipng");
        domTemplate.setTemplateNames(templates);
        
        zms.putDomainTemplate(mockDomRsrcCtx, domainName, auditRef, domTemplate);
        
        domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(1, templates.size());
        assertTrue(templates.contains("vipng"));
        
        // add 2 templates
        
        domTemplate = new DomainTemplate();
        templates = new ArrayList<>();
        templates.add("vipng");
        templates.add("platforms");
        domTemplate.setTemplateNames(templates);
        
        zms.putDomainTemplate(mockDomRsrcCtx, domainName, auditRef, domTemplate);
        
        domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(2, templates.size());
        assertTrue(templates.contains("vipng"));
        assertTrue(templates.contains("platforms"));

        // add the same set of templates again and no change in results
        domTemplate = new DomainTemplate();
        domTemplate.setTemplateNames(templates);
        zms.putDomainTemplate(mockDomRsrcCtx, domainName, auditRef, domTemplate);
        
        domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(2, templates.size());
        assertTrue(templates.contains("vipng"));
        assertTrue(templates.contains("platforms"));

        // delete an applied service template
        //
        String templateName = "vipng";
        zms.deleteDomainTemplate(mockDomRsrcCtx, domainName, templateName, auditRef);

        domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(1, templates.size());
        assertTrue(templates.contains("platforms"));
        
        // delete last applied service template
        //
        templateName = "platforms";
        zms.deleteDomainTemplate(mockDomRsrcCtx, domainName, templateName, auditRef);

        domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertTrue(templates.isEmpty());
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testPostSubDomainWithTemplates() {
        
        String domainName = "postsubdomain-withtemplate";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        SubDomain dom2 = createSubDomainObject("sub", domainName,
                "Test Domain2", "testOrg", adminUser);
        DomainTemplateList templateList = new DomainTemplateList();
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        templates.add("platforms");
        templates.add("user_provisioning");
        templateList.setTemplateNames(templates);
        dom2.setTemplates(templateList);
        
        Domain resDom1 = zms.postSubDomain(mockDomRsrcCtx, domainName, auditRef, dom2);
        assertNotNull(resDom1);
        
        String subDomainName = domainName + ".sub";
        
        // verify that our role collection includes the roles defined in template
        
        List<String> names = zms.dbService.listRoles(subDomainName);
        assertEquals(7, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        Role role = zms.dbService.getRole(subDomainName, "openstack_readers", false, false);
        assertEquals(subDomainName + ":role.openstack_readers", role.getName());
        assertNull(role.getTrust());
        assertEquals(2, role.getRoleMembers().size());

        List<String> checkList = new ArrayList<>();
        checkList.add("sys.builder");
        checkList.add("sys.openstack");
        checkRoleMember(checkList, role.getRoleMembers());
        
        role = zms.dbService.getRole(subDomainName, "sys_network_super_vip_admin", false, false);
        assertEquals(subDomainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());
        
        // verify that our policy collections includes the policies defined in the template
        
        names = zms.dbService.listPolicies(subDomainName);
        assertEquals(7, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));
        
        Policy policy = zms.dbService.getPolicy(subDomainName, "vip_admin");
        assertEquals(subDomainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(subDomainName + ":role.vip_admin", assertion.getRole());
        assertEquals(subDomainName + ":vip*", assertion.getResource());
        
        policy = zms.dbService.getPolicy(subDomainName, "sys_network_super_vip_admin");
        assertEquals(subDomainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(subDomainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(subDomainName + ":vip*", assertion.getResource());

        // verify the saved domain list
        
        DomainTemplateList domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(3, templates.size());
        assertTrue(templates.contains("vipng"));
        assertTrue(templates.contains("platforms"));
        assertTrue(templates.contains("user_provisioning"));

        // delete an applied service template
        //
        String templateName = "vipng";
        zms.deleteDomainTemplate(mockDomRsrcCtx, subDomainName, templateName, auditRef);

        domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(2, templates.size());
        assertTrue(templates.contains("platforms"));
        assertTrue(templates.contains("user_provisioning"));

        names = zms.dbService.listRoles(subDomainName);
        assertEquals(5, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zms.dbService.listPolicies(subDomainName);
        assertEquals(5, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));
        
        // delete an applied service template
        //
        templateName = "platforms";
        zms.deleteDomainTemplate(mockDomRsrcCtx, subDomainName, templateName, auditRef);

        domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(1, templates.size());
        assertTrue(templates.contains("user_provisioning"));

        names = zms.dbService.listRoles(subDomainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zms.dbService.listPolicies(subDomainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));
        
        // delete last applied service template
        //
        templateName = "user_provisioning";
        zms.deleteDomainTemplate(mockDomRsrcCtx, subDomainName, templateName, auditRef);

        domaintemplateList = zms.getDomainTemplateList(mockDomRsrcCtx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertTrue(templates.isEmpty());

        names = zms.dbService.listRoles(subDomainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        names = zms.dbService.listPolicies(subDomainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));
        
        zms.deleteSubDomain(mockDomRsrcCtx, domainName, "sub", auditRef);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testPutPolicyNoLoopbackNoSuchDomainError() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("10.10.10.11");
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_al_noloop";
        ZMSImpl zmsObj = getZmsImpl(storeFile, alogger);

        String userId = "user";
        Principal principal = SimplePrincipal.create("user", userId, "v=U1;d=user;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        String domainName = "DomainName";
        String policyName = "PolicyName";
        
        // Tests the putPolicy() condition: if (domain == null)...
        try {
            Policy policy = createPolicyObject(domainName, policyName);
            
            // should fail b/c we never created a top level domain.
            zmsObj.putPolicy(context, domainName, policyName, auditRef, policy);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
        
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testPutPolicyLoopbackNoXFF_InconsistentNameError() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_al_loopback";
        ZMSImpl zmsObj = getZmsImpl(storeFile, alogger);

        String userId = "user";
        Principal principal = SimplePrincipal.create("user", userId, "v=U1;d=user;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        String domainName = "DomainName";
        String policyName = "PolicyName";
        
        // Tests the putPolicy() condition : if (!policyResourceName(domainName, policyName).equals(policy.getName()))...
        try {
            Policy policy = createPolicyObject(domainName, policyName);
            
            zmsObj.putPolicy(context, domainName, "Bad" + policyName, auditRef, policy);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
        
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testPutPolicyLoopbackXFFSingleValue() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(servletRequest.getHeader("X-Forwarded-For")).thenReturn("10.10.10.11");
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_al_loopbackXff";
        ZMSImpl zmsObj = getZmsImpl(storeFile, alogger);

        String userId = "user";
        Principal principal = SimplePrincipal.create("user", userId, "v=U1;d=user;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        String domainName = "DomainName";
        String policyName = "PolicyName";
        
        // Tests the putPolicy() condition : if (!policyResourceName(domainName, policyName).equals(policy.getName()))...
        try {
            Policy policy = createPolicyObject(domainName, policyName);
            
            zmsObj.putPolicy(context, domainName, "Bad" + policyName, auditRef, policy);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
        
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testPutPolicyLoopbackXFFMultipleValues() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(servletRequest.getHeader("X-Forwarded-For")).thenReturn("10.10.10.11, 10.11.11.11, 10.12.12.12");
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        TestAuditLogger alogger = new TestAuditLogger();
        String storeFile = ZMS_DATA_STORE_FILE + "_al_loopbackXffMulti";
        ZMSImpl zmsObj = getZmsImpl(storeFile, alogger);

        String userId = "user";
        Principal principal = SimplePrincipal.create("user", userId, "v=U1;d=user;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        String domainName = "DomainName";
        String policyName = "PolicyName";
        
        // Tests the putPolicy() condition : if (!policyResourceName(domainName, policyName).equals(policy.getName()))...
        try {
            Policy policy = createPolicyObject(domainName, policyName);
            
            zmsObj.putPolicy(context, domainName, "Bad" + policyName, auditRef, policy);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }
        
        FileConnection.deleteDirectory(new File("/tmp/zms_core_unit_tests/" + storeFile));
    }
    
    @Test
    public void testRetrieveResourceDomainAssumeRoleWithTrust() {
        assertEquals("trustdomain", zms.retrieveResourceDomain("resource", "assume_role", "trustdomain"));
    }
    
    @Test
    public void testRetrieveResourceDomainAssumeRoleWithOutTrust() {
        assertEquals("domain1", zms.retrieveResourceDomain("domain1:resource", "assume_role", null));
    }
    
    @Test
    public void testRetrieveResourceDomainValidDomain() {
        assertEquals("domain1", zms.retrieveResourceDomain("domain1:resource", "read", null));
        assertEquals("domain1", zms.retrieveResourceDomain("domain1:resource", "read", "trustdomain"));
        assertEquals("domain1", zms.retrieveResourceDomain("domain1:a:b:c:d:e", "read", "trustdomain"));

    }
    
    @Test
    public void testRetrieveResourceDomainInvalidResource() {
        assertEquals(null, zms.retrieveResourceDomain("domain1-invalid", "read", null));
    }

    @Test
    public void testLoadPublicKeys() {
        // verify that the public keys were loaded during server startup
        assertFalse(zms.serverPublicKeyMap.isEmpty());
        String privKeyId = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY_ID, "0");
        assertEquals(pubKey, zms.serverPublicKeyMap.get(privKeyId));
    }
    
    @Test
    public void testUnderscoreNotAllowed() {

        String domainName = "core-tech";
        String badDomainName = "core_tech";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject(badDomainName,
                "Test Domain1", "testOrg", adminUser);
        try {
            zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        SubDomain sub = createSubDomainObject(badDomainName, domainName,
                "Test Domain2", "testOrg", adminUser);
        try {
            zms.postSubDomain(mockDomRsrcCtx, domainName, auditRef, sub);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        UserDomain userDom = createUserDomainObject(badDomainName, "Test Domain1", "testOrg");
        try {
            zms.postUserDomain(mockDomRsrcCtx, badDomainName, auditRef, userDom);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testReadOnlyMode() throws Exception {
        
        // first initialize our impl which would create our service
        
        ZMSImpl zmsTest = zmsInit();
        
        // now we're going to create a new instance with read-only mode
        
        System.setProperty(ZMSConsts.ZMS_PROP_READ_ONLY_MODE, "true");
        
        zmsTest = new ZMSImpl();
        ZMSImpl.serverHostName = "localhost";

        TopLevelDomain dom1 = createTopLevelDomainObject("ReadOnlyDom1",
                "Test Domain1", "testOrg", adminUser);
        try {
            zmsTest.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only"));
        }
        
        Policy policy1 = createPolicyObject("ReadOnlyDom1", "Policy1");
        try {
            zmsTest.putPolicy(mockDomRsrcCtx, "ReadOnlyDom1", "Policy1", auditRef, policy1);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only"));
        }
        
        Role role1 = createRoleObject("ReadOnlyDom1", "Role1", null,
                "user.joe", "user.jane");
        try {
            zmsTest.putRole(mockDomRsrcCtx, "ReadOnlyDom1", "Role1", auditRef, role1);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only"));
        }
        
        ServiceIdentity service1 = createServiceObject("ReadOnlyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        try {
            zmsTest.putServiceIdentity(mockDomRsrcCtx, "ReadOnlyDom1", "Service1", auditRef, service1);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only"));
        }
        
        // now make sure we can read our sys.auth zms service
        
        ServiceIdentity serviceRes = zmsTest.getServiceIdentity(mockDomRsrcCtx, "sys.auth", "zms");
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), "sys.auth.zms");
        
        System.clearProperty(ZMSConsts.ZMS_PROP_READ_ONLY_MODE);
    }
    
    @Test
    public void testGetSignedDomainsResult() {
        GetSignedDomainsResult object = new GetSignedDomainsResult(null);
        assertFalse(object.isAsync());
        
        try {
            object.done(101);
        } catch (WebApplicationException ex) {
        }
    }
    
    @Test
    public void testResourceContext() {
        
        RsrcCtxWrapper ctx = (RsrcCtxWrapper) zms.newResourceContext(mockServletRequest, mockServletResponse);
        assertNotNull(ctx);
        assertNotNull(ctx.context());
        assertNull(ctx.principal());
        assertEquals(ctx.request(), mockServletRequest);
        assertEquals(ctx.response(), mockServletResponse);
        
        try {
            com.yahoo.athenz.common.server.rest.ResourceException restExc = new com.yahoo.athenz.common.server.rest.ResourceException(401, "failed struct");
            ctx.throwZmsException(restExc);
            fail();
        } catch (ResourceException ex) {
            assertEquals(401, ex.getCode());
            assertEquals( ((ResourceError) ex.data).message, "failed struct");
        }
    }
    
    @Test
    public void testEqualToOrPrefixedBy() {
        assertTrue(zms.equalToOrPrefixedBy("pattern", "pattern"));
        assertTrue(zms.equalToOrPrefixedBy("pattern", "pattern."));
        assertTrue(zms.equalToOrPrefixedBy("pattern", "pattern.test"));
        assertFalse(zms.equalToOrPrefixedBy("pattern", "pattern-test"));
        assertFalse(zms.equalToOrPrefixedBy("pattern", "patterns.test"));
        assertFalse(zms.equalToOrPrefixedBy("pattern", "apattern.test"));
    }

    @Test
    public void testMatchRoleNoRoles() {
        assertFalse(zms.matchRole("domain", new ArrayList<Role>(), "role", null));
    }
    
    @Test
    public void testMatchRoleNoRoleMatch() {
        Role role = new Role().setName("domain:role.role1");
        ArrayList<Role> roles = new ArrayList<>();
        roles.add(role);
        assertFalse(zms.matchRole("domain", new ArrayList<Role>(), "domain:role\\.role2.*", null));
    }
    
    @Test
    public void testMatchRoleAuthRoleNoMatch() {
        Role role = new Role().setName("domain:role.role1");
        ArrayList<Role> roles = new ArrayList<>();
        roles.add(role);
        
        ArrayList<String> authRoles = new ArrayList<>();
        authRoles.add("role3");
        
        assertFalse(zms.matchRole("domain", roles, "domain:role\\.role1.*", authRoles));
    }
    
    @Test
    public void testMatchRole() {
        Role role = new Role().setName("domain:role.role1");
        ArrayList<Role> roles = new ArrayList<>();
        roles.add(role);
        
        ArrayList<String> authRoles = new ArrayList<>();
        authRoles.add("role1");
        
        assertTrue(zms.matchRole("domain", roles, "domain:role\\.role.*", authRoles));
    }
    
    @Test
    public void testExtractDomainName() {
        assertEquals(zms.extractDomainName("domain:entity"), "domain");
        assertEquals(zms.extractDomainName("domain:entity:value2"), "domain");
        assertEquals(zms.extractDomainName("domain:https://web.athenz.com/data"), "domain");
    }
    
    @Test
    public void testServerInternalError() {
        
        RuntimeException ex = ZMSUtils.internalServerError("unit test", "tester");
        assertTrue(ex.getMessage().contains("{code: 500"));
    }
    
    @Test
    public void testGetSchema() {
        Schema schema = zms.getRdlSchema(mockDomRsrcCtx);
        assertNotNull(schema);
    }
    
    @Test
    public void testValidatePolicyAssertionsInValid() {
        
        // assertion missing domain name
        
        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));

        List<Assertion> assertList = new ArrayList<Assertion>();
        assertList.add(assertion);
        
        try {
            zms.validatePolicyAssertions(assertList, "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        // assertion with empty domain name
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(":resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        assertList.clear();
        assertList.add(assertion);
        
        try {
            zms.validatePolicyAssertions(assertList, "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        // assertion with invalid domain name
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain name:resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        assertList.clear();
        assertList.add(assertion);
        
        try {
            zms.validatePolicyAssertions(assertList, "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }
    
    @Test
    public void testValidatePolicyAssertionInValid() {
        
        // assertion missing domain name
        
        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        try {
            zms.validatePolicyAssertion(assertion, "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        // assertion with empty domain name
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(":resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        try {
            zms.validatePolicyAssertion(assertion, "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        // assertion with invalid domain name
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain name:resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        try {
            zms.validatePolicyAssertion(assertion, "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
        
        // assertion with invalid resource name
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain1:resource\t\ntest");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        try {
            zms.validatePolicyAssertion(assertion, "unitTest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }
    
    @Test
    public void testValidatePolicyAssertionsValid() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain1:resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));

        List<Assertion> assertList = new ArrayList<Assertion>();
        assertList.add(assertion);
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        assertList.add(assertion);
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain1:");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        assertList.add(assertion);
        
        try {
            zms.validatePolicyAssertions(assertList, "unitTest");
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
        
        // null should also be valid
        
        try {
            zms.validatePolicyAssertions(null, "unitTest");
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
    }
    
    @Test
    public void testValidatePolicyAssertionValid() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain1:resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));

        try {
            zms.validatePolicyAssertion(assertion, "unitTest");
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:resource1");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        try {
            zms.validatePolicyAssertion(assertion, "unitTest");
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
        
        assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain1:");
        assertion.setRole(ZMSUtils.roleResourceName("domain1", "role1"));
        
        try {
            zms.validatePolicyAssertion(assertion, "unitTest");
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
    }
    
    @Test
    public void testSetupRoleListWithMembers() {

        String domainName = "setuprolelistwithmembers";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, "Role1", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "Role1", auditRef, role1);

        Role role2 = createRoleObject(domainName, "Role2", null, "user.doe",
                "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "Role2", auditRef, role2);

        Role role3 = createRoleObject(domainName, "Role3", "sys.auth", null, null);
        zms.putRole(mockDomRsrcCtx, domainName, "Role3", auditRef, role3);
        
        AthenzDomain domain = zms.getAthenzDomain(domainName, false);
        List<Role> roles = zms.setupRoleList(domain, Boolean.valueOf(true));
        assertEquals(4, roles.size()); // need to account for admin role
        
        boolean role1Check = false;
        boolean role2Check = false;
        boolean role3Check = false;
        
        for (Role role : roles) {
            switch (role.getName()) {
                case "setuprolelistwithmembers:role.role1":
                    List<String> checkList = new ArrayList<>();
                    checkList.add("user.joe");
                    checkList.add("user.jane");
                    checkRoleMember(checkList, role.getRoleMembers());
                    assertEquals(role.getRoleMembers().size(), 2);
                    assertNull(role.getTrust());
                    assertNotNull(role.getModified());
                    role1Check = true;
                    break;
                case "setuprolelistwithmembers:role.role2":
                    List<String> checkList2 = new ArrayList<>();
                    checkList2.add("user.doe");
                    checkList2.add("user.janie");
                    checkRoleMember(checkList2, role.getRoleMembers());
                    assertEquals(role.getRoleMembers().size(), 2);
                    assertNull(role.getTrust());
                    assertNotNull(role.getModified());
                    role2Check = true;
                    break;
                case "setuprolelistwithmembers:role.role3":
                    assertEquals(role.getTrust(), "sys.auth");
                    assertNull(role.getRoleMembers());
                    role3Check = true;
                    assertNotNull(role.getModified());
                    break;
            }
        }
        
        assertTrue(role1Check);
        assertTrue(role2Check);
        assertTrue(role3Check);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testSetupRoleListWithOutMembers() {

        String domainName = "setuprolelistwithoutmembers";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, "Role1", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "Role1", auditRef, role1);

        Role role2 = createRoleObject(domainName, "Role2", null, "user.doe",
                "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "Role2", auditRef, role2);

        Role role3 = createRoleObject(domainName, "Role3", "sys.auth", null, null);
        zms.putRole(mockDomRsrcCtx, domainName, "Role3", auditRef, role3);
        
        AthenzDomain domain = zms.getAthenzDomain(domainName, false);
        List<Role> roles = zms.setupRoleList(domain, Boolean.valueOf(false));
        assertEquals(4, roles.size()); // need to account for admin role
        
        boolean role1Check = false;
        boolean role2Check = false;
        boolean role3Check = false;
        
        for (Role role : roles) {
            switch (role.getName()) {
                case "setuprolelistwithoutmembers:role.role1":
                    assertNull(role.getRoleMembers());
                    assertNull(role.getTrust());
                    assertNotNull(role.getModified());
                    role1Check = true;
                    break;
                case "setuprolelistwithoutmembers:role.role2":
                    assertNull(role.getRoleMembers());
                    assertNull(role.getTrust());
                    assertNotNull(role.getModified());
                    role2Check = true;
                    break;
                case "setuprolelistwithoutmembers:role.role3":
                    assertEquals(role.getTrust(), "sys.auth");
                    assertNull(role.getRoleMembers());
                    role3Check = true;
                    assertNotNull(role.getModified());
                    break;
            }
        }
        
        assertTrue(role1Check);
        assertTrue(role2Check);
        assertTrue(role3Check);

        // we'll do the same check this time passing null
        // for the boolean flag instead of false
        
        roles = zms.setupRoleList(domain, null);
        assertEquals(4, roles.size()); // need to account for admin role
        
        role1Check = false;
        role2Check = false;
        role3Check = false;
        
        for (Role role : roles) {
            switch (role.getName()) {
                case "setuprolelistwithoutmembers:role.role1":
                    assertNull(role.getRoleMembers());
                    assertNull(role.getTrust());
                    assertNotNull(role.getModified());
                    role1Check = true;
                    break;
                case "setuprolelistwithoutmembers:role.role2":
                    assertNull(role.getRoleMembers());
                    assertNull(role.getTrust());
                    assertNotNull(role.getModified());
                    role2Check = true;
                    break;
                case "setuprolelistwithoutmembers:role.role3":
                    assertEquals(role.getTrust(), "sys.auth");
                    assertNull(role.getRoleMembers());
                    role3Check = true;
                    assertNotNull(role.getModified());
                    break;
            }
        }
        
        assertTrue(role1Check);
        assertTrue(role2Check);
        assertTrue(role3Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetRoles() {

        String domainName = "getroles";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Role role1 = createRoleObject(domainName, "Role1", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "Role1", auditRef, role1);

        Role role2 = createRoleObject(domainName, "Role2", null, "user.doe",
                "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "Role2", auditRef, role2);

        Role role3 = createRoleObject(domainName, "Role3", "sys.auth", null, null);
        zms.putRole(mockDomRsrcCtx, domainName, "Role3", auditRef, role3);
        
        Roles roleList = zms.getRoles(mockDomRsrcCtx, domainName, Boolean.valueOf(true));
        List<Role> roles = roleList.getList();
        assertEquals(4, roles.size()); // need to account for admin role
        
        boolean role1Check = false;
        boolean role2Check = false;
        boolean role3Check = false;
        
        for (Role role : roles) {
            switch (role.getName()) {
                case "getroles:role.role1":
                    List<String> checkList = new ArrayList<>();
                    checkList.add("user.joe");
                    checkList.add("user.jane");
                    checkRoleMember(checkList, role.getRoleMembers());
                    assertEquals(role.getRoleMembers().size(), 2);
                    assertNull(role.getTrust());
                    assertNotNull(role.getModified());
                    role1Check = true;
                    break;
                case "getroles:role.role2":
                    List<String> checkList2 = new ArrayList<>();
                    checkList2.add("user.doe");
                    checkList2.add("user.janie");
                    checkRoleMember(checkList2, role.getRoleMembers());
                    assertEquals(role.getRoleMembers().size(), 2);
                    assertNull(role.getTrust());
                    assertNotNull(role.getModified());
                    role2Check = true;
                    break;
                case "getroles:role.role3":
                    assertEquals(role.getTrust(), "sys.auth");
                    assertNull(role.getRoleMembers());
                    role3Check = true;
                    assertNotNull(role.getModified());
                    break;
            }
        }
        
        assertTrue(role1Check);
        assertTrue(role2Check);
        assertTrue(role3Check);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetRolesInvalidDomain() {

        final String domainName = "getrolesinvaliddomain";
        
        try {
            zms.getRoles(mockDomRsrcCtx, domainName, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }
    
    @Test
    public void testSetupPolicyListWithAssertions() {
        
        final String domainName = "setup-policy-with-assert";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject(domainName, "policy1");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject(domainName, "policy2");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy2", auditRef, policy2);
        
        AthenzDomain domain = zms.getAthenzDomain(domainName, false);
        List<Policy> policies = zms.setupPolicyList(domain, Boolean.valueOf(true));
        assertEquals(3, policies.size()); // need to account for admin policy
        
        boolean policy1Check = false;
        boolean policy2Check = false;
        
        List<Assertion> testAssertions = null;
        for (Policy policy : policies) {
            switch (policy.getName()) {
                case "setup-policy-with-assert:policy.policy1":
                    testAssertions = policy.getAssertions();
                    assertEquals(testAssertions.size(), 1);
                    policy1Check = true;
                    break;
                case "setup-policy-with-assert:policy.policy2":
                    testAssertions = policy.getAssertions();
                    assertEquals(testAssertions.size(), 1);
                    policy2Check = true;
                    break;
            }
        }
        
        assertTrue(policy1Check);
        assertTrue(policy2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetPolicies() {
        
        final String domainName = "get-policies";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject(domainName, "policy1");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject(domainName, "policy2");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy2", auditRef, policy2);
        
        Policies policyList = zms.getPolicies(mockDomRsrcCtx, domainName, Boolean.valueOf(true));
        List<Policy> policies = policyList.getList();
        assertEquals(3, policies.size()); // need to account for admin policy
        
        boolean policy1Check = false;
        boolean policy2Check = false;
        
        List<Assertion> testAssertions = null;
        for (Policy policy : policies) {
            switch (policy.getName()) {
                case "get-policies:policy.policy1":
                    testAssertions = policy.getAssertions();
                    assertEquals(testAssertions.size(), 1);
                    policy1Check = true;
                    break;
                case "get-policies:policy.policy2":
                    testAssertions = policy.getAssertions();
                    assertEquals(testAssertions.size(), 1);
                    policy2Check = true;
                    break;
            }
        }
        
        assertTrue(policy1Check);
        assertTrue(policy2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetPoliciesInvalidDomain() {

        String domainName = "get-policies-invalid-domain";
        
        try {
            zms.getPolicies(mockDomRsrcCtx, domainName, Boolean.valueOf(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }
    
    @Test
    public void testSetupPolicyListWithOutAssertions() {
        
        final String domainName = "setup-policy-without-assert";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy1 = createPolicyObject(domainName, "policy1");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy1);

        Policy policy2 = createPolicyObject(domainName, "policy2");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy2", auditRef, policy2);
        
        AthenzDomain domain = zms.getAthenzDomain(domainName, false);
        List<Policy> policies = zms.setupPolicyList(domain, Boolean.valueOf(false));
        assertEquals(3, policies.size()); // need to account for admin policy
        
        boolean policy1Check = false;
        boolean policy2Check = false;
        
        for (Policy policy : policies) {
            switch (policy.getName()) {
                case "setup-policy-without-assert:policy.policy1":
                    assertNull(policy.getAssertions());
                    policy1Check = true;
                    break;
                case "setup-policy-without-assert:policy.policy2":
                    assertNull(policy.getAssertions());
                    policy2Check = true;
                    break;
            }
        }
        
        assertTrue(policy1Check);
        assertTrue(policy2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetServiceIdentities() {
        
        final String domainName = "get-services";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service1 = createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service1", auditRef, service1);

        ServiceIdentity service2 = createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service2", auditRef, service2);
        
        ServiceIdentities serviceList = zms.getServiceIdentities(mockDomRsrcCtx, domainName,
                Boolean.valueOf(true), Boolean.valueOf(true));
        List<ServiceIdentity> services = serviceList.getList();
        assertEquals(2, services.size());
        
        boolean service1Check = false;
        boolean service2Check = false;
        
        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "get-services.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host1");
                    service1Check = true;
                    break;
                case "get-services.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host2");
                    service2Check = true;
                    break;
            }
        }
        
        assertTrue(service1Check);
        assertTrue(service2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetServiceIdentitiesInvalidDomain() {

        String domainName = "get-services-invalid-domain";
        
        try {
            zms.getServiceIdentities(mockDomRsrcCtx, domainName,
                    Boolean.valueOf(true), Boolean.valueOf(true));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }
    
    @Test
    public void testSetupServiceListWithKeysHosts() {
        
        final String domainName = "setup-service-keys-hosts";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service1 = createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service1", auditRef, service1);

        ServiceIdentity service2 = createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service2", auditRef, service2);
        
        AthenzDomain domain = zms.getAthenzDomain(domainName, false);
        List<ServiceIdentity> services = zms.setupServiceIdentityList(domain,
                Boolean.valueOf(true), Boolean.valueOf(true));
        assertEquals(2, services.size());
        
        boolean service1Check = false;
        boolean service2Check = false;
        
        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "setup-service-keys-hosts.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host1");
                    service1Check = true;
                    break;
                case "setup-service-keys-hosts.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host2");
                    service2Check = true;
                    break;
            }
        }
        
        assertTrue(service1Check);
        assertTrue(service2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testSetupServiceListWithOutKeysHosts() {
        
        final String domainName = "setup-service-without-keys-hosts";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service1 = createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service1", auditRef, service1);

        ServiceIdentity service2 = createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service2", auditRef, service2);
        
        AthenzDomain domain = zms.getAthenzDomain(domainName, false);
        List<ServiceIdentity> services = zms.setupServiceIdentityList(domain,
                Boolean.valueOf(false), Boolean.valueOf(false));
        assertEquals(2, services.size());
        
        boolean service1Check = false;
        boolean service2Check = false;
        
        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "setup-service-without-keys-hosts.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertNull(service.getPublicKeys());
                    assertNull(service.getHosts());
                    service1Check = true;
                    break;
                case "setup-service-without-keys-hosts.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertNull(service.getPublicKeys());
                    assertNull(service.getHosts());
                    service2Check = true;
                    break;
            }
        }
        
        assertTrue(service1Check);
        assertTrue(service2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testSetupServiceListWithKeysOnly() {
        
        final String domainName = "setup-service-keys-only";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service1 = createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service1", auditRef, service1);

        ServiceIdentity service2 = createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service2", auditRef, service2);
        
        AthenzDomain domain = zms.getAthenzDomain(domainName, false);
        List<ServiceIdentity> services = zms.setupServiceIdentityList(domain,
                Boolean.valueOf(true), Boolean.valueOf(false));
        assertEquals(2, services.size());
        
        boolean service1Check = false;
        boolean service2Check = false;
        
        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "setup-service-keys-only.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertNull(service.getHosts());
                    service1Check = true;
                    break;
                case "setup-service-keys-only.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertNull(service.getHosts());
                    service2Check = true;
                    break;
            }
        }
        
        assertTrue(service1Check);
        assertTrue(service2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testSetupServiceListWithHostsOnly() {
        
        final String domainName = "setup-service-hosts-only";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        ServiceIdentity service1 = createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service1", auditRef, service1);

        ServiceIdentity service2 = createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");
        zms.putServiceIdentity(mockDomRsrcCtx, domainName, "service2", auditRef, service2);
        
        AthenzDomain domain = zms.getAthenzDomain(domainName, false);
        List<ServiceIdentity> services = zms.setupServiceIdentityList(domain,
                Boolean.valueOf(false), Boolean.valueOf(true));
        assertEquals(2, services.size());
        
        boolean service1Check = false;
        boolean service2Check = false;
        
        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "setup-service-hosts-only.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertNull(service.getPublicKeys());
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host1");
                    service1Check = true;
                    break;
                case "setup-service-hosts-only.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertNull(service.getPublicKeys());
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host2");
                    service2Check = true;
                    break;
            }
        }
        
        assertTrue(service1Check);
        assertTrue(service2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetAssertion() {

        final String domainName = "get-assertion";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = createPolicyObject(domainName, "policy1");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy);

        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, "policy1");
        Long assertionId = policyRes.getAssertions().get(0).getId();

        Assertion assertion = zms.getAssertion(mockDomRsrcCtx, domainName, "policy1", assertionId);
        assertNotNull(assertion);
        assertEquals(assertion.getAction(), "*");
        assertEquals(assertion.getResource(), domainName + ":*");
       
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetAssertionMultiple() {

        final String domainName = "get-assertion-multiple";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = createPolicyObject(domainName, "policy1");
        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(domainName + ":resource");
        assertion.setRole(ZMSUtils.roleResourceName(domainName, "admin"));
        policy.getAssertions().add(assertion);
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy);

        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, "policy1");
        List<Assertion> testAssertions = new ArrayList<>();

        Long assertionId = policyRes.getAssertions().get(0).getId();
        Assertion testAssertion = zms.getAssertion(mockDomRsrcCtx, domainName, "policy1", assertionId);
        assertNotNull(testAssertion);
        testAssertions.add(testAssertion);
       
        assertionId = policyRes.getAssertions().get(1).getId();
        testAssertion = zms.getAssertion(mockDomRsrcCtx, domainName, "policy1", assertionId);
        assertNotNull(testAssertion);
        testAssertions.add(testAssertion);
        
        boolean assert1Check = false;
        boolean assert2Check = false;
        for (Assertion testAssert : testAssertions) {
            switch (testAssert.getAction()) {
                case "*":
                    assertEquals(testAssert.getResource(), domainName + ":*");
                    assert1Check = true;
                    break;
                case "update":
                    assertEquals(testAssert.getResource(), domainName + ":resource");
                    assert2Check = true;
                    break;
            }
        }
        assertTrue(assert1Check);
        assertTrue(assert2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetAssertionUnknownId() {

        final String domainName = "get-assertion-invalid";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = createPolicyObject(domainName, "policy1");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy);

        try {
            zms.getAssertion(mockDomRsrcCtx, domainName, "policy1", Long.valueOf(1));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
       
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testPutAssertion() {

        final String domainName = "put-assertion";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = createPolicyObject(domainName, "policy1");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy);

        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(domainName + ":resource");
        assertion.setRole(ZMSUtils.roleResourceName(domainName, "admin"));

        // add the assertion
        
        assertion = zms.putAssertion(mockDomRsrcCtx, domainName, "policy1", auditRef, assertion);
        
        // verity that the return assertion object has the id set
        
        assertNotNull(assertion.getId());
        
        // validate that both assertions exist
        
        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, "policy1");
        
        boolean assert1Check = false;
        boolean assert2Check = false;
        for (Assertion testAssert : policyRes.getAssertions()) {
            switch (testAssert.getAction()) {
                case "*":
                    assertEquals(testAssert.getResource(), domainName + ":*");
                    assert1Check = true;
                    break;
                case "update":
                    assertEquals(testAssert.getResource(), domainName + ":resource");
                    assert2Check = true;
                    break;
            }
        }
        assertTrue(assert1Check);
        assertTrue(assert2Check);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testPutAssertionAdminReject() {

        final String domainName = "put-assertion-admin";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(domainName + ":resource");
        assertion.setRole(ZMSUtils.roleResourceName(domainName, "admin"));
        
        try {
            zms.putAssertion(mockDomRsrcCtx, domainName, "admin", auditRef, assertion);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("admin policy cannot be modified"), ex.getMessage());
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testPutAssertionUnknownPolicy() {

        final String domainName = "put-assertion-unknown";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(domainName + ":resource");
        assertion.setRole(ZMSUtils.roleResourceName(domainName, "admin"));

        // add the assertion which should fail due to unknown policy name
        
        try {
            zms.putAssertion(mockDomRsrcCtx, domainName, "policy2", auditRef, assertion);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testDeleteAssertionSingle() {

        final String domainName = "delete-assertion-single";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = createPolicyObject(domainName, "policy1");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy);

        // now let's delete the assertion directly
        
        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, "policy1");
        Long assertionId = policyRes.getAssertions().get(0).getId();

        zms.deleteAssertion(mockDomRsrcCtx, domainName, "policy1", assertionId, auditRef);
        
        policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, "policy1");
        assertEquals(policyRes.getAssertions().size(), 0);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testDeleteAssertionMultiple() {
        
        final String domainName = "delete-assertion-multiple";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = createPolicyObject(domainName, "policy1");
        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(domainName + ":resource");
        assertion.setRole(ZMSUtils.roleResourceName(domainName, "admin"));
        policy.getAssertions().add(assertion);
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy);

        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, "policy1");

        // we are going to delete assertion at index 0
        
        Long assertionId = policyRes.getAssertions().get(0).getId();
        zms.deleteAssertion(mockDomRsrcCtx, domainName, "policy1", assertionId, auditRef);

        // remember the assertion action for index 1
        
        String action = policyRes.getAssertions().get(1).getAction();
        
        // fetch the policy again and verify the action
        
        policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, "policy1");
        assertEquals(policyRes.getAssertions().size(), 1);
        assertEquals(policyRes.getAssertions().get(0).getAction(), action);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testDeleteAssertionAdminReject() {

        final String domainName = "delete-assertion-admin";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);
        
        try {
            zms.deleteAssertion(mockDomRsrcCtx, domainName, "admin", Long.valueOf(101), auditRef);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("admin policy cannot be modified"), ex.getMessage());
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testDeleteAssertionUnknown() {

        final String domainName = "delete-assertion-unknown";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Policy policy = createPolicyObject(domainName, "policy1");
        zms.putPolicy(mockDomRsrcCtx, domainName, "policy1", auditRef, policy);

        // delete the assertion which should fail due to unknown policy name
        
        try {
            zms.deleteAssertion(mockDomRsrcCtx, domainName, "policy2", Long.valueOf(1), auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        // delete the assertion which should fail due to unknown assertion id
        
        try {
            zms.deleteAssertion(mockDomRsrcCtx, domainName, "policy1", Long.valueOf(1), auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testGetPolicyListWithoutAssertionId() {
        
        assertNull(zms.getPolicyListWithoutAssertionId(null));
        
        List<Policy> emptyList = new ArrayList<>();
        List<Policy> result = zms.getPolicyListWithoutAssertionId(emptyList);
        assertTrue(result.isEmpty());
        
        final String domainName = "assertion-test";
        Policy policy = createPolicyObject(domainName, "policy1");
        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource(domainName + ":resource");
        assertion.setRole(ZMSUtils.roleResourceName(domainName, "admin"));
        assertion.setId(Long.valueOf(101));
        policy.getAssertions().add(assertion);
        
        List<Policy> policyList = new ArrayList<>();
        policyList.add(policy);
        
        result = zms.getPolicyListWithoutAssertionId(policyList);
        assertEquals(result.size(), 1);
        Assertion testAssertion = result.get(0).getAssertions().get(0);
        assertNull(testAssertion.getId());
        assertEquals(assertion.getAction(), "update");
        assertEquals(assertion.getEffect(), AssertionEffect.ALLOW);
        assertEquals(assertion.getResource(), domainName + ":resource");
        assertEquals(assertion.getRole(), ZMSUtils.roleResourceName(domainName, "admin"));
    }
    
    @Test
    public void testIsConsistentRoleName() {
        
        Role role = new Role();
        
        role.setName("domain1:role.role1");
        assertTrue(zms.isConsistentRoleName("domain1", "role1", role));
        
        // local name behavior
        
        role.setName("role1");
        assertTrue(zms.isConsistentRoleName("domain1", "role1", role));
        assertEquals(role.getName(), "domain1:role.role1");
        
        // inconsistent behavior
        
        role.setName("domain1:role.role1");
        assertFalse(zms.isConsistentRoleName("domain1", "role2", role));
        
        role.setName("role1");
        assertFalse(zms.isConsistentRoleName("domain1", "role2", role));
    }
    
    @Test
    public void testIsConsistentPolicyName() {
        
        Policy policy = new Policy();
        
        policy.setName("domain1:policy.policy1");
        assertTrue(zms.isConsistentPolicyName("domain1", "policy1", policy));
        
        // local name behavior
        
        policy.setName("policy1");
        assertTrue(zms.isConsistentPolicyName("domain1", "policy1", policy));
        assertEquals(policy.getName(), "domain1:policy.policy1");
        
        // inconsistent behavior
        
        policy.setName("domain1:policy.policy1");
        assertFalse(zms.isConsistentPolicyName("domain1", "policy2", policy));
        
        policy.setName("policy1");
        assertFalse(zms.isConsistentPolicyName("domain1", "policy2", policy));
    }
    
    @Test
    public void testGetDomainListNotNull() {
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        String userId = "user1";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password", 0, userAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        zms.getDomainList(rsrcCtx1, 100, null, null, 100, "account", 224, "roleMem1", "role1", null);
    }

    @Test
    public void testDeleteUserDomainNull() {
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        String userId = "user1";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password", 0, userAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        try {
            zms.deleteUserDomain(rsrcCtx1, null, null);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteDomainTemplateNull() {
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        String userId = "user1";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password", 0, userAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = createResourceContext(principal);
        try {
            zms.deleteDomainTemplate(rsrcCtx1, "dom1", null, "zms");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testIsAllowedResourceLookForAllUsers() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        try{
            zms.isAllowedResourceLookForAllUsers(principal1);
        } catch(Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testDeleteDomainTemplate() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        try{
            zms.deleteDomainTemplate(rsrcCtx1, null, null, null);
        } catch(Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testPutTenancyResourceGroupNull() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        TenancyResourceGroup tenantResource = new TenancyResourceGroup();
        try{
            zms.putTenancyResourceGroup(rsrcCtx1, null, null, null, null, tenantResource);
        } catch(Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testDeleteTenancyResourceGroupNull() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        try{
            zms.deleteTenancyResourceGroup(rsrcCtx1, null, null, null, null);
        } catch(Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testPutTenantResourceGroupRolesNull() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        TenantResourceGroupRoles tenantResource = new TenantResourceGroupRoles();
        try{
            zms.putTenantResourceGroupRoles(rsrcCtx1, null, null, null, null, null, tenantResource);
        } catch(Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testDeleteTenantResourceGroupRolesNull() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        try{
            zms.deleteTenantResourceGroupRoles(rsrcCtx1, null, null, null, null, null);
        } catch(Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testGetResourceAccessList() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        try{
            zms.getResourceAccessList(rsrcCtx1, "principal", "UPDATE");
        } catch(Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testDeleteProviderResourceGroupRolesNull() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = createResourceContext(principal1);
        try{
            zms.deleteProviderResourceGroupRoles(rsrcCtx1, null, null, null, null, null);
        } catch(Exception ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testGetProviderClient() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        try{
            zms.setProviderClientClass(null);
            zms.getProviderClient("localhost/zms", principal1);
        } catch(Exception ex) {
            assertTrue(true);
        }
    }
    
    @DataProvider(name = "roles")
    public static Object[][] getRoles() {
        final String memberName="member1";
        final String memberNameToSearch="notFound";
        final Timestamp expiredTimestamp = Timestamp.fromMillis(System.currentTimeMillis() - 100);
        final Timestamp notExpiredTimestamp = Timestamp.fromMillis(System.currentTimeMillis() + 100);
        
        return new Object[][] {
            //expired
            {memberName, memberName, expiredTimestamp, true, false}, 
            //not expired
            {memberName, memberName, notExpiredTimestamp, true, true}, 
            //not found
            {memberName, memberNameToSearch, notExpiredTimestamp, true, false}, 
            //set not filled which means no members are defined
            {memberName, memberName, notExpiredTimestamp, false, false}, 
            //null expiration
            {memberName, memberName, null, true, true}, 
        };
    }

    @Test(dataProvider = "roles")
    public void testIsMemberOfRole(final String memeberName, final String memberNameToSearch,
            Timestamp expiredTimestamp, boolean setRoleMembers, boolean isMember) {
        //Construct roleMembers
        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember roleMember = new RoleMember();
        roleMember.setMemberName(memeberName);
        roleMember.setExpiration(expiredTimestamp);
        roleMembers.add(roleMember);

        Role role = new Role();
        if (setRoleMembers) {
            role.setRoleMembers(roleMembers);
        }
        boolean actual = zms.isMemberOfRole(role, memberNameToSearch);
        assertEquals(actual, isMember);
    }
    
    @Test
    public void testLogPrincipalEmpty() {
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResourceContext ctx = zms.newResourceContext(request, response);
        zms.logPrincipal(ctx);
        assertTrue(request.attributes.isEmpty());
    }
    
    @Test
    public void testIsSysAdminUserInvalidDomain() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("sports", "nhl", "v=S1;d=sports;n=nhl;s=signature",
                0, principalAuthority);
        assertFalse(zms.isSysAdminUser(principal));
    }
    
    @Test
    public void testMemberNameMatch() {
        assertTrue(zms.memberNameMatch("*", "user.joe"));
        assertTrue(zms.memberNameMatch("*", "athenz.service.storage"));
        assertTrue(zms.memberNameMatch("user.*", "user.joe"));
        assertTrue(zms.memberNameMatch("athenz.*", "athenz.service.storage"));
        assertTrue(zms.memberNameMatch("athenz.service*", "athenz.service.storage"));
        assertTrue(zms.memberNameMatch("athenz.service*", "athenz.service-storage"));
        assertTrue(zms.memberNameMatch("athenz.service*", "athenz.service"));
        assertTrue(zms.memberNameMatch("user.joe", "user.joe"));
        
        assertFalse(zms.memberNameMatch("user.*", "athenz.joe"));
        assertFalse(zms.memberNameMatch("athenz.*", "athenztest.joe"));
        assertFalse(zms.memberNameMatch("athenz.service*", "athenz.servic"));
        assertFalse(zms.memberNameMatch("athenz.service*", "athenz.servictag"));
        assertFalse(zms.memberNameMatch("user.joe", "user.joel"));
    }
    
    @Test
    public void testGetUserList() {
        
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
        
        UserList userList = zms.getUserList(mockDomRsrcCtx);
        List<String> users = userList.getNames();
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
    public void testDeleteUser() {
        
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
        
        UserList userList = zms.getUserList(mockDomRsrcCtx);
        List<String> users = userList.getNames();
        assertEquals(users.size(), 3);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.joe"));
        
        zms.deleteUser(mockDomRsrcCtx, "jack", auditRef);
        
        userList = zms.getUserList(mockDomRsrcCtx);
        users = userList.getNames();
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
    public void testPutQuota() {

        String domainName = "putquota";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Quota quota = new Quota().setName(domainName)
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);
        
        zms.putQuota(mockDomRsrcCtx, domainName, auditRef, quota);

        // now retrieve the quota using zms interface
        
        Quota quotaCheck = zms.getQuota(mockDomRsrcCtx, domainName);
        assertNotNull(quotaCheck);
        assertEquals(quotaCheck.getAssertion(), 10);
        assertEquals(quotaCheck.getRole(), 14);
        assertEquals(quotaCheck.getPolicy(), 12);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testPutQuotaMismatchName() {

        String domainName = "putquotamismatchname";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Quota quota = new Quota().setName("athenz")
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);
        
        try {
            zms.putQuota(mockDomRsrcCtx, domainName, auditRef, quota);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testDeleteQuota() {

        String domainName = "deletequota";
        
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, dom1);

        Quota quota = new Quota().setName(domainName)
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);
        
        zms.putQuota(mockDomRsrcCtx, domainName, auditRef, quota);

        Quota quotaCheck = zms.getQuota(mockDomRsrcCtx, domainName);
        assertNotNull(quotaCheck);
        assertEquals(domainName, quotaCheck.getName());
        assertEquals(quotaCheck.getAssertion(), 10);
        assertEquals(quotaCheck.getRole(), 14);
        assertEquals(quotaCheck.getPolicy(), 12);
        
        // now delete the quota
        
        zms.deleteQuota(mockDomRsrcCtx, domainName, auditRef);
        
        // now we'll get the default quota
        
        quotaCheck = zms.getQuota(mockDomRsrcCtx, domainName);

        assertEquals("server-default", quotaCheck.getName());
        assertEquals(quotaCheck.getAssertion(), 100);
        assertEquals(quotaCheck.getRole(), 1000);
        assertEquals(quotaCheck.getPolicy(), 1000);
        
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef);
    }
    
    @Test
    public void testUserHomeDomainResource() {
        ZMSImpl zmsImpl = zmsInit();
        
        PrincipalAuthority principalAuthority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        PrincipalAuthority testPrincipalAuthority = new com.yahoo.athenz.zms.TestUserPrincipalAuthority();
        
        // no changes expected
        
        zmsImpl.userDomain = "user";
        zmsImpl.userDomainPrefix = "user.";
        zmsImpl.homeDomain = "user";
        zmsImpl.homeDomainPrefix = "user.";
        zmsImpl.userAuthority = principalAuthority;
        assertEquals(zmsImpl.userHomeDomainResource("user.hga:domain"), "user.hga:domain");
        assertEquals(zmsImpl.userHomeDomainResource("user.john.smith:domain"), "user.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("testuser.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("product.john.smith:domain"), "product.john.smith:domain");

        // no changes expected
        
        zmsImpl.userDomain = "user";
        zmsImpl.userDomainPrefix = "user.";
        zmsImpl.homeDomain = "user";
        zmsImpl.homeDomainPrefix = "user.";
        zmsImpl.userAuthority = testPrincipalAuthority;
        assertEquals(zmsImpl.userHomeDomainResource("user.hga:domain"), "user.hga:domain");
        assertEquals(zmsImpl.userHomeDomainResource("user.john.smith:domain"), "user.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("testuser.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("product.john.smith:domain"), "product.john.smith:domain");
        
        // only domain name is changed - no username changes since user/home are same
        
        zmsImpl.userDomain = "testuser";
        zmsImpl.userDomainPrefix = "testuser.";
        zmsImpl.homeDomain = "testuser";
        zmsImpl.homeDomainPrefix = "testuser.";
        zmsImpl.userAuthority = principalAuthority;
        assertEquals(zmsImpl.userHomeDomainResource("user.hga:domain"), "testuser.hga:domain");
        assertEquals(zmsImpl.userHomeDomainResource("user.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("testuser.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("product.john.smith:domain"), "product.john.smith:domain");
        
        // only domain name is changed - no username changes since user/home are same

        zmsImpl.userDomain = "testuser";
        zmsImpl.userDomainPrefix = "testuser.";
        zmsImpl.homeDomain = "testuser";
        zmsImpl.homeDomainPrefix = "testuser.";
        zmsImpl.userAuthority = testPrincipalAuthority;
        assertEquals(zmsImpl.userHomeDomainResource("user.hga:domain"), "testuser.hga:domain");
        assertEquals(zmsImpl.userHomeDomainResource("user.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("testuser.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("product.john.smith:domain"), "product.john.smith:domain");
        
        // domain and username are changed since user/home namespaces are different
        // username impl in authority is default so we'll end up with same username
        
        zmsImpl.userDomain = "user";
        zmsImpl.userDomainPrefix = "user.";
        zmsImpl.homeDomain = "home";
        zmsImpl.homeDomainPrefix = "home.";
        zmsImpl.userAuthority = principalAuthority;
        assertEquals(zmsImpl.userHomeDomainResource("user.hga:domain"), "home.hga:domain");
        assertEquals(zmsImpl.userHomeDomainResource("user.john.smith:domain"), "home.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("testuser.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("product.john.smith:domain"), "product.john.smith:domain");
        
        // domain and username are changed since user/home namespaces are different
        // username impl in authority will replace .'s with -'s

        zmsImpl.userDomain = "user";
        zmsImpl.userDomainPrefix = "user.";
        zmsImpl.homeDomain = "home";
        zmsImpl.homeDomainPrefix = "home.";
        zmsImpl.userAuthority = testPrincipalAuthority;
        assertEquals(zmsImpl.userHomeDomainResource("user.hga:domain"), "home.hga:domain");
        assertEquals(zmsImpl.userHomeDomainResource("user.john.smith:domain"), "home.john-smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("testuser.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("product.john.smith:domain"), "product.john.smith:domain");
        
        // domain and username are changed since user/home namespaces are different
        // username impl in authority is default so we'll end up with same username
        
        zmsImpl.userDomain = "testuser";
        zmsImpl.userDomainPrefix = "testuser.";
        zmsImpl.homeDomain = "home";
        zmsImpl.homeDomainPrefix = "home.";
        zmsImpl.userAuthority = principalAuthority;
        assertEquals(zmsImpl.userHomeDomainResource("user.hga:domain"), "home.hga:domain");
        assertEquals(zmsImpl.userHomeDomainResource("user.john.smith:domain"), "home.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("testuser.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("product.john.smith:domain"), "product.john.smith:domain");
        
        // domain and username are changed since user/home namespaces are different
        // username impl in authority will replace .'s with -'s
        
        zmsImpl.userDomain = "testuser";
        zmsImpl.userDomainPrefix = "testuser.";
        zmsImpl.homeDomain = "home";
        zmsImpl.homeDomainPrefix = "home.";
        zmsImpl.userAuthority = testPrincipalAuthority;
        assertEquals(zmsImpl.userHomeDomainResource("user.hga:domain"), "home.hga:domain");
        assertEquals(zmsImpl.userHomeDomainResource("user.john.smith:domain"), "home.john-smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("testuser.john.smith:domain"), "testuser.john.smith:domain");
        assertEquals(zmsImpl.userHomeDomainResource("product.john.smith:domain"), "product.john.smith:domain");
    }

    @Test
    public void testCreatePrincipalForName() {
        
        ZMSImpl zmsImpl = zmsInit();
        zmsImpl.userDomain = "user";
        zmsImpl.userDomainAlias = null;
        
        Principal principal = zmsImpl.createPrincipalForName("joe");
        assertEquals(principal.getFullName(), "user.joe");
        
        principal = zmsImpl.createPrincipalForName("joe-smith");
        assertEquals(principal.getFullName(), "user.joe-smith");
        
        principal = zmsImpl.createPrincipalForName("user.joe");
        assertEquals(principal.getFullName(), "user.joe");

        principal = zmsImpl.createPrincipalForName("user.joe.storage");
        assertEquals(principal.getFullName(), "user.joe.storage");
        
        principal = zmsImpl.createPrincipalForName("alias.joe");
        assertEquals(principal.getFullName(), "alias.joe");
        
        principal = zmsImpl.createPrincipalForName("alias.joe.storage");
        assertEquals(principal.getFullName(), "alias.joe.storage");
        
        zmsImpl.userDomainAlias = "alias";
        
        principal = zmsImpl.createPrincipalForName("joe");
        assertEquals(principal.getFullName(), "user.joe");
        
        principal = zmsImpl.createPrincipalForName("joe-smith");
        assertEquals(principal.getFullName(), "user.joe-smith");
        
        principal = zmsImpl.createPrincipalForName("user.joe");
        assertEquals(principal.getFullName(), "user.joe");

        principal = zmsImpl.createPrincipalForName("user.joe.storage");
        assertEquals(principal.getFullName(), "user.joe.storage");
        
        principal = zmsImpl.createPrincipalForName("alias.joe");
        assertEquals(principal.getFullName(), "user.joe");
        
        principal = zmsImpl.createPrincipalForName("alias.joe.storage");
        assertEquals(principal.getFullName(), "alias.joe.storage");
    }
}

