/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms;

import com.google.common.io.Resources;
import com.wix.mysql.EmbeddedMysql;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.impl.DefaultAuditLogger;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.provider.DomainDependencyProviderResponse;
import com.yahoo.athenz.zms.provider.ServiceProviderClient;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.METRIC_DEFAULT_FACTORY_CLASS;
import static com.yahoo.athenz.zms.ZMSConsts.*;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

public class ZMSTestInitializer {
    public static final String ZMS_PROP_PUBLIC_KEY = "athenz.zms.publickey";

    private ZMSImpl zms             = null;
    private String adminUser        = null;
    private String pubKey           = null; // assume default is K0
    private String pubKeyK1         = null;
    private String pubKeyK2         = null;
    private String privKey          = null; // assume default is K0
    private String privKeyK1        = null;
    private String privKeyK2        = null;
    private final String auditRef   = "audittest";

    // typically used when creating and deleting domains with all the tests
    //

    private final RsrcCtxWrapper mockDomRsrcCtx = Mockito.mock(RsrcCtxWrapper.class);
    private final com.yahoo.athenz.common.server.rest.ResourceContext mockDomRestRsrcCtx = Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
    private AuditLogger auditLogger = null; // default audit logger

    public static final String MOCKCLIENTADDR = "10.11.12.13";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "unit-test";

    private final HttpServletRequest mockServletRequest = Mockito.mock(HttpServletRequest.class);
    private final HttpServletResponse mockServletResponse = Mockito.mock(HttpServletResponse.class);
    private final NotificationManager mockNotificationManager = Mockito.mock(NotificationManager.class);

    public static final Struct TABLE_PROVIDER_ROLE_ACTIONS = new Struct()
            .with("admin", "*").with("writer", "WRITE").with("reader", "READ");

    public static final Struct RESOURCE_PROVIDER_ROLE_ACTIONS = new Struct()
            .with("writer", "WRITE").with("reader", "READ");

    private static final int BASE_PRODUCT_ID = 400000000; // these product ids will lie in 400 million range
    private static final java.util.Random domainProductId = new java.security.SecureRandom();
    public static synchronized int getRandomProductId() {
        return BASE_PRODUCT_ID + domainProductId.nextInt(99999999);
    }
    private EmbeddedMysql mysqld;

    public void startMemoryMySQL() {
        mysqld = ZMSTestUtils.startMemoryMySQL(DB_USER, DB_PASS);
    }

    public void stopMemoryMySQL() {
        ZMSTestUtils.stopMemoryMySQL(mysqld);
    }

    public void setDatabaseReadOnlyMode(boolean readOnlyMode) {
        zms.dbService.defaultRetryCount = 3;
        ZMSTestUtils.setDatabaseReadOnlyMode(mysqld, readOnlyMode);
    }

    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        System.setProperty(ZMSConsts.ZMS_PROP_OBJECT_STORE_FACTORY_CLASS, "com.yahoo.athenz.zms.store.impl.JDBCObjectStoreFactory");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE, "jdbc:mysql://localhost:3310/zms_server");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_USER, DB_USER);
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_PASSWORD, DB_PASS);

        when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        when(mockServletRequest.isSecure()).thenReturn(true);
        when(mockServletRequest.getRequestURI()).thenReturn("/zms/v1/request");
        when(mockServletRequest.getMethod()).thenReturn("GET");

        System.setProperty(ZMSConsts.ZMS_PROP_FILE_NAME, "src/test/resources/zms.properties");
        System.setProperty(ZMSConsts.ZMS_PROP_METRIC_FACTORY_CLASS, METRIC_DEFAULT_FACTORY_CLASS);
        System.setProperty(ZMSConsts.ZMS_PROP_PROVIDER_ENDPOINTS, ".athenzcompany.com");
        System.setProperty(ZMSConsts.ZMS_PROP_MASTER_COPY_FOR_SIGNED_DOMAINS, "true");

        System.setProperty(ZMSConsts.ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zms_private.pem");
        System.setProperty(ZMS_PROP_PUBLIC_KEY, "src/test/resources/zms_public.pem");
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN, "user.testadminuser");
        System.setProperty(ZMSConsts.ZMS_PROP_AUTHZ_SERVICE_FNAME,
                "src/test/resources/authorized_services.json");
        System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME,
                "src/test/resources/solution_templates.json");
        System.setProperty(ZMSConsts.ZMS_PROP_NOAUTH_URI_LIST,
                "uri1,uri2,uri3+uri4");
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_REF_CHECK_OBJECTS,
                "role,group,policy,service,domain,entity,tenancy,template");
        System.setProperty(ZMSConsts.ZMS_PROP_VALIDATE_ASSERTION_ROLES, "true");
        System.setProperty(ZMSConsts.ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER, "true");
        System.setProperty(ZMSConsts.ZMS_PROP_MAX_POLICY_VERSIONS, "5");

        String certPath = Resources.getResource("service.provider.cert.pem").getPath();
        String keyPath = Resources.getResource("service.provider.key.pem").getPath();
        System.setProperty(ZMSConsts.ZMS_PROP_PROVIDER_KEY_PATH, keyPath);
        System.setProperty(ZMS_PROP_PROVIDER_CERT_PATH, certPath);
        System.setProperty(ZMS_PROP_PROVIDER_TRUST_STORE, "test.truststore");
        System.setProperty(ZMS_PROP_PROVIDER_TRUST_STORE_PASSWORD, "test.truststore.password");

        auditLogger = new DefaultAuditLogger();

        initializeZms();
    }

    public void clearConnections() {
        if (zms != null && zms.objectStore != null) {
            zms.objectStore.clearConnections();
        }
    }

    public com.yahoo.athenz.zms.ResourceContext createResourceContext(Principal prince) {
        return createResourceContext(prince, "someApi");
    }

    public com.yahoo.athenz.zms.ResourceContext createResourceContext(Principal prince, String apiName) {
        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx =
                Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
        when(rsrcCtx.principal()).thenReturn(prince);
        when(rsrcCtx.request()).thenReturn(mockServletRequest);
        when(rsrcCtx.response()).thenReturn(mockServletResponse);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
        when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        when(rsrcCtxWrapper.principal()).thenReturn(prince);
        when(rsrcCtxWrapper.request()).thenReturn(mockServletRequest);
        when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        when(rsrcCtxWrapper.getApiName()).thenReturn(apiName);

        return rsrcCtxWrapper;
    }

    public ResourceContext createResourceContext(Principal principal, HttpServletRequest request) {
        return createResourceContext(principal, request, "someApi");
    }

    public ResourceContext createResourceContext(Principal principal, HttpServletRequest request, String apiName) {
        if (request == null) {
            return createResourceContext(principal, apiName);
        }

        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx =
                Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
        when(rsrcCtx.principal()).thenReturn(principal);
        when(rsrcCtx.request()).thenReturn(request);
        when(rsrcCtx.response()).thenReturn(mockServletResponse);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
        when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        when(rsrcCtxWrapper.request()).thenReturn(request);
        when(rsrcCtxWrapper.principal()).thenReturn(principal);
        when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        when(rsrcCtxWrapper.getApiName()).thenReturn(apiName);

        return rsrcCtxWrapper;
    }

    public ZMSImpl zmsInit() {

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String unsignedCreds = "v=U1;d=user;n=user1";
        // used with the mockDomRestRsrcCtx
        final Principal rsrcPrince = SimplePrincipal.create("user", "user1", unsignedCreds + ";s=signature",
                0, principalAuthority);
        assertNotNull(rsrcPrince);
        ((SimplePrincipal) rsrcPrince).setUnsignedCreds(unsignedCreds);

        when(mockDomRestRsrcCtx.request()).thenReturn(mockServletRequest);
        when(mockDomRestRsrcCtx.principal()).thenReturn(rsrcPrince);
        when(mockDomRsrcCtx.context()).thenReturn(mockDomRestRsrcCtx);
        when(mockDomRsrcCtx.request()).thenReturn(mockServletRequest);
        when(mockDomRsrcCtx.principal()).thenReturn(rsrcPrince);
        when(mockDomRsrcCtx.getApiName()).thenReturn("someApiMethod");
        when(mockDomRsrcCtx.getHttpMethod()).thenReturn("GET");

        String pubKeyName = System.getProperty(ZMS_PROP_PUBLIC_KEY);
        File pubKeyFile = new File(pubKeyName);
        pubKey = Crypto.encodedFile(pubKeyFile);

        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File privKeyFile = new File(privKeyName);
        privKey = Crypto.encodedFile(privKeyFile);

        adminUser = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN);

        ZMSImpl zmsObj = new ZMSImpl();
        zmsObj.serverPublicKeyMap.put("1", pubKeyK1);
        zmsObj.serverPublicKeyMap.put("2", pubKeyK2);
        ZMSImpl.serverHostName = "localhost";
        zmsObj.notificationManager = mockNotificationManager;

        return zmsObj;
    }

    public void loadServerPublicKeys(ZMSImpl zmsImpl) {
        zmsImpl.serverPublicKeyMap.put("0", pubKey);
        zmsImpl.serverPublicKeyMap.put("1", pubKeyK1);
        zmsImpl.serverPublicKeyMap.put("2", pubKeyK2);
    }

    public ZMSImpl getZmsImpl(AuditLogger alogger) {
        System.setProperty(ZMSConsts.ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER, "true");
        ZMSImpl zmsObj = new ZMSImpl();
        zmsObj.auditLogger = alogger;
        zmsObj.dbService.auditLogger = alogger;
        zmsObj.notificationManager = mockNotificationManager;

        ZMSImpl.serverHostName = "localhost";

        ServiceIdentity service = createServiceObject("sys.auth", "zms",
                "http://localhost", "/usr/bin/java", "root", "users", "host1");

        zmsObj.putServiceIdentity(mockDomRsrcCtx, "sys.auth", "zms", auditRef, service);
        return zmsObj;
    }

    private void initializeZms() throws IOException {

        Path path = Paths.get("./src/test/resources/zms_public_k1.pem");
        pubKeyK1 = Crypto.ybase64((new String(Files.readAllBytes(path))).getBytes());

        path = Paths.get("./src/test/resources/zms_public_k2.pem");
        pubKeyK2 = Crypto.ybase64(new String(Files.readAllBytes(path)).getBytes());

        path = Paths.get("./src/test/resources/unit_test_zms_private_k1.pem");
        privKeyK1 = Crypto.ybase64(new String(Files.readAllBytes(path)).getBytes());

        path = Paths.get("./src/test/resources/unit_test_zms_private_k2.pem");
        privKeyK2 = Crypto.ybase64(new String(Files.readAllBytes(path)).getBytes());

        zms = zmsInit();
        zms.serviceProviderClient = Mockito.mock(ServiceProviderClient.class);
        DomainDependencyProviderResponse providerResponse = new DomainDependencyProviderResponse();
        providerResponse.setStatus(PROVIDER_RESPONSE_ALLOW);
        when(zms.serviceProviderClient.getDependencyStatus(Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.any(), Mockito.any())).thenReturn(providerResponse);
    }

    public Membership generateMembership(String roleName, String memberName) {
        return generateMembership(roleName, memberName, null);
    }

    public Membership generateMembership(String roleName, String memberName,
                                          Timestamp expiration) {
        Membership mbr = new Membership();
        mbr.setRoleName(roleName);
        mbr.setMemberName(memberName);
        mbr.setIsMember(true);
        mbr.setExpiration(expiration);
        return mbr;
    }

    public GroupMembership generateGroupMembership(final String groupName, final String memberName) {
        return generateGroupMembership(groupName, memberName, null);
    }

    public GroupMembership generateGroupMembership(final String groupName, final String memberName,
                                                    Timestamp expiration) {
        GroupMembership mbr = new GroupMembership();
        mbr.setGroupName(groupName);
        mbr.setMemberName(memberName);
        mbr.setIsMember(true);
        mbr.setExpiration(expiration);
        return mbr;
    }

    public TopLevelDomain createTopLevelDomainObject(String name,
                                                      String description, String org, String admin) {

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setYpmId(getRandomProductId());

        List<String> admins = new ArrayList<>();
        admins.add(admin);
        dom.setAdminUsers(admins);

        return dom;
    }

    public UserDomain createUserDomainObject(String name, String description, String org) {

        UserDomain dom = new UserDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);

        return dom;
    }

    public SubDomain createSubDomainObject(String name, String parent,
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

    public DomainMeta createDomainMetaObject(String description, String org,
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

    public void checkRoleMember(final List<String> checkList, List<RoleMember> members) {
        boolean found = false;
        for (String roleMemberName: checkList) {
            for (RoleMember roleMember: members) {
                if (roleMember.getMemberName().equals(roleMemberName)){
                    found = true;
                    break;
                }
            }
            if (!found) {
                fail("Member " + roleMemberName + " not found");
            }
        }
    }

    public void checkGroupMember(final List<String> checkList, List<GroupMember> members) {
        boolean found = false;
        for (String groupMemberName: checkList) {
            for (GroupMember groupMember: members) {
                if (groupMember.getMemberName().equals(groupMemberName)){
                    found = true;
                    break;
                }
            }
            if (!found) {
                fail("Member " + groupMemberName + " not found");
            }
        }
    }

    public Group createGroupObject(String domainName, String groupName, String member1, String member2) {

        List<GroupMember> members = new ArrayList<>();
        if (member1 != null) {
            members.add(new GroupMember().setMemberName(member1));
        }
        if (member2 != null) {
            members.add(new GroupMember().setMemberName(member2));
        }
        return createGroupObject(domainName, groupName, members);
    }

    public Group createGroupObject(String domainName, String groupName, List<GroupMember> members) {

        Group group = new Group();
        group.setName(ResourceUtils.groupResourceName(domainName, groupName));
        group.setGroupMembers(members);
        return group;
    }

    public Role createRoleObject(String domainName, String roleName,
                                  String trust) {
        Role role = new Role();
        role.setName(ResourceUtils.roleResourceName(domainName, roleName));
        role.setTrust(trust);
        return role;
    }

    public Role createRoleObject(String domainName, String roleName,
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

    public Role createRoleObject(String domainName, String roleName,
                                  String trust, List<RoleMember> members) {

        Role role = new Role();
        role.setName(ResourceUtils.roleResourceName(domainName, roleName));
        role.setRoleMembers(members);
        if (trust != null) {
            role.setTrust(trust);
        }

        return role;
    }

    public Policy createPolicyObject(String domainName, String policyName,
                                      String roleName, String action,  String resource,
                                      AssertionEffect effect) {
        return createPolicyObject(domainName, policyName, roleName, true,
                action, resource, effect, null, true);
    }

    public Policy createPolicyObject(String domainName, String policyName,
                                      String roleName, String action,  String resource,
                                      AssertionEffect effect, String version, boolean active) {
        return createPolicyObject(domainName, policyName, roleName, true,
                action, resource, effect, version, active);
    }

    public Policy createPolicyObject(String domainName, String policyName,
                                      String roleName, boolean generateRoleName, String action,
                                      String resource, AssertionEffect effect)
    {
        return createPolicyObject(domainName, policyName, roleName, generateRoleName, action,
                resource, effect, null, true);
    }

    public Policy createPolicyObject(String domainName, String policyName,
                                      String roleName, boolean generateRoleName, String action,
                                      String resource, AssertionEffect effect, String version, boolean active) {

        Policy policy = new Policy();
        policy.setName(ResourceUtils.policyResourceName(domainName, policyName));
        policy.setVersion(version);
        policy.setActive(active);

        Assertion assertion = new Assertion();
        assertion.setAction(action);
        assertion.setEffect(effect);
        assertion.setResource(resource);
        if (generateRoleName) {
            assertion.setRole(ResourceUtils.roleResourceName(domainName, roleName));
        } else {
            assertion.setRole(roleName);
        }

        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion);

        policy.setAssertions(assertList);
        return policy;
    }

    public Policy createPolicyObject(String domainName, String policyName) {
        return createPolicyObject(domainName, policyName, "Admin", "*",
                domainName + ":*", AssertionEffect.ALLOW, null, true);
    }

    public Policy createPolicyObject(String domainName, String policyName, String version, boolean active) {
        return createPolicyObject(domainName, policyName, "Role1", "*",
                domainName + ":*", AssertionEffect.ALLOW, version, active);
    }

    public ServiceIdentity createServiceObject(String domainName,
                                                String serviceName, String endPoint, String executable,
                                                String user, String group, String host) {

        ServiceIdentity service = new ServiceIdentity();
        service.setExecutable(executable);
        service.setName(ResourceUtils.serviceResourceName(domainName, serviceName));

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

    public Entity createEntityObject(String domainName, String entityName) {

        Entity entity = new Entity();
        entity.setName(ResourceUtils.entityResourceName(domainName, entityName));

        Struct value = new Struct();
        value.put("Key1", "Value1");
        entity.setValue(value);

        return entity;
    }

    public void setupTenantDomainProviderService(ZMSImpl zms, String tenantDomain, String providerDomain,
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

    public void setupPrincipalSystemMetaDelete(ZMSImpl zms, final String principal,
                                                final String domainName, final String ...attributeNames) {

        Role role = createRoleObject("sys.auth", "metaadmin", null, principal, null);
        zms.putRole(mockDomRsrcCtx, "sys.auth", "metaadmin", auditRef, role);

        Policy policy = new Policy();
        policy.setName("metaadmin");

        List<Assertion> assertList = new ArrayList<>();
        Assertion assertion;

        for (String attributeName : attributeNames) {
            assertion = new Assertion();
            assertion.setAction("delete");
            assertion.setEffect(AssertionEffect.ALLOW);
            assertion.setResource("sys.auth:meta.domain." + attributeName + "." + domainName);
            assertion.setRole("sys.auth:role.metaadmin");
            assertList.add(assertion);
        }

        policy.setAssertions(assertList);

        zms.putPolicy(mockDomRsrcCtx, "sys.auth", "metaadmin", auditRef, policy);
    }

    public void cleanupPrincipalSystemMetaDelete(ZMSImpl zms) {

        zms.deletePolicy(mockDomRsrcCtx, "sys.auth", "metaadmin", auditRef);
        zms.deleteRole(mockDomRsrcCtx, "sys.auth", "metaadmin", auditRef);
    }

    public void setupTenantDomainProviderService(String tenantDomain, String providerDomain,
                                                  String providerService, String providerEndpoint) {
        setupTenantDomainProviderService(zms, tenantDomain, providerDomain, providerService, providerEndpoint);
    }

    public Tenancy createTenantObject(String domain, String service) {

        return createTenantObject(domain, service, true);
    }

    public Tenancy createTenantObject(String domain, String service, boolean createAdminRole) {

        Tenancy tenant = new Tenancy();
        tenant.setDomain(domain);
        tenant.setService(service);
        tenant.setCreateAdminRole(createAdminRole);
        return tenant;
    }

    public boolean verifyRoleMember(Role role, final String memberName) {
        for (RoleMember roleMember : role.getRoleMembers()) {
            if (roleMember.getMemberName().equals(memberName)) {
                return true;
            }
        }
        return false;
    }

    public ZMSImpl getZms() {
        return zms;
    }

    public RsrcCtxWrapper getMockDomRsrcCtx() {
        return mockDomRsrcCtx;
    }

    public com.yahoo.athenz.common.server.rest.ResourceContext getMockDomRestRsrcCtx() {
        return mockDomRestRsrcCtx;
    }

    public String getAuditRef() {
        return auditRef;
    }

    public AuditLogger getAuditLogger() {
        return auditLogger;
    }

    public String getAdminUser() {
        return adminUser;
    }

    public String getPrivKeyK2() {
        return privKeyK2;
    }

    public String getPrivKeyK1() {
        return privKeyK1;
    }

    public String getPrivKey() {
        return privKey;
    }

    public String getPubKeyK2() {
        return pubKeyK2;
    }

    public String getPubKeyK1() {
        return pubKeyK1;
    }

    public String getPubKey() {
        return pubKey;
    }

    public HttpServletRequest getMockServletRequest() {
        return mockServletRequest;
    }

    public HttpServletResponse getMockServletResponse() {
        return mockServletResponse;
    }

    public NotificationManager getMockNotificationManager() {
        return mockNotificationManager;
    }

    public RsrcCtxWrapper contextWithMockPrincipal(String apiName) {
        return contextWithMockPrincipal(apiName, "testadminuser");
    }

    public RsrcCtxWrapper contextWithMockPrincipal(String apiName, String princName) {
        return contextWithMockPrincipal(apiName, "user", princName);
    }

    public RsrcCtxWrapper contextWithMockPrincipal(String apiName, String princDomainName, String princName) {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        RsrcCtxWrapper wrapperCtx = new RsrcCtxWrapper(servletRequest, servletResponse, null, false,
                null, new Object(), apiName, true);
        com.yahoo.athenz.common.server.rest.ResourceContext ctx = wrapperCtx.context();

        Authority adminPrincipalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        String adminUnsignedCreds = "v=U1;d=" + princDomainName + ";n=" + princName;
        Principal principal = SimplePrincipal.create(princDomainName, princName, adminUnsignedCreds + ";s=signature",
                0, adminPrincipalAuthority);
        ((SimplePrincipal) principal).setUnsignedCreds(adminUnsignedCreds);

        final Field principalField;
        try {
            principalField = ctx.getClass().getDeclaredField("principal");
            principalField.setAccessible(true);
            principalField.set(ctx, principal);
        } catch (final NoSuchFieldException | IllegalAccessException ignored) {
            throw new AssertionError("Failed to get Principal::principal");
        }
        return wrapperCtx;
    }

    public RsrcCtxWrapper generateServiceSysAdmin(String caller, String admindomain, String serviceprincipal) {
        RsrcCtxWrapper sysAdminCtx = contextWithMockPrincipal(caller);

        TopLevelDomain dom1 = createTopLevelDomainObject(admindomain,
                "Test Domain1", "testOrg", getAdminUser());
        getZms().postTopLevelDomain(sysAdminCtx, getAuditRef(), dom1);


        Membership membership = new Membership();
        membership.setMemberName(admindomain + "." + serviceprincipal);
        getZms().putMembership(sysAdminCtx, "sys.auth", "admin", admindomain + "." + serviceprincipal, getAuditRef(), membership);
        return contextWithMockPrincipal(caller, admindomain, serviceprincipal);
    }
}
