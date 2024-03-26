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

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.AppenderBase;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.Resources;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.audit.AuditReferenceValidator;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigInteger;
import com.yahoo.athenz.zms.DBService.DataCache;
import com.yahoo.athenz.zms.audit.MockAuditReferenceValidatorImpl;
import com.yahoo.athenz.zms.config.MemberDueDays;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.store.impl.jdbc.JDBCConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.MySQLContainer;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static com.yahoo.athenz.zms.ZMSConsts.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

@SuppressWarnings("SameParameterValue")
public class DBServiceTest {

    @Mock private JDBCConnection mockJdbcConn;
    @Mock private ObjectStore mockObjStore;

    private ZMSImpl zms             = null;
    private String adminUser        = null;
    private String pubKeyK1         = null;
    private String pubKeyK2         = null;
    private final String auditRef   = "audittest";
    private MySQLContainer<?> mysqld;

    // typically used when creating and deleting domains with all the tests
    //
    @Mock private RsrcCtxWrapper mockDomRsrcCtx;
    @Mock private com.yahoo.athenz.common.server.rest.ResourceContext mockDomRestRsrcCtx;

    private static final String MOCKCLIENTADDR = "10.11.12.13";
    @Mock private HttpServletRequest mockServletRequest;

    private static final String DB_USER = "admin";
    private static final String DB_PASS = "unit-test";

    private static final Struct TABLE_PROVIDER_ROLE_ACTIONS = new Struct()
            .with("admin", "*").with("writer", "WRITE").with("reader", "READ");

    private static final int BASE_PRODUCT_ID = 500000000; // these product ids will lie in 500 million range
    private static final java.util.Random domainProductId = new java.security.SecureRandom();

    private static synchronized int getRandomProductId() {
        return BASE_PRODUCT_ID + domainProductId.nextInt(99999999);
    }

    @Mock private NotificationManager mockNotificationManager;

    @BeforeClass
    public void setup() throws Exception {

        MockitoAnnotations.openMocks(this);
        mysqld = ZMSTestUtils.startMemoryMySQL(DB_USER, DB_PASS);
        System.setProperty(ZMSTestInitializer.ZMS_PROP_PUBLIC_KEY, "src/test/resources/zms_public.pem");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zms_private.pem");
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN, "user.testadminuser");

        System.setProperty(ZMSConsts.ZMS_PROP_OBJECT_STORE_FACTORY_CLASS, "com.yahoo.athenz.zms.store.impl.JDBCObjectStoreFactory");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE, mysqld.getJdbcUrl());
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_USER, DB_USER);
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_PASSWORD, DB_PASS);

        System.setProperty(ZMSConsts.ZMS_PROP_FILE_NAME, "src/test/resources/zms.properties");
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_REF_CHECK_OBJECTS,
                "role,group,policy,service,domain,entity,tenancy,template");
        System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME,
                "src/test/resources/solution_templates.json");
        System.setProperty(ZMSConsts.ZMS_PROP_USER_AUTHORITY_CLASS, ZMSConsts.ZMS_PRINCIPAL_AUTHORITY_CLASS);
        System.setProperty(ZMSConsts.ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER, "true");
        String certPath = Resources.getResource("service.provider.cert.pem").getPath();
        String keyPath = Resources.getResource("service.provider.key.pem").getPath();
        System.setProperty(ZMSConsts.ZMS_PROP_PROVIDER_KEY_PATH, keyPath);
        System.setProperty(ZMS_PROP_PROVIDER_CERT_PATH, certPath);
        System.setProperty(ZMS_PROP_PROVIDER_TRUST_STORE, "test.truststore");
        System.setProperty(ZMS_PROP_PROVIDER_TRUST_STORE_PASSWORD, "test.truststore.password");
        System.setProperty(ZMS_PROP_HEADLESS_USER_DOMAIN, "user-headless");
        initializeZms();
    }

    @BeforeMethod
    void initMocks() {
        Mockito.reset(mockJdbcConn, mockObjStore, mockDomRsrcCtx, mockDomRestRsrcCtx, mockServletRequest);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockJdbcConn);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        Mockito.when(mockServletRequest.isSecure()).thenReturn(true);
        Mockito.when(mockDomRestRsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockDomRsrcCtx.request()).thenReturn(mockServletRequest);

        final Principal rsrcPrincipal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority());
        assertNotNull(rsrcPrincipal);
        ((SimplePrincipal) rsrcPrincipal).setUnsignedCreds("v=U1;d=user;n=user1");

        Mockito.when(mockDomRestRsrcCtx.principal()).thenReturn(rsrcPrincipal);
        Mockito.when(mockDomRsrcCtx.context()).thenReturn(mockDomRestRsrcCtx);
        Mockito.when(mockDomRsrcCtx.principal()).thenReturn(rsrcPrincipal);
    }

    private ZMSImpl zmsInit() {

        adminUser = System.getProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN);

        // enable product id support
        System.setProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "true");
        System.setProperty(ZMSConsts.ZMS_PROP_SOLUTION_TEMPLATE_FNAME, "src/test/resources/solution_templates.json");

        System.setProperty(ZMSConsts.ZMS_PROP_MAX_POLICY_VERSIONS, "3");
        return new ZMSImpl();
    }

    private Entity createEntityObject(String domainName, String entityName) {

        Entity entity = new Entity();
        entity.setName(ResourceUtils.entityResourceName(domainName, entityName));

        Struct value = new Struct();
        value.put("Key1", "Value1");
        entity.setValue(value);

        return entity;
    }

    private Group createGroupObject(final String domainName, final String groupName, final String member1,
                                    final String member2) {

        List<GroupMember> members = new ArrayList<>();
        if (member1 != null) {
            members.add(new GroupMember().setMemberName(member1).setActive(true).setApproved(true));
        }
        if (member2 != null) {
            members.add(new GroupMember().setMemberName(member2).setActive(true).setApproved(true));
        }

        return new Group().setName(ResourceUtils.groupResourceName(domainName, groupName)).setGroupMembers(members);
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
        role.setName(ResourceUtils.roleResourceName(domainName, roleName));
        role.setRoleMembers(members);
        if (trust != null) {
            role.setTrust(trust);
        }

        return role;
    }

    private Policy createPolicyObject(String domainName, String policyName) {
        return createPolicyObject(domainName, policyName, "admin", true, "*",
                domainName + ":*", AssertionEffect.ALLOW, null, true);
    }

    private Policy createPolicyObject(String domainName, String policyName,
            String roleName, boolean generateRoleName, String action,
            String resource, AssertionEffect effect, String version, boolean active) {

        Policy policy = new Policy();
        policy.setName(ResourceUtils.policyResourceName(domainName, policyName));
        if (!StringUtils.isEmpty(version)) {
            policy.setVersion(version);
            policy.setActive(active);
        }
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

    private ServiceIdentity createServiceObject(String domainName,
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
        ZMSTestUtils.stopMemoryMySQL(mysqld);
        System.clearProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT);
        System.clearProperty(ZMSConsts.ZMS_PROP_USER_AUTHORITY_CLASS);
        System.clearProperty(ZMSConsts.ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER);
    }

    private TopLevelDomain createTopLevelDomainObject(String name, String description,
            String org, boolean enabled, boolean auditEnabled, String ...admins) {

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setAuditEnabled(auditEnabled);
        dom.setEnabled(enabled);
        dom.setYpmId(getRandomProductId());
        dom.setAdminUsers(new ArrayList<>(List.of(admins)));

        return dom;
    }

    private TopLevelDomain createTopLevelDomainObject(String name,
            String description, String org, String ...admins) {
        return createTopLevelDomainObject(name, description, org, true, false, admins);
    }

    private boolean isValidJSON(String jsonText) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.readTree(jsonText);
        } catch (Exception ex) {
            return false;
        }

        return true;
    }

    @Test
    public void testCheckDomainAuditEnabledFlagTrueRefValid() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain(domainName);

        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledFlagTrueRefValid";
        String principal = "testprincipal";
        zms.dbService.checkDomainAuditEnabled(mockJdbcConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
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
            String description, String org, String ...admins) {

        SubDomain dom = new SubDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setParent(parent);
        dom.setAdminUsers(new ArrayList<>(List.of(admins)));

        return dom;
    }

    @Test
    public void testCheckDomainAuditEnabledFlagTrueRefNull() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain(domainName);

        String caller = "testCheckDomainAuditEnabledFlagTrueRefNull";
        String principal = "testprincipal";
        try {
            zms.dbService.checkDomainAuditEnabled(mockJdbcConn, domainName, null, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
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
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain(domainName);

        String auditCheck = "";
        String caller = "testCheckDomainAuditEnabledFlagTrueRefEmpty";
        String principal = "testprincipal";
        try {
            zms.dbService.checkDomainAuditEnabled(mockJdbcConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
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
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain(domainName);

        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledFlagFalseRefValid";
        String principal = "testprincipal";
        zms.dbService.checkDomainAuditEnabled(mockJdbcConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
    }

    @Test
    public void testCheckDomainAuditEnabledFlagFalseRefNull() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain(domainName);

        String caller = "testCheckDomainAuditEnabledFlagFalseRefNull";
        String principal = "testprincipal";
        zms.dbService.checkDomainAuditEnabled(mockJdbcConn, domainName, null, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
    }

    private void checkRoleMember(final List<String> checkList, List<RoleMember> members) {
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

    @Test
    public void testCheckDomainAuditEnabledFlagFalseRefEmpty() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain(domainName);

        String auditCheck = "";
        String caller = "testCheckDomainAuditEnabledFlagFalseRefEmpty";
        String principal = "testprincipal";
        zms.dbService.checkDomainAuditEnabled(mockJdbcConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
    }

    @Test
    public void testCheckDomainAuditEnabledInvalidDomain() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain(domainName);

        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledDefault";
        String principal = "testprincipal";
        try {
            zms.dbService.checkDomainAuditEnabled(mockJdbcConn, "unknown_domain", auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testCheckDomainAuditEnabledRefValid() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain(domainName);

        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledFlagTrueRefValid";
        String principal = "testprincipal";

        zms.dbService.auditReferenceValidator = Mockito.mock(AuditReferenceValidator.class);
        Mockito.when(zms.dbService.auditReferenceValidator.validateReference(auditCheck, principal, caller)).thenReturn(true);

        zms.dbService.checkDomainAuditEnabled(mockJdbcConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);

        zms.dbService.auditReferenceValidator = null;
    }

    @Test
    public void testCheckDomainAuditEnabledRefFail() {

        String domainName = "audit-test-domain-name";
        Domain domain = new Domain().setAuditEnabled(true).setEnabled(true);
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain(domainName);

        String auditCheck = "testaudit";
        String caller = "testCheckDomainAuditEnabledFlagTrueRefValid";
        String principal = "testprincipal";

        zms.dbService.auditReferenceValidator = Mockito.mock(AuditReferenceValidator.class);
        Mockito.when(zms.dbService.auditReferenceValidator.validateReference(auditCheck, principal, caller)).thenReturn(false);

        try {
            zms.dbService.checkDomainAuditEnabled(mockJdbcConn, domainName, auditCheck, caller, principal, DBService.AUDIT_TYPE_DOMAIN);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zms.dbService.auditReferenceValidator = null;
    }

    @Test
    public void testUpdateTemplateRoleNoMembers() {
        Role role = new Role().setName("_domain_:role.readers");
        Role newRole = zms.dbService.updateTemplateRole(null, role, "athenz", null);
        assertEquals("athenz:role.readers", newRole.getName());
        assertEquals(0, newRole.getRoleMembers().size());
    }

    @Test
    public void testUpdateTemplateRoleWithTrust() {
        Role role = new Role().setName("_domain_:role.readers").setTrust("trustdomain");
        Domain domain = new Domain().setName("trustdomain");
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        when(con.getDomain("trustdomain")).thenReturn(domain);

        Role newRole = zms.dbService.updateTemplateRole(con, role, "athenz", null);
        assertEquals("athenz:role.readers", newRole.getName());
        assertEquals("trustdomain", newRole.getTrust());
        assertEquals(0, newRole.getRoleMembers().size());

        // retry the operation with parameters

        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("service").setValue("storage"));

        newRole = zms.dbService.updateTemplateRole(con, role, "athenz", params);
        assertEquals("athenz:role.readers", newRole.getName());
        assertEquals("trustdomain", newRole.getTrust());
        assertEquals(0, newRole.getRoleMembers().size());

        // empty and null trust values do not use the connection object

        role = new Role().setName("_domain_:role.readers").setTrust(null);
        assertNotNull(zms.dbService.updateTemplateRole(null, role, "athenz", null));
        assertNotNull(zms.dbService.updateTemplateRole(null, role, "athenz", params));

        role = new Role().setName("_domain_:role.readers").setTrust("");
        assertNotNull(zms.dbService.updateTemplateRole(null, role, "athenz", null));
        assertNotNull(zms.dbService.updateTemplateRole(null, role, "athenz", params));
    }

    @Test
    public void testUpdateTemplateRoleWithTrustKeyword() {
        Role role = new Role().setName("_domain_:role.readers").setTrust("_trustdomain_");
        Domain domain = new Domain().setName("sports");
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        when(con.getDomain("sports")).thenReturn(domain);
        when(con.getDomain("weather")).thenReturn(null);
        when(con.getDomain("_trustdomain_")).thenReturn(null);

        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("trustdomain").setValue("sports"));

        Role newRole = zms.dbService.updateTemplateRole(con, role, "athenz", params);
        assertEquals("athenz:role.readers", newRole.getName());
        assertEquals("sports", newRole.getTrust());
        assertEquals(0, newRole.getRoleMembers().size());

        // domain does not exist with specified keyword

        params = new ArrayList<>();
        params.add(new TemplateParam().setName("trustdomain").setValue("weather"));
        assertNull(zms.dbService.updateTemplateRole(con, role, "athenz", params));

        // without params it should fail as well

        assertNull(zms.dbService.updateTemplateRole(con, role, "athenz", null));
    }

    @Test
    public void testUpdateTemplateRoleWithTrustNotValid() {
        Role role = new Role().setName("_domain_:role.readers").setTrust("trustdomain");
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        when(con.getDomain("trustdomain")).thenReturn(null);
        assertNull(zms.dbService.updateTemplateRole(con, role, "athenz", null));
    }

    @Test
    public void testUpdateTemplateRoleWithTrustPointingToItself() {

        Role role = new Role().setName("_domain_:role.readers").setTrust("sports");
        Domain domain = new Domain().setName("sports");
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        when(con.getDomain("sports")).thenReturn(domain);

        // no substitution - pointing to itself

        assertNull(zms.dbService.updateTemplateRole(con, role, "sports", null));

        // with keyword substitution

        role = new Role().setName("_domain_:role.readers").setTrust("_trustdomain_");
        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("trustdomain").setValue("sports"));
        assertNull(zms.dbService.updateTemplateRole(con, role, "sports", params));
    }

    @Test
    public void testUpdateTemplateRoleWithMembers() {
        Role role = new Role().setName("_domain_:role.readers");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1"));
        members.add(new RoleMember().setMemberName("user.user2"));
        members.add(new RoleMember().setMemberName("_domain_.user3"));
        role.setRoleMembers(members);

        Role newRole = zms.dbService.updateTemplateRole(null, role, "athenz", null);
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
        Role newRole = zms.dbService.updateTemplateRole(null, role, "athenz", params);
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
                "role1", true, "read", "_domain_:*", AssertionEffect.ALLOW, null, true);

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
                "_api_-role1", true, "read", "_domain_:_api___service__*", AssertionEffect.ALLOW, null, true);

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
                "coretech:role.role1", false, "read", "coretech:*", AssertionEffect.ALLOW, null, true);

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
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockJdbcConn, "coretech.storage.role1",
                "coretech2.role.", null, "tenant"));
    }

    @Test
    public void testIsTenantRolePrefixMatchResGroupNullTenant() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockJdbcConn, "coretech.storage.res_group.reader",
                "coretech.storage.", "reader", "tenant"));
    }

    @Test
    public void testIsTenantRolePrefixMatchResGroupMultipleComponents() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockJdbcConn, "coretech.storage.res_group.group1.group2.group3.reader",
                "coretech.storage.", "group1.group2.group3", "tenant"));
    }

    @Test
    public void testIsTenantRolePrefixMatchResGroupSingleComponent() {
        assertTrue(zms.dbService.isTenantRolePrefixMatch(mockJdbcConn, "coretech.storage.res_group.group1.access",
                "coretech.storage.res_group.group1.", "group1", "tenant"));
    }

    @Test
    public void testIsTenantRolePrefixMatchResGroupSubstring() {
        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockJdbcConn, "coretech.storage.res_group.group1.group2.access",
                "coretech.storage.res_group1.group1.", "group1", "tenant"));
    }

    @Test
    public void testIsTenantRolePrefixMatchSubdomainCheckExists() {

        Domain domain = new Domain().setAuditEnabled(false).setEnabled(true);
        Mockito.doReturn(domain).when(mockJdbcConn).getDomain("tenant.sub");

        // since subdomain exists - we're assuming is not a tenant role

        assertFalse(zms.dbService.isTenantRolePrefixMatch(mockJdbcConn, "coretech.storage.sub.reader",
                "coretech.storage.", null, "tenant"));
    }

    @Test
    public void testIsTenantRolePrefixMatchSubdomainCheckDoesNotExist() {

        Mockito.doReturn(null).when(mockJdbcConn).getDomain("tenant.sub");

        // subdomain does not exist thus this is a tenant role

        assertTrue(zms.dbService.isTenantRolePrefixMatch(mockJdbcConn, "coretech.storage.sub.reader",
                "coretech.storage.", null, "tenant"));
    }

    @Test
    public void testIsTrustRoleForTenantPrefixNoMatch() {

        assertFalse(zms.dbService.isTrustRoleForTenant(mockJdbcConn, "sports", "coretech.storage.tenant.admin",
                "coretech2.storage.tenant.", null, "athenz"));
    }

    @Test
    public void testIsTrustRoleForTenantNoRole() {

        Mockito.doReturn(null).when(mockJdbcConn).getRole("sports", "coretech.storage.tenant.admin");

        assertFalse(zms.dbService.isTrustRoleForTenant(mockJdbcConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", null, "athenz"));
    }

    @Test
    public void testIsTrustRoleForTenantNoRoleTrust() {

        Role role = new Role().setName(ResourceUtils.roleResourceName("sports",  "coretech.storage.tenant.admin"));
        Mockito.doReturn(role).when(mockJdbcConn).getRole("sports", "coretech.storage.tenant.admin");

        assertFalse(zms.dbService.isTrustRoleForTenant(mockJdbcConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", null, "athenz"));
    }

    @Test
    public void testIsTrustRoleForTenantRoleTrustMatch() {

        Role role = new Role().setName(ResourceUtils.roleResourceName("sports",  "coretech.storage.tenant.admin"))
                .setTrust("athenz");
        Mockito.doReturn(role).when(mockJdbcConn).getRole("sports", "coretech.storage.tenant.admin");

        assertTrue(zms.dbService.isTrustRoleForTenant(mockJdbcConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", null, "athenz"));
    }

    @Test
    public void testIsTrustRoleForTenantRoleTrustNoMatch() {

        Role role = new Role().setName(ResourceUtils.roleResourceName("sports",  "coretech.storage.tenant.admin"))
                .setTrust("athenz2");
        Mockito.doReturn(role).when(mockJdbcConn).getRole("sports", "coretech.storage.tenant.admin");

        assertFalse(zms.dbService.isTrustRoleForTenant(mockJdbcConn, "sports", "coretech.storage.tenant.admin",
                "coretech.storage.tenant.", null, "athenz"));
    }

    @Test
    public void testExecutePutPolicyCreate() {

        String domainName = "testreplacepolicycreatedomain";
        String policyName = "policy1";

        TopLevelDomain dom = createTopLevelDomainObject(domainName, null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom);

        Policy policy = createPolicyObject(domainName, policyName);
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName, policy,
                auditRef, "testReplacePolicyCreate", false);

        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes);
        assertEquals(policyRes.getName(), domainName + ":policy." + policyName);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutPolicyVersion() {
        String domainName = "policyadddom1";
        String policyName = "policy1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Policy policy1 = createPolicyObject(domainName, policyName);
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName,
                policy1, auditRef, "putPolicy", false);

        Policy policyRes2 = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), domainName + ":policy." + policyName);
        assertEquals(policyRes2.getVersion(), "0");
        assertTrue(policyRes2.getActive());

        // Put new version
        zms.dbService.executePutPolicyVersion(mockDomRsrcCtx, domainName, policyName, "new-version", null, auditRef, "putPolicyVersion", false);

        // Getting policy will return original active policy version
        policyRes2 = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), domainName + ":policy." + policyName);
        assertEquals(policyRes2.getVersion(), "0");
        assertTrue(policyRes2.getActive());

        // Get new non-active version
        policyRes2 = zms.getPolicyVersion(mockDomRsrcCtx, domainName, policyName, "new-version");
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), domainName + ":policy." + policyName);
        assertEquals(policyRes2.getVersion(), "new-version");
        assertFalse(policyRes2.getActive());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutPolicyVersionMaxReached() {
        String domainName = "policyadddom1";
        String policyName = "policy1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Policy policy1 = createPolicyObject(domainName, policyName);
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName,
                policy1, auditRef, "putPolicy", false);

        // Put new version
        zms.dbService.executePutPolicyVersion(mockDomRsrcCtx, domainName, policyName, "new-version",
                null, auditRef, "putPolicyVersion", false);

        // Put third version (max number is 3)
        zms.dbService.executePutPolicyVersion(mockDomRsrcCtx, domainName, policyName, "new-version2",
                null, auditRef, "putPolicyVersion", false);

        // Trying to put another version will throw an exception
        try {
            zms.dbService.executePutPolicyVersion(mockDomRsrcCtx, domainName, policyName, "new-version3",
                    null, auditRef, "putPolicyVersion", false);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (429): {code: 429, message: \"unable to put "
                    + "policy: policy1, version: new-version3, max number of versions reached (3)\"}");
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutPolicyVersionFailure() {
        String domainName = "policy-put-policy-version-failure";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        Policy originalPolicyVersion = createPolicyObject(domainName, policyName);

        Map<String, TagValueList> tags = new HashMap<>();
        tags.put("tagKey1", new TagValueList().setList(Collections.singletonList("tagValue1")));

        Mockito.when(mockJdbcConn.insertPolicy(domainName, originalPolicyVersion))
                .thenReturn(true).thenReturn(false).thenReturn(true);
        Mockito.when(mockJdbcConn.insertPolicyTags(domainName, policyName, tags, null))
                .thenReturn(true);
        Mockito.when(mockJdbcConn.listAssertions(eq(domainName), eq(policyName), isNull()))
                .thenReturn(originalPolicyVersion.getAssertions());
        Mockito.when(mockJdbcConn.listAssertions(domainName, policyName, "new-version"))
                .thenReturn(originalPolicyVersion.getAssertions());

        Mockito.when(mockJdbcConn.insertAssertion(eq(domainName), eq(policyName), isNull(), any()))
                .thenReturn(true).thenReturn(false);
        Mockito.when(mockJdbcConn.insertAssertion(eq(domainName), eq(policyName), eq("new-version"), any()))
                .thenReturn(false).thenReturn(true);
        Mockito.when(mockJdbcConn.insertPolicyTags(eq(domainName), eq(policyName), any(), eq("new-version")))
                .thenReturn(false);
        Mockito.when(mockJdbcConn.getPolicy(eq(domainName), eq(policyName), isNull()))
                .thenReturn(null).thenReturn(originalPolicyVersion);
        Mockito.when(mockJdbcConn.getPolicyTags(eq(domainName), eq(policyName), isNull()))
                .thenReturn(tags);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        // Put policy
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName, originalPolicyVersion,
                auditRef, "putPolicy", false);

        // Put policy version - simulate failure in inserting policy
        try {
            zms.dbService.executePutPolicyVersion(mockDomRsrcCtx, domainName, policyName, "new-version",
                    null, auditRef, "putPolicyVersion", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (500): {code: 500, message: \"unable to put "
                    + "policy: policy-put-policy-version-failure:policy.policy1, version: new-version\"}");
        }

        // Put policy version - simulate failure in inserting assertion
        try {
            zms.dbService.executePutPolicyVersion(mockDomRsrcCtx, domainName, policyName, "new-version",
                    null, auditRef, "putPolicyVersion", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (500): {code: 500, message: \"unable to put "
                    + "policy: policy-put-policy-version-failure:policy.policy1, version: new-version, "
                    + "fail copying assertions\"}");
        }

        // Put policy version - simulate failure in inserting tags
        try {
            zms.dbService.executePutPolicyVersion(mockDomRsrcCtx, domainName, policyName, "new-version",
                    null, auditRef, "putPolicyVersion", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (500): {code: 500, message: \"unable to put "
                    + "policy: policy-put-policy-version-failure:policy.policy1, version: new-version, "
                    + "fail copying tags\"}");
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutPolicyVersionConditionsFailure() {
        String domainName = "policy-put-policy-version-condition-failure";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Policy originalPolicyVersion = createPolicyObject(domainName, policyName);
        Map<String, AssertionConditionData> conditionsMap = new HashMap<>();
        conditionsMap.put("cond1", new AssertionConditionData()
                .setOperator(AssertionConditionOperator.EQUALS).setValue("testVal"));
        final List<AssertionCondition> assertionConditions = new ArrayList<>();
        assertionConditions.add(new AssertionCondition().setConditionsMap(conditionsMap));
        originalPolicyVersion.getAssertions().get(0).setConditions(
                new AssertionConditions().setConditionsList(assertionConditions));
        originalPolicyVersion.getAssertions().get(0).setId(1L);
        Mockito.when(mockJdbcConn.insertPolicy(domainName, originalPolicyVersion)).thenReturn(true);
        Mockito.when(mockJdbcConn.listAssertions(eq(domainName), eq(policyName), isNull()))
                .thenReturn(originalPolicyVersion.getAssertions());
        Mockito.when(mockJdbcConn.getPolicy(eq(domainName), eq(policyName), isNull())).thenReturn(originalPolicyVersion);
        Mockito.when(mockJdbcConn.insertAssertion(eq(domainName), eq(policyName), any(), any())).thenReturn(true);
        Mockito.when(mockJdbcConn.getAssertionConditions(anyLong())).thenReturn(assertionConditions);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        // Put policy version - simulate failure in inserting assertion conditions
        try {
            zms.dbService.executePutPolicyVersion(mockDomRsrcCtx, domainName, policyName, "new-version",
                    null, auditRef, "putPolicyVersion", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (500): {code: 500, message: \"unable to put "
                    + "policy: policy-put-policy-version-condition-failure:policy.policy1, version: new-version, "
                    + "fail copying assertions\"}");
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testProcessPolicyAssertionsNull() {
        assertTrue(zms.dbService.processPolicyCopyAssertions(null, new Policy(), null, null, null, null));
    }

    @Test
    public void testExecuteSetActivePolicyFailure() {
        String domainName = "policy-set-active-failure";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Policy policy = createPolicyObject(domainName, policyName);
        Mockito.when(mockJdbcConn.getPolicy(eq(domainName), eq(policyName), isNull())).thenReturn(policy);
        Mockito.when(mockJdbcConn.getPolicy(eq(domainName), eq(policyName), eq("1"))).thenReturn(policy);
        Mockito.when(mockJdbcConn.setActivePolicyVersion(eq(domainName), eq(policyName), eq("1"))).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeSetActivePolicy(mockDomRsrcCtx, domainName, policyName, "1", auditRef, "setActivePolicy");
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (500): {code: 500, message: \"unable to set active policy version: 1 for policy: policy1 in domain: policy-set-active-failure\"}");
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteSetActivePolicyRetryException() {
        String domainName = "policy-set-active-retry";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Policy policy = createPolicyObject(domainName, policyName);
        Mockito.when(mockJdbcConn.getPolicy(eq(domainName), eq(policyName), isNull())).thenReturn(policy);
        Mockito.when(mockJdbcConn.getPolicy(eq(domainName), eq(policyName), eq("1"))).thenReturn(policy);
        Mockito.when(mockJdbcConn.setActivePolicyVersion(eq(domainName), eq(policyName), eq("1")))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "db conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeSetActivePolicy(mockDomRsrcCtx, domainName, policyName, "1", auditRef, "setActivePolicy");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePolicyVersionFailure() {
        String domainName = "policy-delete-version";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Policy originalPolicyVersion = createPolicyObject(domainName, policyName);
        originalPolicyVersion.setActive(false);
        Mockito.when(mockJdbcConn.getPolicy(eq(domainName), eq(policyName), eq("0"))).thenReturn(originalPolicyVersion);
        Mockito.when(mockJdbcConn.deletePolicyVersion(eq(domainName), eq(policyName), eq("0"))).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeletePolicyVersion(mockDomRsrcCtx, domainName, policyName, "0", auditRef, "deletePolicyVersion");
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (404): {code: 404, message: \"deletePolicyVersion: unable to delete policy: policy1, version: 0\"}");
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutPolicyExisting() {

        String domainName = "testreplacepolicycreatedomain";
        String policyName = "policy1";

        TopLevelDomain dom = createTopLevelDomainObject(domainName, null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom);

        Policy policy = createPolicyObject(domainName, policyName);
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName, policy,
                auditRef, "testExecutePutPolicyExisting", false);

        Policy policyRes = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes);
        assertEquals(policyRes.getName(), domainName + ":policy." + policyName);
        List<Assertion> asserts = policyRes.getAssertions();
        int origAssertCnt = (asserts == null) ? 0 : asserts.size();

        // replace the existing policy with a modified version

        Assertion assertion = new Assertion();
        assertion.setAction("test").setEffect(AssertionEffect.ALLOW)
                .setResource("testreplacepolicycreatedomain:tests")
                .setRole("testreplacepolicycreatedomain:role.readers");
        asserts = policy.getAssertions();
        asserts.add(assertion);
        policy = policy.setAssertions(asserts);

        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName, policy,
                auditRef, "testExecutePutPolicyExisting", false);

        Policy policyRes2 = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes2);
        asserts = policyRes2.getAssertions();
        assertTrue(asserts.size() > origAssertCnt);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutPolicyFailure() {

        String domainName = "testExecutePutPolicyFailure";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        Policy policy = createPolicyObject(domainName, policyName);
        Mockito.when(mockJdbcConn.insertPolicy(domainName, policy)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName, policy,
                    auditRef, "testExecutePutPolicyFailure", false);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (500): {code: 500, message: \"unable to put policy: testExecutePutPolicyFailure:policy.policy1\"}");
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutPolicyMissingAuditRef() {
        // create a new policy without an auditref

        String domain = "testreplacepolicymissingauditref";
        TopLevelDomain dom = createTopLevelDomainObject(
            domain, null, null, adminUser);
        dom.setAuditEnabled(true);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom);

        Policy policy = createPolicyObject(domain, "policy1");
        try {
            zms.dbService.executePutPolicy(mockDomRsrcCtx, domain, "policy1", policy,
                    null, "testExecutePutPolicyMissingAuditRef", false);
            fail("requesterror not thrown by replacePolicy.");
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zms.deleteTopLevelDomain(mockDomRsrcCtx, domain, auditRef, null);
        }
    }

    @Test
    public void testExecuteDeleteEntity() {

        String domainName = "delentitydom1";
        String entityName = "entity1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Entity entity1 = createEntityObject(domainName, entityName);
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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecuteDeleteMembership() {

        String domainName = "mbrdeldom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);
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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecuteDeletePolicy() {

        String domainName = "policydeldom1";
        String policyName = "policy1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Policy policy1 = createPolicyObject(domainName, policyName);
        zms.putPolicy(mockDomRsrcCtx, domainName, policyName, auditRef, false, null, policy1);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecuteDeletePublicKeyEntry() {

        String domainName = "servicedelpubkeydom1";
        String serviceName = "service1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, false, null, service);

        zms.dbService.executeDeletePublicKeyEntry(mockDomRsrcCtx, domainName, serviceName,
                "1", auditRef, "deletePublicKeyEntry");

        ServiceIdentity serviceRes = zms.getServiceIdentity(mockDomRsrcCtx, domainName, serviceName);

        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        boolean found = false;
        for (PublicKeyEntry entry : keyList) {
            if (entry.getId().equals("1")) {
                found = true;
                break;
            }
        }
        assertFalse(found);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecuteDeletePublicKeyEntryLastKeyAllowed() {

        String domainName = "servicedelpubkeydom1";
        String serviceName = "service1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, false, null, service);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecuteDeleteRole() {

        String domainName = "delroledom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecuteDeleteServiceIdentity() {

        String domainName = "servicedeldom1";
        String serviceName = "service1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        ServiceIdentity service1 = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, false, null, service1);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutEntity() {

        String domainName = "createentitydom1";
        String entityName = "entity1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Entity entity1 = createEntityObject(domainName, entityName);
        zms.dbService.executePutEntity(mockDomRsrcCtx, domainName, entityName,
                entity1, auditRef, "putEntity");

        Entity entity2 = zms.getEntity(mockDomRsrcCtx, domainName, entityName);
        assertNotNull(entity2);
        assertEquals(entity2.getName(), ResourceUtils.entityResourceName(domainName, entityName));

        Struct value = entity2.getValue();
        assertEquals("Value1", value.getString("Key1"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutEntityUpdate() {

        String domainName = "createentitydom1-mod";
        String entityName = "entity1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Entity entity1 = createEntityObject(domainName, entityName);
        zms.dbService.executePutEntity(mockDomRsrcCtx, domainName, entityName,
                entity1, auditRef, "putEntity");

        Struct value = new Struct();
        value.put("Key2", "Value2");
        entity1.setValue(value);

        zms.dbService.executePutEntity(mockDomRsrcCtx, domainName, entityName,
                entity1, auditRef, "putEntity");

        Entity entity2 = zms.getEntity(mockDomRsrcCtx, domainName, entityName);
        assertNotNull(entity2);
        assertEquals(entity2.getName(), ResourceUtils.entityResourceName(domainName, entityName));
        value = entity2.getValue();
        assertEquals("Value2", value.getString("Key2"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutDomainMeta() {

        final String domainName = "metadom1";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Domain resDom1 = zms.getDomain(mockDomRsrcCtx, domainName);
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
        assertNull(resDom1.getBusinessService());
        assertNull(resDom1.getMemberPurgeExpiryDays());

        // update meta with values for account and product ids

        DomainMeta meta = new DomainMeta().setDescription("Test2 Domain").setOrg("NewOrg")
                .setEnabled(true).setAuditEnabled(false).setAccount("12345").setYpmId(1001)
                .setCertDnsDomain("athenz1.cloud").setMemberExpiryDays(10).setTokenExpiryMins(20)
                .setServiceExpiryDays(45).setGroupExpiryDays(50).setBusinessService("service1")
                .setMemberPurgeExpiryDays(90);
        Domain metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, null, false, auditRef, "putDomainMeta");
        metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, "productid", true, auditRef, "putDomainMeta");
        metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, "account", true, auditRef, "putDomainMeta");
        metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, "certdnsdomain", true, auditRef, "putDomainMeta");
        metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, "org", true, auditRef, "putDomainMeta");

        Domain resDom2 = zms.getDomain(mockDomRsrcCtx, domainName);
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
        assertEquals(Integer.valueOf(50), resDom2.getGroupExpiryDays());
        assertEquals(Integer.valueOf(90), resDom2.getMemberPurgeExpiryDays());
        assertNull(resDom2.getRoleCertExpiryMins());
        assertNull(resDom2.getServiceCertExpiryMins());
        assertEquals("service1", resDom2.getBusinessService());

        // now update without account and product ids

        meta = new DomainMeta().setDescription("Test2 Domain-New").setOrg("NewOrg-New")
                .setEnabled(true).setAuditEnabled(false).setRoleCertExpiryMins(30)
                .setServiceCertExpiryMins(40).setSignAlgorithm("rsa")
                .setServiceExpiryDays(45).setGroupExpiryDays(50)
                .setMemberPurgeExpiryDays(90);
        metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, null, false, auditRef, "putDomainMeta");
        metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, "org", true, auditRef, "putDomainMeta");

        Domain resDom3 = zms.getDomain(mockDomRsrcCtx, domainName);
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
        assertEquals(Integer.valueOf(50), resDom3.getGroupExpiryDays());
        assertEquals(Integer.valueOf(30), resDom3.getRoleCertExpiryMins());
        assertEquals(Integer.valueOf(40), resDom3.getServiceCertExpiryMins());
        assertEquals(Integer.valueOf(90), resDom3.getMemberPurgeExpiryDays());
        assertEquals(resDom3.getSignAlgorithm(), "rsa");
        assertEquals("service1", resDom3.getBusinessService());

        meta = new DomainMeta().setDescription("Test2 Domain-New").setOrg("NewOrg-New")
                .setEnabled(true).setAuditEnabled(false).setRoleCertExpiryMins(300)
                .setServiceCertExpiryMins(400).setTokenExpiryMins(500)
                .setSignAlgorithm("ec").setServiceExpiryDays(20).setGroupExpiryDays(25)
                .setBusinessService("service2").setMemberPurgeExpiryDays(120);
        metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, null, false, auditRef, "putDomainMeta");

        Domain resDom4 = zms.getDomain(mockDomRsrcCtx, domainName);
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
        assertEquals(Integer.valueOf(25), resDom4.getGroupExpiryDays());
        assertEquals(Integer.valueOf(300), resDom4.getRoleCertExpiryMins());
        assertEquals(Integer.valueOf(400), resDom4.getServiceCertExpiryMins());
        assertEquals(Integer.valueOf(120), resDom4.getMemberPurgeExpiryDays());
        assertEquals(resDom4.getSignAlgorithm(), "ec");
        assertEquals("service2", resDom4.getBusinessService());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutDomainMetaTagFailure() {

        final String domainName = "domain-meta-tag-failure";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Map<String, TagValueList> tags = new HashMap<>();
        tags.put("key1", new TagValueList().setList(Collections.singletonList("value1")));
        DomainMeta meta = new DomainMeta().setDescription("Test2 Domain")
                .setTags(tags);

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.updateDomain(any())).thenReturn(true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domain, meta,
                    null, false, auditRef, "tag-failure");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("Unable to update tags"));
        }

        zms.dbService.store = saveStore;
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutDomainMetaContactFailure() {

        final String domainName = "domain-meta-tag-failure";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Map<String, String> contacts = new HashMap<>();
        contacts.put("security-contact", "user.joe");
        DomainMeta meta = new DomainMeta().setDescription("Test2 Domain")
                .setContacts(contacts);

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.updateDomain(any())).thenReturn(true);
        Mockito.when(mockJdbcConn.insertDomainContact(domainName, "security-contact", "user.joe"))
                .thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domain, meta,
                    null, false, auditRef, "contact-failure");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("Unable to update contacts"));
        }

        zms.dbService.store = saveStore;
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutDomainMetaRetryException() {

        String domainName = "metadom1retry";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        DomainMeta meta = new DomainMeta().setDescription("Test2 Domain").setOrg("NewOrg")
                .setEnabled(true).setAuditEnabled(false).setAccount("12345").setYpmId(1001);

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.updateDomain(any()))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            Domain metaDomain = zms.dbService.getDomain(domainName, true);
            zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta,
                    null, false, auditRef, "testExecutePutDomainMetaRetryException");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutMembership() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("coretech",
                "Test Domain2", "testOrg", adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom2);

        SubDomain subDom2 = createSubDomainObject("storage", "coretech",
                "Test Domain2", "testOrg", adminUser);
        zms.postSubDomain(mockDomRsrcCtx, "coretech", auditRef, null, subDom2);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe"), auditRef, "putMembership", false);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("coretech.storage"), auditRef, "putMembership", false);

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

        zms.deleteSubDomain(mockDomRsrcCtx, "coretech", "storage", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "coretech", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutMembershipInvalidRoleFailure() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        Mockito.when(mockJdbcConn.insertRoleMember(anyString(), anyString(), any(RoleMember.class),
                anyString(), anyString())).thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.getRole(domainName, roleName)).thenReturn(null);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                    new RoleMember().setMemberName("user.doe"), auditRef, "putMembership", false);
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

        Mockito.when(mockJdbcConn.insertRoleMember(anyString(), anyString(), any(RoleMember.class),
                anyString(), anyString())).thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Role role = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        Mockito.when(mockJdbcConn.getRole(domainName, roleName)).thenReturn(role);
        Membership membership = new Membership().setMemberName("user.doe").setIsMember(false);
        Mockito.when(mockJdbcConn.getRoleMember(domainName, roleName, "user.doe", 0, false)).thenReturn(membership);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                    new RoleMember().setMemberName("user.doe"), auditRef, "putMembership", false);
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

        Mockito.when(mockJdbcConn.insertRoleMember(anyString(), anyString(), any(RoleMember.class),
                anyString(), anyString())).thenThrow(new ResourceException(ResourceException.CONFLICT));
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Role role = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        Mockito.when(mockJdbcConn.getRole(domainName, roleName)).thenReturn(role);
        Membership membership = new Membership().setMemberName("user.doe").setIsMember(false);
        Mockito.when(mockJdbcConn.getRoleMember(domainName, roleName, "user.doe", 0, false)).thenReturn(membership);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                    new RoleMember().setMemberName("user.doe"), auditRef, "putMembership", false);
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
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, "sys.auth",
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);
        Membership membership = new Membership().setMemberName("user.doe").setIsMember(false);
        Mockito.when(mockJdbcConn.getRoleMember(domainName, roleName, "user.doe", 0, false)).thenReturn(membership);

        try {
            zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                    new RoleMember().setMemberName("user.doe"), auditRef, "putMembership", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutPolicy() {

        String domainName = "policyadddom1";
        String policyName = "policy1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Policy policy1 = createPolicyObject(domainName, policyName);
        Policy policy2 = zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, policyName,
                policy1, auditRef, "putPolicy", true);

        assertNotNull(policy2);
        assertEquals(policy2.getName(), domainName + ":policy." + policyName);

        Policy policyRes2 = zms.getPolicy(mockDomRsrcCtx, domainName, policyName);
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), domainName + ":policy." + policyName);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutPolicyInvalidDomain() {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyAddDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Policy policy1 = createPolicyObject("PolicyAddDom1", "Policy1");

        try {
            zms.dbService.executePutPolicy(mockDomRsrcCtx, "PolicyAddDom1Invalid", "Policy1",
                    policy1, auditRef, "putPolicy", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "PolicyAddDom1", auditRef, null);
    }

    @Test
    public void testExecutePutPublicKeyEntry() {

        String domainName = "servicepubpubkeydom1";
        String serviceName = "service1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.putServiceIdentity(mockDomRsrcCtx, domainName, serviceName, auditRef, false, null, service);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecuteDeleteServiceIdentityFailure() {

        String domainName = "servicedelete1";
        String serviceName = "service1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteServiceIdentity(domainName, serviceName)).thenReturn(false);

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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteServiceIdentity(domainName, serviceName))
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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteEntity(domainName, entityName)).thenReturn(false);

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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteEntity(domainName, entityName))
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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteRole(domainName, roleName)).thenReturn(false);

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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteRole(domainName, roleName))
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
    public void testExecuteDeleteAssertionNotFoundFailure() {

        String domainName = "policy-assertion-delete-notfound-failure";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.getAssertion(domainName, policyName, 1001L)).thenReturn(null);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeleteAssertion(mockDomRsrcCtx, domainName, policyName, null,
                    1001L, auditRef, "deleteAssertion");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteAssertionRequestFailure() {

        String domainName = "policy-assertion-delete-request-failure";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Assertion assertion = new Assertion().setRole("reader").setResource("table")
                .setAction("update").setId(1001L);
        Mockito.when(mockJdbcConn.getAssertion(domainName, policyName, 1001L)).thenReturn(assertion);
        Mockito.when(mockJdbcConn.deleteAssertion(domainName, policyName, null, 1001L)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeleteAssertion(mockDomRsrcCtx, domainName, policyName, null,
                    1001L, auditRef, "deleteAssertion");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteAssertionFailureRetry() {

        String domainName = "policy-delete-assertion-failure-retry";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Assertion assertion = new Assertion().setRole("reader").setResource("table")
                .setAction("update").setId(1001L);
        Mockito.when(mockJdbcConn.getAssertion(domainName, policyName, 1001L)).thenReturn(assertion);
        Mockito.when(mockJdbcConn.deleteAssertion(domainName, policyName, null, 1001L))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeleteAssertion(mockDomRsrcCtx, domainName, policyName, null,
                    1001L, auditRef, "deleteAssertion");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutAssertionFailureRequestError() {

        String domainName = "policy-put-assertion-failure-request-error";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Assertion assertion = new Assertion().setRole("reader").setResource("table")
                .setAction("update").setId(1001L);
        Mockito.when(mockJdbcConn.insertAssertion(domainName, policyName, null, assertion)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutAssertion(mockDomRsrcCtx, domainName, policyName, null,
                    assertion, auditRef, "putAssertion");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutAssertionFailureRetry() {

        String domainName = "policy-put-assertion-failure-retry";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Assertion assertion = new Assertion().setRole("reader").setResource("table")
                .setAction("update").setId(1001L);
        Mockito.when(mockJdbcConn.insertAssertion(domainName, policyName, null, assertion))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutAssertion(mockDomRsrcCtx, domainName, policyName, null,
                    assertion, auditRef, "putAssertion");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePolicyNotFoundFailure() {

        String domainName = "policy-delete-failure";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.getPolicy(domainName, policyName, null)).thenReturn(null);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeletePolicy(mockDomRsrcCtx, domainName, policyName,
                    auditRef, "deletePolicy");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePolicyFailure() {

        String domainName = "policy-delete-failure";
        String policyName = "policy1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Policy policy = new Policy().setName(policyName);
        Mockito.when(mockJdbcConn.getPolicy(domainName, policyName, "0")).thenReturn(null).thenReturn(policy);
        Mockito.when(mockJdbcConn.listPolicyVersions(domainName, policyName)).thenReturn(null).thenReturn(Arrays.asList("0"));
        Mockito.when(mockJdbcConn.deletePolicy(domainName, policyName)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeletePolicy(mockDomRsrcCtx, domainName, policyName,
                    auditRef, "deletePolicy");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (404): {code: 404, message: \"deletePolicy: unable to get versions for policy: policy1\"}");
        }

        try {
            zms.dbService.executeDeletePolicy(mockDomRsrcCtx, domainName, policyName,
                    auditRef, "deletePolicy");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (404): {code: 404, message: \"deletePolicy: unable to read policy: policy1, with version: 0\"}");
        }

        try {
            zms.dbService.executeDeletePolicy(mockDomRsrcCtx, domainName, policyName,
                    auditRef, "deletePolicy");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (404): {code: 404, message: \"deletePolicy: unable to delete policy: policy1\"}");
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePolicyFailureRetry() {

        String domainName = "policy-delete-failure-retry";
        String policyName = "policy1";
        String version = "0";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Policy policy = new Policy().setName(policyName).setVersion(version).setActive(true);
        Mockito.when(mockJdbcConn.getPolicy(domainName, policyName, version)).thenReturn(policy);
        Mockito.when(mockJdbcConn.deletePolicy(domainName, policyName))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));
        Mockito.when(mockJdbcConn.listPolicyVersions(domainName, policyName)).thenReturn(Arrays.asList(version));

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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        PublicKeyEntry keyEntry = new PublicKeyEntry().setId("0").setKey("key");
        Mockito.when(mockJdbcConn.getPublicKeyEntry(domainName, serviceName, "0", false)).thenReturn(keyEntry);
        Mockito.when(mockJdbcConn.updatePublicKeyEntry(domainName, serviceName, keyEntry))
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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deletePublicKeyEntry(domainName, serviceName, "0"))
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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        PublicKeyEntry keyEntry = new PublicKeyEntry().setId("0").setKey("key");
        Mockito.when(mockJdbcConn.getPublicKeyEntry(domainName, serviceName, "0", false)).thenReturn(keyEntry);
        Mockito.when(mockJdbcConn.updatePublicKeyEntry(domainName, serviceName, keyEntry)).thenReturn(false);

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
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        Role role2 = zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole", true);
        assertNotNull(role2);
        assertEquals(role2.getName(), domainName + ":role." + roleName);
        assertNull(role2.getTrust());
        Role role3 = zms.getRole(mockDomRsrcCtx, domainName, roleName, false, false, false);
        assertNotNull(role3);
        assertEquals(role3.getName(), domainName + ":role." + roleName);
        assertNull(role3.getTrust());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutRoleFailure() {

        String domainName = "executeputroledom1";
        String roleName = "role1";

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");

        Mockito.when(mockJdbcConn.insertRole(anyString(), any(Role.class)))
                .thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutDomainDependencyFailure() {

        String domainName = "putDomainDependencyFail1";
        String serviceName = "svc1";

        Mockito.when(mockJdbcConn.insertDomainDependency(eq(domainName), eq(serviceName)))
                .thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.putDomainDependency(mockDomRsrcCtx, domainName, serviceName, auditRef, "putDomainDependency");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteDomainDependencyFailure() {

        String domainName = "deleteDomainDependencyFail1";
        String serviceName = "svc1";

        Mockito.when(mockJdbcConn.deleteDomainDependency(eq(domainName), eq(serviceName)))
                .thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.deleteDomainDependency(mockDomRsrcCtx, domainName, serviceName, auditRef, "deleteDomainDependency");
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

        Mockito.when(mockJdbcConn.insertRole(anyString(), any(Role.class)))
                .thenThrow(new ResourceException(ResourceException.CONFLICT));
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testPutDomainDependencyRetryFailure() {

        String domainName = "putDomainDependencyRetryFail1";
        String serviceName = "service1";

        Mockito.when(mockJdbcConn.insertDomainDependency(eq(domainName), eq(serviceName)))
                .thenThrow(new ResourceException(ResourceException.CONFLICT));
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.putDomainDependency(mockDomRsrcCtx, domainName, serviceName, auditRef, "putDomainDependency");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }


    @Test
    public void testDeleteDomainDependencyRetryFailure() {

        String domainName = "deleteDomainDependencyRetryFail1";
        String serviceName = "service-retry1";

        Mockito.when(mockJdbcConn.deleteDomainDependency(eq(domainName), eq(serviceName)))
                .thenThrow(new ResourceException(ResourceException.CONFLICT));
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.deleteDomainDependency(mockDomRsrcCtx, domainName, serviceName, auditRef, "deleteDomainDependency");
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
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject("ExecutePutRoleInvalidDom1", "Role1", null,
                "user.joe", "user.jane");

        try {
            zms.dbService.executePutRole(mockDomRsrcCtx, "ExecutePutRoleInvalidDom2",
                    "Role1", role1, auditRef, "putRole", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ExecutePutRoleInvalidDom1", auditRef, null);
    }

    @Test
    public void testExecutePutServiceIdentity() {

        String domainName = "serviceadddom1";
        String serviceName = "service1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        service.setDescription("test");

        ServiceIdentity service2 = zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                service, auditRef, "putServiceIdentity", true);

        assertNotNull(service2);
        assertEquals(service2.getName(), domainName + "." + serviceName);
        assertEquals(service2.getDescription(), "test");

        ServiceIdentity serviceRes2 = zms.getServiceIdentity(mockDomRsrcCtx, domainName,
                serviceName);
        assertNotNull(serviceRes2);
        assertEquals(serviceRes2.getName(), domainName + "." + serviceName);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutServiceIdentityFailure() {

        String domainName = "serviceadddom1";
        String serviceName = "service1";

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        Mockito.when(mockJdbcConn.insertServiceIdentity(anyString(), any(ServiceIdentity.class)))
                .thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName, service,
                    auditRef, "putServiceIdentity", false);
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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.insertServiceIdentity(domainName, service))
            .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                    service, auditRef, "putServiceIdentity", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.defaultRetryCount = saveRetryCount;
        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutServiceIdentitySystemMetaFailureInvalidDomain() {

        String domainName = "domain-not-found-service-meta";
        String serviceName = "service1";

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(null);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta();
        meta.setProviderEndpoint("https://localhost");
        try {
            zms.dbService.executePutServiceIdentitySystemMeta(mockDomRsrcCtx, domainName, serviceName, meta,
                    "providerendpoint", auditRef, "putServiceIdentitySystemMeta");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
            assertTrue(ex.getMessage().contains("Unknown domain: " + domainName));
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutServiceIdentitySystemMetaFailureInvalidService() {

        String domainName = "service-not-found-service-meta";
        String serviceName = "service1";

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.getServiceIdentity(domainName, serviceName)).thenReturn(null);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta();
        meta.setProviderEndpoint("https://localhost");
        try {
            zms.dbService.executePutServiceIdentitySystemMeta(mockDomRsrcCtx, domainName, serviceName, meta,
                    "providerendpoint", auditRef, "putServiceIdentitySystemMeta");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
            assertTrue(ex.getMessage().contains("Unknown service: " + serviceName));
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutServiceIdentitySystemMetaFailureRetry() {

        String domainName = "serviceadddom1";
        String serviceName = "service1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        ServiceIdentity service = new ServiceIdentity().setProviderEndpoint("https://localhost");
        Mockito.when(mockJdbcConn.getServiceIdentity(domainName, serviceName)).thenReturn(service);
        Mockito.when(mockJdbcConn.updateServiceIdentity(domainName, service))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta();
        meta.setProviderEndpoint("https://localhost");
        try {
            zms.dbService.executePutServiceIdentitySystemMeta(mockDomRsrcCtx, domainName, serviceName, meta,
                    "providerendpoint", auditRef, "putServiceIdentitySystemMeta");
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
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        ServiceIdentity service = createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                service, auditRef, "putServiceIdentity", false);

        service.getHosts().add("host2");
        service.getHosts().add("host3");
        service.getHosts().remove("host1");

        zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, domainName, serviceName,
                service, auditRef, "putServiceIdentity", false);

        ServiceIdentity serviceRes2 = zms.getServiceIdentity(mockDomRsrcCtx, domainName,
                serviceName);
        assertNotNull(serviceRes2);
        assertEquals(serviceRes2.getName(), domainName + "." + serviceName);
        assertEquals(2, service.getHosts().size());
        assertTrue(service.getHosts().contains("host2"));
        assertTrue(service.getHosts().contains("host3"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutServiceIdentityInvalidDomain() {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        ServiceIdentity service = createServiceObject("ServiceAddDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        try {
            zms.dbService.executePutServiceIdentity(mockDomRsrcCtx, "ServiceAddDom1Invalid",
                    "Service1", service, auditRef, "putServiceIdentity", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "ServiceAddDom1", auditRef, null);
    }

    @Test
    public void testExecutePutTenantRoles() {

        String tenantDomain = "tenantadminpolicy";
        String providerDomain = "coretech";
        String providerService = "storage";

        // create domain for tenant

        TopLevelDomain dom1 = createTopLevelDomainObject(tenantDomain,
                "Test Tenant Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        // create domain for provider

        TopLevelDomain domProv = createTopLevelDomainObject(providerDomain,
                "Test Provider Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, domProv);

        // create service identity for providerDomain.providerService

        ServiceIdentity service = createServiceObject(
                providerDomain, providerService, "http://localhost:8090/tableprovider",
                "/usr/bin/java", "root", "users", "localhost");

        zms.putServiceIdentity(mockDomRsrcCtx, providerDomain, providerService, auditRef, false, null, service);

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
                tenantDomain, null, roleActions, false, auditRef, "putTenantRoles");

        zms.deleteTenancy(mockDomRsrcCtx, tenantDomain, "coretech.storage", auditRef);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef, null);
    }

    private void verifyPolicies(String domainName) {

        List<String> names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        // this should be our own policy that we created previously
        Policy policy = zms.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(domainName + ":policy.vip_admin", policy.getName());

        // The updated policy will have two assertions, one from the original, and the other from template application.
        // The original assertion is {    role: "solutiontemplate-withpolicy:role.role1",    action: "*",    effect: "ALLOW",    resource: "*"}
        // Newly added one is {    resource: "solutiontemplate-withpolicy:vip*",    role: "solutiontemplate-withpolicy:role.vip_admin",    action: "*"}
        assertEquals(2, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0); // this is the original assertion
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.admin", assertion.getRole());
        assertEquals("solutiontemplate-withpolicy:*", assertion.getResource());

        Assertion assertionAdded = policy.getAssertions().get(1); // this is the added assertion
        assertEquals("*", assertionAdded.getAction());
        assertEquals(domainName + ":role.vip_admin", assertionAdded.getRole());
        assertEquals("solutiontemplate-withpolicy:vip*", assertionAdded.getResource());
    }

    @Test
    public void testAuditLogAddSolutionTemplate() {

        String domainName = "auditlog-solutiontemplate-rolemeta";
        String caller = "testAuditLogAddSolutionTemplate";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        // apply the template

        List<String> templates = new ArrayList<>();
        templates.add("templateWithRoleMeta");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        ObjectStoreConnection conn = zms.dbService.store.getConnection(true, false);

        StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        auditDetails.append("{\"add-templates\": ");
        zms.dbService.addSolutionTemplate(mockDomRsrcCtx, conn, domainName, "templateWithRoleMeta",
                adminUser, domainTemplate.getParams(), auditRef, auditDetails);
        auditDetails.append("}");

        assertTrue(isValidJSON(auditDetails.toString()));
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testApplySolutionTemplateDomainExistingPolicies() {

        String caller = "testApplySolutionTemplateDomainExistingPolicies";
        String domainName = "solutiontemplate-withpolicy";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        SubDomain domSysNetwork = createSubDomainObject("network", "sys", "Test Domain",
                "testOrg", adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "sys", auditRef, null, domSysNetwork);

        // we are going to create one of the policies that's also in
        // the template - this should not change

        Policy policy1 = createPolicyObject(domainName, "vip_admin");
        zms.putPolicy(mockDomRsrcCtx, domainName, "vip_admin", auditRef, false, null, policy1);

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
        assertTrue(role.getRoleMembers().isEmpty());

        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());

        // verify that our policy collections includes the policies defined in the template

        verifyPolicies(domainName);

        // Try applying the template again. This time, there should be no changes.

        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        verifyPolicies(domainName);

        // the rest should be identical what's in the template

        Policy policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
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
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin", null));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove vipng again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng",
                auditRef, caller);

        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin", null));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteSubDomain(mockDomRsrcCtx, "sys", "network", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testApplySolutionTemplateMultipleTemplates() {

        String caller = "testApplySolutionTemplateMultipleTemplates";
        String domainName = "solutiontemplate-multi";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        SubDomain domSysNetwork = createSubDomainObject("network", "sys", "Test Domain", "testOrg",
                adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "sys", auditRef, null, domSysNetwork);

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
        assertTrue(role.getRoleMembers().isEmpty());

        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());

        // verify that our policy collections includes the policies defined in the template

        names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Policy policy = zms.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
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

        zms.deleteSubDomain(mockDomRsrcCtx, "sys", "network", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }


    @Test
    public void testApplySolutionTemplateWithService() {

        String domainName = "solutiontemplate-service";
        String caller = "testApplySolutionTemplateDomainWithService";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

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
        assertTrue(role.getRoleMembers().isEmpty());

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testApplySolutionTemplateWithMultipleServices() {

        String domainName = "solutiontemplate-multiservice";
        String caller = "testApplySolutionTemplateWithMultipleServices";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

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
        assertTrue(role.getRoleMembers().isEmpty());

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }


    @Test
    public void testApplySolutionTemplateWithServiceWithKey() {

        String domainName = "solutiontemplate-servicekey";
        String caller = "testApplySolutionTemplateWithServiceWithKey";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

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
        assertTrue(role.getRoleMembers().isEmpty());

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testApplySolutionTemplateEmptyDomain() {

        String domainName = "solutiontemplate-ok";
        String caller = "testApplySolutionTemplateDomainExistingPolicies";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        SubDomain domSysNetwork = createSubDomainObject("network", "sys", "Test Domain", "testOrg",
                adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "sys", auditRef, null, domSysNetwork);

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
        assertTrue(role.getRoleMembers().isEmpty());

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

        Policy policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
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
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin", null));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove vipng again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "vipng",
                auditRef, caller);

        assertNull(zms.dbService.getRole(domainName, "vip_admin", false, false, false));
        assertNull(zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false));
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin", null));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteSubDomain(mockDomRsrcCtx, "sys", "network", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testApplySolutionTemplateMultipleTimes() {

        String caller = "testApplySolutionTemplateMultipleTimes";
        String domainName = "solutiontemplate-multiple";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        SubDomain domSysNetwork = createSubDomainObject("network", "sys", "Test Domain", "testOrg",
                adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "sys", auditRef, null, domSysNetwork);

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
        assertTrue(role.getRoleMembers().isEmpty());

        role = zms.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());

        // verify that our policy collections includes the policies defined in the template

        names = zms.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Policy policy = zms.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
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
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin", null));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteSubDomain(mockDomRsrcCtx, "sys", "network", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testApplySolutionTemplateExistingRoles() {

        String caller = "testApplySolutionTemplateExistingRoles";
        String domainName = "solutiontemplate-withrole";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        SubDomain domSysNetwork = createSubDomainObject("network", "sys", "Test Domain", "testOrg",
                adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "sys", auditRef, null, domSysNetwork);

        // we are going to create one of the roles that's also in
        // the template - this should not change

        Role role1 = createRoleObject(domainName, "vip_admin", null, "user.joe",
                "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "vip_admin", auditRef, false, null, role1);

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

        Policy policy = zms.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        policy = zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
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
        assertNull(zms.dbService.getPolicy(domainName, "vip_admin", null));
        assertNull(zms.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null));
        assertNotNull(zms.dbService.getRole(domainName, "admin", false, false, false));

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteSubDomain(mockDomRsrcCtx, "sys", "network", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testApplySolutionTemplateWithLatestVersion() {

        String caller = "testApplySolutionTemplateWithLatestVersion";
        String domainName = "solutiontemplate-latestversion";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "domain-latestversion-test", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        List<String> templates = new ArrayList<>();
        templates.add("templateWithService");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        DomainTemplateDetailsList domainTemplateDetailsList = zms.getDomainTemplateDetailsList(mockDomRsrcCtx, domainName);
        List<TemplateMetaData> metaData = domainTemplateDetailsList.getMetaData();
        for (TemplateMetaData meta : metaData) {
            assertEquals(10, (meta.getLatestVersion().intValue()));
            assertEquals("templateWithService", meta.getTemplateName());
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
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
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        // create domain for provider

        TopLevelDomain domProv = createTopLevelDomainObject(providerDomain,
                "Test Provider Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, domProv);

        // create service identity for providerDomain.providerService

        ServiceIdentity service = createServiceObject(
                providerDomain, providerService, "http://localhost:8090/tableprovider",
                "/usr/bin/java", "root", "users", "localhost");

        zms.putServiceIdentity(mockDomRsrcCtx, providerDomain, providerService, auditRef, false, null, service);

        // let's create the tenant admin policy

        zms.dbService.setupTenantAdminPolicy(null, tenantDomain, providerDomain,
                providerService, auditRef, caller);

        // the admin policy must be called

        String policyName = "tenancy.coretech.storage.admin";
        Policy policy = zms.dbService.getPolicy(tenantDomain, policyName, null);
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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, tenantDomain, auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, providerDomain, auditRef, null);
    }

    @Test
    public void testInvalidDBServiceConfig() {

        System.setProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_COUNT, "-100");
        System.setProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_SLEEP_TIME, "-1000");
        System.setProperty(ZMSConsts.ZMS_PROP_STORE_OP_TIMEOUT, "-100");

        ZMSConfig zmsConfig = new ZMSConfig();
        zmsConfig.setUserDomain("user");
        DBService dbService = new DBService(null, null, zmsConfig, null, null);
        assertEquals(120, dbService.defaultRetryCount);
        assertEquals(250, dbService.retrySleepTime);
        assertEquals(60, dbService.defaultOpTimeout);

        System.clearProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_COUNT);
        System.clearProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_SLEEP_TIME);
        System.clearProperty(ZMSConsts.ZMS_PROP_STORE_OP_TIMEOUT);
    }

    @Test
    public void testShouldRetryOperation() {

        ZMSConfig zmsConfig = new ZMSConfig();
        zmsConfig.setUserDomain("user");
        DBService dbService = new DBService(mockObjStore, null, zmsConfig, null, null);

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
    public void testLookupDomainByAwsAccount() {

        String domainName = "lookupdomainawsaccount";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setAccount("aws");
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        DomainList list = zms.dbService.lookupDomainByAWSAccount("aws");
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);

        list = zms.dbService.lookupDomainByAWSAccount("aws2");
        assertNull(list.getNames());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testLookupDomainByAzureSubscription() {

        String domainName = "lookupdomainazuresubscription";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setAzureSubscription("azure");
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        DomainList list = zms.dbService.lookupDomainByAzureSubscription("azure");
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);

        list = zms.dbService.lookupDomainByAzureSubscription("azure2");
        assertNull(list.getNames());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testLookupDomainByGcpProject() {

        String domainName = "lookupdomainagcpproject";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setGcpProject("gcp");
        dom1.setGcpProjectNumber("1234");
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        DomainList list = zms.dbService.lookupDomainByGcpProject("gcp");
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);

        list = zms.dbService.lookupDomainByGcpProject("gcp2");
        assertNull(list.getNames());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testLookupDomainByProductIdNumber() {

        String domainName = "lookupdomainbyproductid";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setYpmId(101);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        DomainList list = zms.dbService.lookupDomainByProductId(101);
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);

        list = zms.dbService.lookupDomainByProductId(102);
        assertNull(list.getNames());

        // by default, we're assigning id 0 to all domains without valid value

        list = zms.dbService.lookupDomainByProductId(0);
        assertNotNull(list.getNames());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testLookupDomainByProductId() {

        String domainName = "lookupdomainbyproductid";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setProductId("abcd-101");
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        DomainList list = zms.dbService.lookupDomainByProductId("abcd-101");
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);

        list = zms.dbService.lookupDomainByProductId("abcd-102");
        assertNull(list.getNames());

        // by default, we're assigning empty string to all domains without valid value

        list = zms.dbService.lookupDomainByProductId("");
        assertNotNull(list.getNames());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testLookupDomainByRole() {

        String domainName = "lookupdomainrole";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        dom1.setYpmId(199);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        DomainList list = zms.dbService.lookupDomainByRole(adminUser, "admin");
        assertNotNull(list.getNames());
        assertTrue(list.getNames().contains(domainName));

        List<String> doms = zms.dbService.listDomains(null, 0, false);

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
                role1, auditRef, "putRole", false);

        list = zms.dbService.lookupDomainByRole("user.joe", "list-role");
        assertNotNull(list.getNames());
        assertEquals(list.getNames().size(), 1);
        assertEquals(list.getNames().get(0), domainName);

        list = zms.dbService.lookupDomainByRole(adminUser, "list-role");
        assertEquals(list.getNames().size(), 0);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
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
        assertTrue(zms.dbService.addSolutionTemplate(mockDomRsrcCtx, null, null, "template1",
                null, null, null, auditDetails));
        assertEquals("{\"name\": \"template1\"}", auditDetails.toString());

        auditDetails.setLength(0);
        zms.dbService.deleteSolutionTemplate(mockDomRsrcCtx, null, null, "template1", null, auditDetails);
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
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, "sys.auth",
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);

        Role role = zms.dbService.getRole(domainName, roleName, false, false, false);
        assertNotNull(role);
        assertEquals(role.getTrust(), "sys.auth");
        assertNull(role.getRoleMembers());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testGetDelegatedRoleExpand() {

        String domainName1 = "role-expand1";
        String domainName2 = "role-expand2";

        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom2);

        Role role1 = createRoleObject(domainName1, roleName, domainName2,
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName1, roleName, auditRef, false, null, role1);

        Role role2a = createRoleObject(domainName2, "role2a", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2a", auditRef, false, null, role2a);

        Role role2b = createRoleObject(domainName2, "role2b", null,
                "user.joe", "user.doe");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2b", auditRef, false, null, role2b);

        Policy policy = createPolicyObject(domainName2, "policy",
                domainName2 + ":role.role2a", false, "assume_role", domainName1 + ":role." + roleName,
                AssertionEffect.ALLOW, null, true);

        Assertion assertion = new Assertion();
        assertion.setAction("assume_role");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role." + roleName);
        assertion.setRole(domainName2 + ":role.role2b");
        policy.getAssertions().add(assertion);
        zms.putPolicy(mockDomRsrcCtx, domainName2, "policy", auditRef, false, null, policy);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName1, auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName2, auditRef, null);
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
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom2);

        Role role1 = createRoleObject(domainName1, roleName, domainName2,
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName1, roleName, auditRef, false, null, role1);

        Role role2a = createRoleObject(domainName2, "role2a", null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2a", auditRef, false, null, role2a);

        Role role2b = createRoleObject(domainName2, "role2b", null,
                "user.joe", "user.doe");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2b", auditRef, false, null, role2b);

        Role role2c = createRoleObject(domainName2, "role2c", "sys.auth",
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName2, "role2c", auditRef, false, null, role2c);

        Role role2d = createRoleObject(domainName2, "role2d", null,
                "user.user1", "user.user2");
        zms.putRole(mockDomRsrcCtx, domainName2, "role2d", auditRef, false, null, role2d);

        Role role2e = createRoleObject(domainName2, "role2e", null,
                null, null);
        zms.putRole(mockDomRsrcCtx, domainName2, "role2e", auditRef, false, null, role2e);

        Policy policy = createPolicyObject(domainName2, "policy",
                domainName2 + ":role.role2a", false, "assume_role", domainName1 + ":role." + roleName,
                AssertionEffect.ALLOW, null, true);

        Assertion assertion = new Assertion();
        assertion.setAction("assume_role");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role." + roleName);
        assertion.setRole(domainName2 + ":role.role2b");
        policy.getAssertions().add(assertion);
        zms.putPolicy(mockDomRsrcCtx, domainName2, "policy", auditRef, false, null, policy);

        policy = new Policy().setName(domainName2 + ":policy.policy2");
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName2, "policy2", policy, auditRef, "putPolicy", false);

        ObjectStoreConnection conn = zms.dbService.store.getConnection(true, false);
        List<RoleMember> members = zms.dbService.getDelegatedRoleMembers(conn, domainName1, domainName2, roleName);
        assertEquals(3, members.size());

        List<String> checkList = new ArrayList<>();
        checkList.add("user.joe");
        checkList.add("user.jane");
        checkList.add("user.doe");
        checkRoleMember(checkList, members);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName1, auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName2, auditRef, null);
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
        service3.setName(ResourceUtils.serviceResourceName(domainName1, "service3"));

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

        // unknown domain case

        key = zms.dbService.getPublicKeyFromCache("unknown-domain", "service1", "1");
        assertNull(key);

        // domain without the proper object

        DataCache dataCache3 = new DataCache(null, 101);
        zms.dbService.cacheStore.put("domain-without-object", dataCache3);

        key = zms.dbService.getPublicKeyFromCache("domain-without-object", "service1", "1");
        assertNull(key);

        // domain without services

        AthenzDomain athenzDomain4 = new AthenzDomain("domain-without-services");
        athenzDomain4.setServices(null);
        DataCache dataCache4 = new DataCache(athenzDomain4, 101);
        zms.dbService.cacheStore.put("domain-without-services", dataCache4);

        key = zms.dbService.getPublicKeyFromCache("domain-without-services", "service1", "1");
        assertNull(key);
    }

    @Test
    public void testListPrincipalsUsersOnly() {

        String domainName = "listusers1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("listusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom2);

        TopLevelDomain dom3 = createTopLevelDomainObject("listuserweather",
                "Test Domain3", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom3);

        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, false, null, role1);

        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "listusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, false, null, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "listuserweather.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, false, null, role3);

        Role role4 = createRoleObject("listusersports", "role4", null,
                "user.ana", "user.janie");
        zms.putRole(mockDomRsrcCtx, "listusersports", "role4", auditRef, false, null, role4);

        List<String> users = zms.dbService.listPrincipals("user", true);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.joe"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listusersports", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listuserweather", auditRef, null);
    }

    @Test
    public void testListPrincipalsAll() {

        String domainName = "listusers1";

        ZMSTestUtils.cleanupNotAdminUsers(zms, adminUser, mockDomRsrcCtx);

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("listusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom2);

        TopLevelDomain dom3 = createTopLevelDomainObject("listuserweather",
                "Test Domain3", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom3);

        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, false, null, role1);

        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "listusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, false, null, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "listuserweather.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, false, null, role3);

        Role role4 = createRoleObject("listusersports", "role4", null,
                "user.ana", "user.janie");
        zms.putRole(mockDomRsrcCtx, "listusersports", "role4", auditRef, false, null, role4);

        Role role5 = createRoleObject("listusersports", "role5", null,
                null, null);
        zms.putRole(mockDomRsrcCtx, "listusersports", "role5", auditRef, false, null, role5);

        List<String> users = zms.dbService.listPrincipals(null, false);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.joe"));
        assertTrue(users.contains("listusersports.jane"));
        assertTrue(users.contains("listuserweather.jane"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listusersports", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listuserweather", auditRef, null);
    }

    @Test
    public void testListPrincipalsSubdomains() {

        String domainName = "listusers1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("listusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom2);

        SubDomain subDom2 = createSubDomainObject("api", "listusersports",
                "Test SubDomain2", "testOrg", adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "listusersports", auditRef, null, subDom2);

        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, false, null, role1);

        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "listusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, false, null, role2);

        Role role3 = createRoleObject("listusersports", "role3", null,
                "user.ana", "listusersports.api.service");
        zms.putRole(mockDomRsrcCtx, "listusersports", "role3", auditRef, false, null, role3);

        List<String> users = zms.dbService.listPrincipals(null, false);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.joe"));
        assertTrue(users.contains("listusersports.jane"));
        assertTrue(users.contains("listusersports.api.service"));

        users = zms.dbService.listPrincipals(null, true);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.joe"));
        assertTrue(users.contains("listusersports.jane"));
        assertFalse(users.contains("listusersports.api.service"));

        users = zms.dbService.listPrincipals("listusersports", false);
        assertEquals(users.size(), 2);
        assertTrue(users.contains("listusersports.jane"));
        assertTrue(users.contains("listusersports.api.service"));

        users = zms.dbService.listPrincipals("listusersports", true);
        assertEquals(users.size(), 1);
        assertTrue(users.contains("listusersports.jane"));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
        zms.deleteSubDomain(mockDomRsrcCtx, "listusersports", "api", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "listusersports", auditRef, null);
    }

    @Test
    public void testExecuteDeleteUser() {

        String domainName = "deleteuser1";

        ZMSTestUtils.cleanupNotAdminUsers(zms, adminUser, mockDomRsrcCtx);

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("deleteusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom2);

        TopLevelDomain dom3 = createTopLevelDomainObject("deleteuserweather",
                "Test Domain3", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom3);

        SubDomain subDom1 = createSubDomainObject("jack", "user",
                "Test SubDomain2", "testOrg", adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "user", auditRef, null, subDom1);

        SubDomain subDom2 = createSubDomainObject("jane", "user",
                "Test SubDomain2", "testOrg", adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "user", auditRef, null, subDom2);

        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, false, null, role1);

        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "deleteusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, false, null, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "deleteuserweather.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, false, null, role3);

        Role role4 = createRoleObject("deleteusersports", "role4", null,
                "user.ana", "user.janie");
        zms.putRole(mockDomRsrcCtx, "deleteusersports", "role4", auditRef, false, null, role4);

        Role role5 = createRoleObject("deleteusersports", "role5", null,
                "user.jack.service", "user.jane.storage");
        zms.putRole(mockDomRsrcCtx, "deleteusersports", "role5", auditRef, false, null, role5);

        List<String> users = zms.dbService.listPrincipals("user", true);
        assertEquals(users.size(), 6);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.joe"));
        assertTrue(users.contains("user.user1"));

        zms.dbService.executeDeleteUser(mockDomRsrcCtx, "user.jack", "user.jack", auditRef, "testExecuteDeleteUser");

        users = zms.dbService.listPrincipals("user", true);
        assertEquals(users.size(), 5);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.janie"));
        assertTrue(users.contains("user.ana"));
        assertTrue(users.contains("user.joe"));
        assertFalse(users.contains("user.jack"));
        assertTrue(users.contains("user.user1"));

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
        zms.deleteSubDomain(mockDomRsrcCtx, "user", "jane", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "deleteusersports", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "deleteuserweather", auditRef, null);
    }

    @Test
    public void testExecuteDeleteUserSubdomains() {

        String domainName = "deleteuser1";

        ZMSTestUtils.cleanupNotAdminUsers(zms, adminUser, mockDomRsrcCtx);

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        TopLevelDomain dom2 = createTopLevelDomainObject("deleteusersports",
                "Test Domain2", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom2);

        SubDomain subDom1 = createSubDomainObject("jack", "user",
                "Test SubDomain2", "testOrg", adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "user", auditRef, null, subDom1);

        SubDomain subDom2 = createSubDomainObject("sub1", "user.jack",
                "Test SubDomain21", "testOrg", adminUser, mockDomRsrcCtx.principal().getFullName());
        zms.postSubDomain(mockDomRsrcCtx, "user.jack", auditRef, null, subDom2);

        Role role1 = createRoleObject(domainName, "role1", null,
                "user.joe", "user.jack.sub1.service");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, false, null, role1);

        Role role2 = createRoleObject(domainName, "role2", null,
                "user.joe", "deleteusersports.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, false, null, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "user.jack.sub1.api");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, false, null, role3);

        List<String> users = zms.dbService.listPrincipals("user", false);
        int userLen = users.size();
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.jack.sub1.service"));
        assertTrue(users.contains("user.jack.sub1.api"));
        assertTrue(users.contains("user.joe"));

        zms.dbService.executeDeleteUser(mockDomRsrcCtx, "user.jack", "user.jack", auditRef, "testExecuteDeleteUser");

        users = zms.dbService.listPrincipals("user", false);
        assertEquals(users.size(), userLen - 3);
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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "deleteusersports", auditRef, null);
    }

    @Test
    public void testExecuteDeleteDomainRoleMember() {

        String domainName = "deletedomainrolemember1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, "role1", null,
                "user.jack", "user.janie");
        zms.putRole(mockDomRsrcCtx, domainName, "role1", auditRef, false, null, role1);

        Role role2 = createRoleObject(domainName, "role2", null,
                "user.janie", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role2", auditRef, false, null, role2);

        Role role3 = createRoleObject(domainName, "role3", null,
                "user.jack", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role3", auditRef, false, null, role3);

        Role role4 = createRoleObject(domainName, "role4", null,
                "user.jack", null);
        zms.putRole(mockDomRsrcCtx, domainName, "role4", auditRef, false, null, role4);

        Role role5 = createRoleObject(domainName, "role5", null,
                "user.jack-service", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, "role5", auditRef, false, null, role5);

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

        // this should exception with not-found user

        try {
            zms.dbService.executeDeleteDomainRoleMember(mockDomRsrcCtx, domainName, "user.unknown", auditRef,
                    "testExecuteDeleteDomainRoleMember");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecuteDeleteDomainRoleMemberRetryException() {

        Mockito.when(mockJdbcConn.getPrincipalRoles("user.joe", "dom1"))
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
        Mockito.when(conn.getPrincipalRoles("user.joe", "dom1"))
                .thenThrow(new ResourceException(404))
                .thenThrow(new ResourceException(501));

        // handle exceptions accordingly

        try {
            zms.dbService.removePrincipalFromDomainRoles(null, conn, "dom1", "user.joe", adminUser, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }

        try {
            zms.dbService.removePrincipalFromDomainRoles(null, conn, "dom1", "user.joe", adminUser, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(501, ex.getCode());
        }
    }

    @Test
    public void testRemovePrincipalFromDomainRolesDeleteUserException() {

        DomainRoleMember roles = new DomainRoleMember();
        roles.setMemberRoles(new ArrayList<>());
        MemberRole role1 = new MemberRole();
        role1.setDomainName("dom1");
        role1.setRoleName("role1");
        roles.getMemberRoles().add(role1);
        MemberRole role2 = new MemberRole();
        role2.setDomainName("dom1");
        role2.setRoleName("role2");
        roles.getMemberRoles().add(role2);

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.getPrincipalRoles("user.joe", "dom1")).thenReturn(roles);
        Mockito.when(conn.deleteRoleMember("dom1", "role1", "user.joe", adminUser, "unittest"))
                .thenReturn(true);
        Mockito.when(conn.deleteRoleMember("dom1", "role2", "user.joe", adminUser, "unittest"))
                .thenThrow(new ResourceException(501));

        // we should handle the exception without any errors

        zms.dbService.removePrincipalFromDomainRoles(null, conn, "dom1", "user.joe", adminUser, "unittest");
    }

    @Test
    public void testRemovePrincipalFromAllRolesExceptions() {

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.getPrincipalRoles("user.joe", null))
                .thenThrow(new ResourceException(404))
                .thenThrow(new ResourceException(501));

        // no exception if store returns 404

        zms.dbService.removePrincipalFromAllRoles(mockDomRsrcCtx, conn, "user.joe", adminUser, "unittest");

        // with next we should throw the exception so we should catch it

        try {
            zms.dbService.removePrincipalFromAllRoles(mockDomRsrcCtx, conn, "user.joe", adminUser, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(501, ex.getCode());
        }
    }

    @Test
    public void testExecuteDeleteUserRetryException() {

        Mockito.when(mockJdbcConn.listDomains("home.joe.", 0))
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

        DomainRoleMember roles = new DomainRoleMember();
        roles.setMemberRoles(new ArrayList<>());
        MemberRole role1 = new MemberRole();
        role1.setDomainName("dom1");
        role1.setRoleName("role1");
        roles.getMemberRoles().add(role1);
        MemberRole role2 = new MemberRole();
        role2.setDomainName("dom1");
        role2.setRoleName("role2");
        roles.getMemberRoles().add(role2);

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.getPrincipalRoles("user.joe", null)).thenReturn(roles);
        Mockito.when(conn.deleteRoleMember("dom1", "role1", "user.joe", adminUser, "unittest"))
                .thenReturn(true);
        Mockito.when(conn.deleteRoleMember("dom1", "role2", "user.joe", adminUser, "unittest"))
                .thenThrow(new ResourceException(501));

        // we should handle the exception without any errors

        zms.dbService.removePrincipalFromAllRoles(mockDomRsrcCtx, conn, "user.joe", adminUser, "unittest");
    }

    @Test
    public void testRemovePrincipalFromAllGroupExceptions() {

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.getPrincipalGroups("user.joe", null))
                .thenThrow(new ResourceException(404))
                .thenThrow(new ResourceException(501));

        // no exception if store returns 404

        zms.dbService.removePrincipalFromAllGroups(mockDomRsrcCtx, conn, "user.joe", adminUser, "unittest");

        // with next we should throw the exception so we should catch it

        try {
            zms.dbService.removePrincipalFromAllGroups(mockDomRsrcCtx, conn, "user.joe", adminUser, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(501, ex.getCode());
        }
    }

    @Test
    public void testRemovePrincipalFromAllGroupsDeleteUserException() {

        DomainGroupMember roles = new DomainGroupMember();
        roles.setMemberGroups(new ArrayList<>());
        GroupMember group1 = new GroupMember();
        group1.setDomainName("dom1");
        group1.setGroupName("group1");
        roles.getMemberGroups().add(group1);
        GroupMember group2 = new GroupMember();
        group2.setDomainName("dom1");
        group2.setGroupName("group2");
        roles.getMemberGroups().add(group2);

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.getPrincipalGroups("user.joe", null)).thenReturn(roles);
        Mockito.when(conn.deleteGroupMember("dom1", "group1", "user.joe", adminUser, "unittest"))
                .thenReturn(true);
        Mockito.when(conn.deleteGroupMember("dom1", "group2", "user.joe", adminUser, "unittest"))
                .thenThrow(new ResourceException(501));

        // we should handle the exception without any errors

        zms.dbService.removePrincipalFromAllGroups(mockDomRsrcCtx, conn, "user.joe", adminUser, "unittest");
    }

    @Test
    public void testExecutePutQuotaFailureRetry() {

        String domainName = "putquota";

        Quota quota = new Quota();
        Mockito.when(mockJdbcConn.insertQuota(domainName, quota))
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

        Mockito.when(mockJdbcConn.deleteQuota(domainName))
                .thenReturn(false)
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executeDeleteQuota(mockDomRsrcCtx, domainName, auditRef, "deleteQuota");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

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
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Quota quota = new Quota().setName(domainName)
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18).setGroup(19).setGroupMember(20);

        zms.dbService.executePutQuota(mockDomRsrcCtx, domainName, quota,
                auditRef, "testExecutePutQuotaInsert");

        // now retrieve the quota using zms interface

        Quota quotaCheck = zms.getQuota(mockDomRsrcCtx, domainName);
        assertNotNull(quotaCheck);
        assertEquals(quotaCheck.getAssertion(), 10);
        assertEquals(quotaCheck.getRole(), 14);
        assertEquals(quotaCheck.getPolicy(), 12);
        assertEquals(quotaCheck.getGroupMember(), 20);
        assertEquals(quotaCheck.getGroup(), 19);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutQuotaUpdate() {

        String domainName = "executeputquotaupdate";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Quota quota = new Quota().setName(domainName)
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18).setGroupMember(19).setGroup(20);

        zms.dbService.executePutQuota(mockDomRsrcCtx, domainName, quota,
                auditRef, "testExecutePutQuotaUpdate");

        // now update the quota and apply the change again

        quota.setAssertion(100);
        quota.setRole(104);
        quota.setGroup(120);

        zms.dbService.executePutQuota(mockDomRsrcCtx, domainName, quota,
                auditRef, "testExecutePutQuotaUpdate");

        // now retrieve the quota using zms interface

        Quota quotaCheck = zms.getQuota(mockDomRsrcCtx, domainName);
        assertNotNull(quotaCheck);
        assertEquals(quotaCheck.getAssertion(), 100);
        assertEquals(quotaCheck.getRole(), 104);
        assertEquals(quotaCheck.getPolicy(), 12);
        assertEquals(quotaCheck.getGroup(), 120);
        assertEquals(quotaCheck.getGroupMember(), 19);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecuteDeleteQuota() {

        String domainName = "executedeletequota";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Quota quota = new Quota().setName(domainName)
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18).setGroupMember(19).setGroup(20);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
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
                .setCertDnsDomain("athenz.cloud")
                .setAzureSubscription("azure")
                .setBusinessService("123:business service")
                .setGcpProject("gcp")
                .setGcpProjectNumber("1234")
                .setProductId("abcd-1234")
                .setFeatureFlags(3);
        zms.dbService.updateSystemMetaFields(domain, "account", true, meta);
        assertEquals(domain.getAccount(), "acct");
        zms.dbService.updateSystemMetaFields(domain, "productid", true, meta);
        assertEquals(domain.getYpmId().intValue(), 1234);
        assertEquals(domain.getProductId(), "abcd-1234");
        zms.dbService.updateSystemMetaFields(domain, "certdnsdomain", true, meta);
        assertEquals(domain.getCertDnsDomain(), "athenz.cloud");
        zms.dbService.updateSystemMetaFields(domain, "azuresubscription", true, meta);
        assertEquals(domain.getAzureSubscription(), "azure");
        zms.dbService.updateSystemMetaFields(domain, "gcpproject", true, meta);
        assertEquals(domain.getGcpProject(), "gcp");
        zms.dbService.updateSystemMetaFields(domain, "businessservice", true, meta);
        assertEquals(domain.getBusinessService(), "123:business service");
        zms.dbService.updateSystemMetaFields(domain, "featureflags", true, meta);
        assertEquals(domain.getFeatureFlags().intValue(), 3);
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
                .setCertDnsDomain("athenz.cloud")
                .setAzureSubscription("azure")
                .setBusinessService("123:business service")
                .setGcpProject("gcp")
                .setGcpProjectNumber("1235")
                .setFeatureFlags(3);
        zms.dbService.updateSystemMetaFields(domain1, "account", false, meta1);
        assertEquals(domain1.getAccount(), "acct");
        zms.dbService.updateSystemMetaFields(domain1, "productid", false, meta1);
        assertEquals(domain1.getYpmId().intValue(), 1234);
        zms.dbService.updateSystemMetaFields(domain1, "certdnsdomain", false, meta1);
        assertEquals(domain1.getCertDnsDomain(), "athenz.cloud");
        zms.dbService.updateSystemMetaFields(domain1, "azuresubscription", false, meta1);
        assertEquals(domain1.getAzureSubscription(), "azure");
        zms.dbService.updateSystemMetaFields(domain1, "gcpproject", false, meta1);
        assertEquals(domain1.getGcpProject(), "gcp");
        zms.dbService.updateSystemMetaFields(domain1, "businessservice", false, meta1);
        assertEquals(domain1.getBusinessService(), "123:business service");
        zms.dbService.updateSystemMetaFields(domain, "featureflags", false, meta);
        assertEquals(domain.getFeatureFlags().intValue(), 3);

        // setting from set values should be all rejected

        Domain domain2 = new Domain()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud")
                .setAzureSubscription("azure")
                .setBusinessService("123:business service")
                .setGcpProject("gcp")
                .setGcpProjectNumber("1236")
                .setFeatureFlags(3);
        DomainMeta meta2 = new DomainMeta()
                .setAccount("acct-new")
                .setYpmId(1235)
                .setCertDnsDomain("athenz.cloud.new")
                .setAzureSubscription("azure.new")
                .setBusinessService("1234:business service2")
                .setGcpProject("gcp.new")
                .setGcpProjectNumber("1237")
                .setFeatureFlags(4);

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

        try {
            zms.dbService.updateSystemMetaFields(domain2, "azuresubscription", false, meta2);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("reset system meta attribute"));
        }

        try {
            zms.dbService.updateSystemMetaFields(domain2, "gcpproject", false, meta2);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("reset system meta attribute"));
        }

        try {
            zms.dbService.updateSystemMetaFields(domain2, "businessservice", false, meta2);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("reset system meta attribute"));
        }

        try {
            zms.dbService.updateSystemMetaFields(domain2, "featureflags", false, meta2);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("reset system meta attribute"));
        }

        // setting from set value to the same value should be allowed

        Domain domain3 = new Domain()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud")
                .setAzureSubscription("azure")
                .setBusinessService("123:business service")
                .setGcpProject("gcp")
                .setGcpProjectNumber("1237")
                .setFeatureFlags(3);
        DomainMeta meta3 = new DomainMeta()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud")
                .setAzureSubscription("azure")
                .setBusinessService("123:business service")
                .setGcpProject("gcp")
                .setGcpProjectNumber("1237")
                .setFeatureFlags(3);
        zms.dbService.updateSystemMetaFields(domain3, "account", false, meta3);
        assertEquals(domain3.getAccount(), "acct");
        zms.dbService.updateSystemMetaFields(domain3, "productid", false, meta3);
        assertEquals(domain3.getYpmId().intValue(), 1234);
        zms.dbService.updateSystemMetaFields(domain3, "certdnsdomain", false, meta3);
        assertEquals(domain3.getCertDnsDomain(), "athenz.cloud");
        zms.dbService.updateSystemMetaFields(domain3, "azuresubscription", false, meta3);
        assertEquals(domain3.getAzureSubscription(), "azure");
        zms.dbService.updateSystemMetaFields(domain3, "gcpproject", false, meta3);
        assertEquals(domain3.getGcpProject(), "gcp");
        zms.dbService.updateSystemMetaFields(domain3, "businessservice", false, meta3);
        assertEquals(domain3.getBusinessService(), "123:business service");
        zms.dbService.updateSystemMetaFields(domain3, "featureflags", false, meta3);
        assertEquals(domain3.getFeatureFlags().intValue(), 3);
    }

    @Test
    public void testDeleteSystemMetaAllowed() {

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, null, (String) null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, null, (Integer) null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, null, "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, null, ""));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "old", null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "old", "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "old", ""));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "", null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "", "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, "", ""));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, null, (String) null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, null, (Integer) null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, null, "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, null, ""));

        assertFalse(zms.dbService.isDeleteSystemMetaAllowed(false, "old", null));
        assertFalse(zms.dbService.isDeleteSystemMetaAllowed(false, "old", "new"));
        assertFalse(zms.dbService.isDeleteSystemMetaAllowed(false, "old", ""));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, "", null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, "", "new"));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, "", ""));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, "test", "test"));

        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, 0, 0));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, 5, 5));
        assertFalse(zms.dbService.isDeleteSystemMetaAllowed(false, 5, null));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(false, 0, 5));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, 5, 5));
        assertTrue(zms.dbService.isDeleteSystemMetaAllowed(true, 5, 0));
    }

    @Test
    public void testUpdateRoleSystemMetaFields() {
        Role updatedRole = new Role();
        Role originalRole = new Role();
        RoleSystemMeta meta = new RoleSystemMeta()
                .setAuditEnabled(true);
        zms.dbService.updateRoleSystemMetaFields(mockJdbcConn, updatedRole, originalRole, "auditenabled", meta, "unit-test");
        assertTrue(updatedRole.getAuditEnabled());
        try {
            zms.dbService.updateRoleSystemMetaFields(mockJdbcConn, updatedRole, originalRole, "unknown", meta, "unit-test");
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
        zms.dbService.updateServiceIdentitySystemMetaFields(service, "providerendpoint", meta, "unit-test");
        assertEquals(service.getProviderEndpoint(), "https://localhost");
        try {
            zms.dbService.updateServiceIdentitySystemMetaFields(service, "unknown", meta, "unit-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testUpdateGroupSystemMetaFields() {
        Group group = new Group();
        GroupSystemMeta meta = new GroupSystemMeta()
                .setAuditEnabled(true);
        zms.dbService.updateGroupSystemMetaFields(group, "auditenabled", meta, "unit-test");
        assertTrue(group.getAuditEnabled());
        try {
            zms.dbService.updateGroupSystemMetaFields(group, "unknown", meta, "unit-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testExecutePutGroupMeta() {

        final String domainName = "metadomTest1";
        final String groupName = "metagroupTest1";

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc",
                "testOrg", false, "", 1234, "", 0), admins, null, auditRef);

        Group group = createGroupObject(domainName, groupName, "user.john", "user.jane");
        Group resGroup2 = zms.dbService.executePutGroup(mockDomRsrcCtx, domainName, groupName, group, "test", true);

        assertNotNull(resGroup2);
        assertEquals(resGroup2.getName(), domainName + ":group." + groupName);
        assertEquals(resGroup2.getGroupMembers().size(), 2);

        GroupMeta gm = new GroupMeta();
        gm.setSelfServe(true);

        Group originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
        zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName, groupName, originalGroup, gm, auditRef);

        Group resGroup1 = zms.dbService.getGroup(domainName, groupName, false, false);
        assertTrue(resGroup1.getSelfServe());

        gm = new GroupMeta();
        gm.setSelfServe(true);
        gm.setMemberExpiryDays(10);
        gm.setServiceExpiryDays(15);
        gm.setReviewEnabled(true);
        gm.setNotifyRoles("role1,role2");
        gm.setUserAuthorityFilter("employee");
        gm.setUserAuthorityExpiration("elevated-clearance");

        originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
        zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName, groupName, originalGroup, gm, auditRef);
        resGroup1 = zms.dbService.getGroup(domainName, groupName, false, false);
        assertTrue(resGroup1.getSelfServe());
        assertEquals(resGroup1.getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(resGroup1.getServiceExpiryDays(), Integer.valueOf(15));
        assertTrue(resGroup1.getReviewEnabled());
        assertEquals(resGroup1.getNotifyRoles(), "role1,role2");
        assertEquals(resGroup1.getUserAuthorityFilter(), "employee");
        assertEquals(resGroup1.getUserAuthorityExpiration(), "elevated-clearance");

        gm = new GroupMeta();
        gm.setSelfServe(false);
        gm.setServiceExpiryDays(15);
        gm.setReviewEnabled(false);
        gm.setUserAuthorityFilter("contractor");

        originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
        zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName, groupName, originalGroup, gm, auditRef);
        resGroup1 = zms.dbService.getGroup(domainName, groupName, false, false);
        assertNull(resGroup1.getSelfServe());
        assertEquals(resGroup1.getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(resGroup1.getServiceExpiryDays(), Integer.valueOf(15));
        assertNull(resGroup1.getReviewEnabled());
        assertEquals(resGroup1.getNotifyRoles(), "role1,role2");
        assertEquals(resGroup1.getUserAuthorityFilter(), "contractor");
        assertEquals(resGroup1.getUserAuthorityExpiration(), "elevated-clearance");

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutGroupMetaRetry() {

        final String domainName = "metadomTest1";
        final String groupName = "metagroupTest1";

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc",
                "testOrg", false, "", 1234, "", 0), admins, null, auditRef);

        Group group = createGroupObject(domainName, groupName, "user.john", "user.jane");
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName, groupName, group, "test", false);

        GroupMeta gm = new GroupMeta();
        gm.setSelfServe(true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        zms.dbService.defaultRetryCount = 2;
        ResourceException rex = new ResourceException(409);
        Mockito.when(mockJdbcConn.getGroup(eq(domainName), eq(groupName))).thenReturn(group);
        Mockito.when(mockJdbcConn.updateGroup(eq(domainName), any(Group.class))).thenThrow(rex);

        try {
            Group originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
            zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName, groupName, originalGroup, gm, auditRef);
            fail();
        }catch (ResourceException r) {
            assertEquals(r.getCode(), 409);
            assertTrue(r.getMessage().contains("Conflict"));
        }
        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = 120;
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutGroupMetaExpirationUpdate() {

        final String domainName = "group-meta-expiry";
        final String groupName = "group1";

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Group group = createGroupObject(domainName, groupName, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        group.getGroupMembers().add(new GroupMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true));
        group.getGroupMembers().add(new GroupMember().setMemberName("sys.tim").setExpiration(timExpiry).setApproved(true));
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName, groupName, group, "test", false);

        GroupMeta gm = new GroupMeta();
        gm.setMemberExpiryDays(40);
        gm.setServiceExpiryDays(40);

        Group originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
        zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName, groupName, originalGroup, gm, auditRef);

        Group resGroup1 = zms.dbService.getGroup(domainName, groupName, true, false);

        // verify all users have an expiry of close to 40 days except tim who will maintain
        // his 10 day expiry value

        long ext40Millis = TimeUnit.MILLISECONDS.convert(40, TimeUnit.DAYS);

        int membersChecked = 0;
        for (GroupMember groupMember : resGroup1.getGroupMembers()) {
            switch (groupMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(groupMember.getExpiration().millis() > System.currentTimeMillis() + ext40Millis - 5000 &&
                            groupMember.getExpiration().millis() < System.currentTimeMillis() + ext40Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                case "sys.tim":
                    assertEquals(groupMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

        // now reduce limit to 20 days

        gm.setMemberExpiryDays(20);
        gm.setServiceExpiryDays(20);
        originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
        zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName, groupName, originalGroup, gm, auditRef);

        resGroup1 = zms.dbService.getGroup(domainName, groupName, false, false);

        // verify all users have an expiry of close to 20 days except tim who will maintain
        // his 10 day expiry value

        long ext20Millis = TimeUnit.MILLISECONDS.convert(20, TimeUnit.DAYS);

        membersChecked = 0;
        for (GroupMember groupMember : resGroup1.getGroupMembers()) {
            switch (groupMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(groupMember.getExpiration().millis() > System.currentTimeMillis() + ext20Millis - 5000 &&
                            groupMember.getExpiration().millis() < System.currentTimeMillis() + ext20Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                case "sys.tim":
                    assertEquals(groupMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

        // now set it back to 40 but nothing will change

        gm.setMemberExpiryDays(40);
        gm.setServiceExpiryDays(40);
        originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
        zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName, groupName, originalGroup, gm, auditRef);

        resGroup1 = zms.dbService.getGroup(domainName, groupName, false, false);

        // verify all users have an expiry of close to 20 days except tim who will maintain
        // his 10 day expiry value

        membersChecked = 0;
        for (GroupMember groupMember : resGroup1.getGroupMembers()) {
            switch (groupMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(groupMember.getExpiration().millis() > System.currentTimeMillis() + ext20Millis - 5000 &&
                            groupMember.getExpiration().millis() < System.currentTimeMillis() + ext20Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                case "sys.tim":
                    assertEquals(groupMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

        // now set the service down to 5 days.

        gm.setServiceExpiryDays(5);
        originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
        zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName, groupName, originalGroup, gm, auditRef);

        resGroup1 = zms.dbService.getGroup(domainName, groupName, false, false);

        long ext5Millis = TimeUnit.MILLISECONDS.convert(5, TimeUnit.DAYS);

        // verify all users have their previous values except service tim who will now have
        // a new 5 day expiry value

        membersChecked = 0;
        for (GroupMember groupMember : resGroup1.getGroupMembers()) {
            switch (groupMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(groupMember.getExpiration().millis() > System.currentTimeMillis() + ext20Millis - 5000 &&
                            groupMember.getExpiration().millis() < System.currentTimeMillis() + ext20Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(groupMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
                case "sys.tim":
                    assertTrue(groupMember.getExpiration().millis() > System.currentTimeMillis() + ext5Millis - 5000 &&
                            groupMember.getExpiration().millis() < System.currentTimeMillis() + ext5Millis + 5000);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testUpdateGroupMembersDueDateFailures() {

        final String domainName = "group-meta-duedate";

        Group originalGroup = createGroupObject(domainName, "group1", "user.john", "user.jane");
        originalGroup.setMemberExpiryDays(10);

        Group updateGroup = createGroupObject(domainName, "group1", "user.john", "user.jane");
        updateGroup.setMemberExpiryDays(5);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertGroupMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString()))
                .thenReturn(false)
                .thenThrow(new IllegalArgumentException());

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenThrow(new IllegalArgumentException());

        zms.dbService.updateGroupMembersDueDates(
                mockDomRsrcCtx,
                mockConn,
                domainName,
                "group1",
                originalGroup,
                updateGroup,
                auditRef);
    }

    @Test
    public void testUpdateGroupMembersDueDateNoRoleMembers() {

        final String domainName = "group-meta-duedate";

        // in this test case we're going to set the expiry days to 0 so we
        // get an exception when accessed

        Group group = createGroupObject(domainName, "group1", null, null);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertGroupMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString()))
                .thenReturn(true);

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenThrow(new IllegalArgumentException());

        zms.dbService.updateGroupMembersDueDates(
                mockDomRsrcCtx,
                mockConn,
                domainName,
                "group1",
                group,
                group,
                auditRef);
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
        zms.dbService.executePutRole(mockDomRsrcCtx, "MetaDom1", "MetaRole1", role, "test", "putrole", false);

        RoleSystemMeta rsm = new RoleSystemMeta();
        rsm.setAuditEnabled(true);

        try {
            zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, "MetaDom1", "MetaRole1",
                    rsm,"auditenabled", auditRef, "putrolesystemmeta");
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
        zms.dbService.executePutRole(mockDomRsrcCtx, "MetaDom2", "MetaRole2",role2, "test", "putrole", false);
        RoleSystemMeta rsm2 = new RoleSystemMeta();
        rsm2.setAuditEnabled(true);
        zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, "MetaDom2", "MetaRole2",
                rsm2,"auditenabled", auditRef, "putrolesystemmeta");
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
        zms.dbService.executePutRole(mockDomRsrcCtx, "MetaDom1", "MetaRole1", role, "test", "putrole", false);

        RoleSystemMeta rsm = new RoleSystemMeta();
        rsm.setAuditEnabled(true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        zms.dbService.defaultRetryCount = 2;
        ResourceException rex = new ResourceException(409);
        Domain d = new Domain().setName("MetaDom1").setAuditEnabled(true);
        Mockito.when(mockJdbcConn.getDomain(anyString())).thenReturn(d);
        Mockito.when(mockJdbcConn.getRole(anyString(), anyString())).thenReturn(role);
        Mockito.when(mockJdbcConn.updateRole(anyString(), any(Role.class))).thenThrow(rex);

        try {
            zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, "MetaDom1", "MetaRole1", rsm,
                    "auditenabled", auditRef, "putrolesystemmeta");
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
        assertTrue(role.getAuditEnabled());
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
        final String caller = "testUpdateRoleMetaFields";
        Role role = new Role();
        RoleMeta meta = new RoleMeta().setSelfServe(true)
                .setReviewEnabled(true).setNotifyRoles("role1");
        zms.dbService.updateRoleMetaFields(role, meta, caller);
        assertTrue(role.getSelfServe());
        assertTrue(role.getReviewEnabled());
        assertEquals(role.getNotifyRoles(), "role1");

        meta = new RoleMeta().setReviewEnabled(false);
        zms.dbService.updateRoleMetaFields(role, meta, caller);

        assertTrue(role.getSelfServe());
        assertFalse(role.getReviewEnabled());
        assertEquals(role.getNotifyRoles(), "role1");

        meta = new RoleMeta().setNotifyRoles("role2");
        zms.dbService.updateRoleMetaFields(role, meta, caller);

        assertTrue(role.getSelfServe());
        assertFalse(role.getReviewEnabled());
        assertEquals(role.getNotifyRoles(), "role2");

        meta = new RoleMeta().setUserAuthorityExpiration("expiry");
        zms.dbService.updateRoleMetaFields(role, meta, caller);
        assertEquals(role.getNotifyRoles(), "role2");
        assertEquals(role.getUserAuthorityExpiration(), "expiry");

        meta = new RoleMeta().setUserAuthorityFilter("attr1");
        zms.dbService.updateRoleMetaFields(role, meta, caller);
        assertEquals(role.getNotifyRoles(), "role2");
        assertEquals(role.getUserAuthorityExpiration(), "expiry");
        assertEquals(role.getUserAuthorityFilter(), "attr1");
    }

    @Test
    public void testAuditLogRoleMeta() {
        StringBuilder auditDetails = new StringBuilder();
        Role role = new Role().setName("dom1:role.role1").setSelfServe(true).setReviewEnabled(false)
                        .setSelfRenew(true).setSelfRenewMins(10);
        zms.dbService.auditLogRoleMeta(auditDetails, role, "role1", true);
        assertEquals(auditDetails.toString(),
                "{\"name\": \"role1\", \"selfServe\": \"true\", \"memberExpiryDays\": \"null\","
                        + " \"serviceExpiryDays\": \"null\", \"groupExpiryDays\": \"null\", \"tokenExpiryMins\": \"null\","
                        + " \"certExpiryMins\": \"null\", \"memberReviewDays\": \"null\", \"serviceReviewDays\": \"null\","
                        + " \"groupReviewDays\": \"null\","
                        + " \"reviewEnabled\": \"false\", \"notifyRoles\": \"null\", \"signAlgorithm\": \"null\","
                        + " \"userAuthorityFilter\": \"null\", \"userAuthorityExpiration\": \"null\","
                        + " \"description\": \"null\", \"deleteProtection\": \"null\", \"lastReviewedDate\": \"null\","
                        + " \"maxMembers\": \"null\", \"selfRenew\": \"true\", \"selfRenewMins\": \"10\"}");
    }

    @Test
    public void testExecutePutRoleMeta() {

        final String domainName = "metadom1";
        final String roleName = "metarole1";

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc",
                "testOrg", false, "", 1234, "", 0), admins, null, auditRef);

        Role role = createRoleObject(domainName, roleName, null, "user.john", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role, "test", "putrole", false);

        RoleMeta rm = new RoleMeta();
        rm.setSelfServe(true);

        Role originalRole = zms.dbService.getRole(domainName, roleName, false, false, false);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, roleName, originalRole,
                rm, auditRef, "putrolemeta");

        Role resRole1 = zms.dbService.getRole(domainName, roleName, false, true, false);
        assertTrue(resRole1.getSelfServe());

        rm = new RoleMeta();
        rm.setSelfServe(true);
        rm.setMemberExpiryDays(10);
        rm.setServiceExpiryDays(15);
        rm.setGroupExpiryDays(25);
        rm.setGroupReviewDays(40);
        rm.setTokenExpiryMins(20);
        rm.setReviewEnabled(true);
        rm.setNotifyRoles("role1,role2");
        rm.setMemberReviewDays(30);
        rm.setServiceReviewDays(35);
        rm.setUserAuthorityFilter("employee");
        rm.setUserAuthorityExpiration("elevated-clearance");
        rm.setDescription("testroledescription");

        originalRole = zms.dbService.getRole(domainName, roleName, false, false, false);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, roleName, originalRole,
                rm, auditRef, "putrolemeta");
        resRole1 = zms.dbService.getRole(domainName, roleName, false, true, false);
        assertTrue(resRole1.getSelfServe());
        assertNull(resRole1.getCertExpiryMins());
        assertEquals(resRole1.getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(resRole1.getServiceExpiryDays(), Integer.valueOf(15));
        assertEquals(resRole1.getGroupExpiryDays(), Integer.valueOf(25));
        assertEquals(resRole1.getGroupReviewDays(), Integer.valueOf(40));
        assertEquals(resRole1.getTokenExpiryMins(), Integer.valueOf(20));
        assertTrue(resRole1.getReviewEnabled());
        assertEquals(resRole1.getNotifyRoles(), "role1,role2");
        assertEquals(resRole1.getMemberReviewDays(), Integer.valueOf(30));
        assertEquals(resRole1.getServiceReviewDays(), Integer.valueOf(35));
        assertEquals(resRole1.getUserAuthorityFilter(), "employee");
        assertEquals(resRole1.getUserAuthorityExpiration(), "elevated-clearance");
        assertEquals(resRole1.getDescription(), "testroledescription");

        rm = new RoleMeta();
        rm.setSelfServe(false);
        rm.setCertExpiryMins(10);
        rm.setTokenExpiryMins(25);
        rm.setServiceExpiryDays(15);
        rm.setGroupExpiryDays(20);
        rm.setGroupReviewDays(40);
        rm.setSignAlgorithm("rsa");
        rm.setReviewEnabled(false);
        rm.setServiceReviewDays(35);
        rm.setUserAuthorityFilter("contractor");
        rm.setDescription("testroledescription");

        originalRole = zms.dbService.getRole(domainName, roleName, false, false, false);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, roleName, originalRole,
                rm, auditRef, "putrolemeta");
        resRole1 = zms.dbService.getRole(domainName, roleName, false, true, false);
        assertNull(resRole1.getSelfServe());
        assertEquals(resRole1.getCertExpiryMins(), Integer.valueOf(10));
        assertEquals(resRole1.getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(resRole1.getServiceExpiryDays(), Integer.valueOf(15));
        assertEquals(resRole1.getGroupExpiryDays(), Integer.valueOf(20));
        assertEquals(resRole1.getGroupReviewDays(), Integer.valueOf(40));
        assertEquals(resRole1.getTokenExpiryMins(), Integer.valueOf(25));
        assertEquals(resRole1.getMemberReviewDays(), Integer.valueOf(30));
        assertEquals(resRole1.getServiceReviewDays(), Integer.valueOf(35));
        assertEquals(resRole1.getSignAlgorithm(), "rsa");
        assertNull(resRole1.getReviewEnabled());
        assertEquals(resRole1.getNotifyRoles(), "role1,role2");
        assertEquals(resRole1.getUserAuthorityFilter(), "contractor");
        assertEquals(resRole1.getUserAuthorityExpiration(), "elevated-clearance");
        assertEquals(resRole1.getDescription(), "testroledescription");

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleMetaRetry() {

        final String domainName = "metadom1";
        final String roleName = "metarole1";

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc",
                "testOrg", false, "", 1234, "", 0), admins, null, auditRef);

        Role role = createRoleObject(domainName, roleName, null, "user.john", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role, "test", "putrole", false);

        RoleMeta rm = new RoleMeta();
        rm.setSelfServe(true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        zms.dbService.defaultRetryCount = 2;
        ResourceException rex = new ResourceException(409);
        Mockito.when(mockJdbcConn.getRole(anyString(), anyString())).thenReturn(role);
        Mockito.when(mockJdbcConn.updateRole(anyString(), any(Role.class))).thenThrow(rex);

        try {
            Role originalRole = zms.dbService.getRole(domainName, roleName, false, false, false);
            zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, roleName, originalRole,
                    rm, auditRef, "putrolemeta");
            fail();
        }catch (ResourceException r) {
            assertEquals(r.getCode(), 409);
            assertTrue(r.getMessage().contains("Conflict"));
        }
        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = 120;
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testCheckRoleAuditEnabledFlagTrueRefNull() {

        String domainName = "audit-test-domain-name";
        String roleName = "testrole";
        Role role = new Role().setAuditEnabled(true);
        Mockito.doReturn(role).when(mockJdbcConn).getRole(domainName, roleName);

        String caller = "testCheckRoleAuditEnabledFlagTrueRefNull";
        String principal = "testprincipal";
        try {
            zms.dbService.checkObjectAuditEnabled(mockJdbcConn, role.getAuditEnabled(), role.getName(), null, caller, principal);
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
        Mockito.doReturn(role).when(mockJdbcConn).getRole(domainName, roleName);

        String auditCheck = "";  // empty string
        String caller = "testCheckRoleAuditEnabledFlagTrueRefEmpty";
        String principal = "testprincipal";
        try {
            zms.dbService.checkObjectAuditEnabled(mockJdbcConn, role.getAuditEnabled(), role.getName(), auditCheck, caller, principal);
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
        Mockito.doReturn(role).when(mockJdbcConn).getRole(domainName, roleName);

        String auditCheck = "testaudit";
        String caller = "testCheckRoleAuditEnabledFlagFalseRefValid";
        String principal = "testprincipal";
        zms.dbService.checkObjectAuditEnabled(mockJdbcConn, role.getAuditEnabled(), role.getName(), auditCheck, caller, principal);
    }

    @Test
    public void testCheckRoleAuditEnabledFlagFalseRefNull() {

        String domainName = "audit-test-domain-name";
        String roleName = "testrole";
        Role role = new Role().setAuditEnabled(false);
        Mockito.doReturn(role).when(mockJdbcConn).getRole(domainName, roleName);

        String caller = "testCheckRoleAuditEnabledFlagFalseRefNull";
        String principal = "testprincipal";
        zms.dbService.checkObjectAuditEnabled(mockJdbcConn, role.getAuditEnabled(), role.getName(), null, caller, principal);
    }

    @Test
    public void testCheckRoleAuditEnabledFlagTrueRefValidationFail() {

        String domainName = "audit-test-domain-name";
        String roleName = "testrole";
        Role role = new Role().setAuditEnabled(true);
        Mockito.doReturn(role).when(mockJdbcConn).getRole(domainName, roleName);

        zms.dbService.auditReferenceValidator = new MockAuditReferenceValidatorImpl();

        String caller = "testCheckRoleAuditEnabledFlagTrueRefValidationFail";
        String principal = "testprincipal";
        try {
            zms.dbService.checkObjectAuditEnabled(mockJdbcConn, role.getAuditEnabled(), role.getName(), "auditref", caller, principal);
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
        Mockito.doReturn(role).when(mockJdbcConn).getRole(domainName, roleName);

        zms.dbService.auditReferenceValidator = null;

        String caller = "testCheckRoleAuditEnabledFlagTrueValidatorNull";
        String principal = "testprincipal";
        zms.dbService.checkObjectAuditEnabled(mockJdbcConn, role.getAuditEnabled(), role.getName(), "auditref", caller, principal);
    }

    @Test
    public void testExecutePutMembershipDecision() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setApproved(false), auditRef, "putMembership", false);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob").setApproved(false), auditRef, "putMembership", false);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutMembershipDecisionFail() {

        String domainName = "mgradddom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership", false);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob").setActive(false).setApproved(false),
                    auditRef, "putMembership", false);

        try {
            zms.dbService.executePutMembershipDecision(mockDomRsrcCtx, domainName, "invalid",
                new RoleMember().setMemberName("user.doe").setActive(true).setApproved(true),
                    auditRef, "putMembershipDecision");
            fail();
        }catch (ResourceException r) {
            assertEquals(r.getCode(), 404);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutRoleAuditEnabled() {

        String domainName = "executeputroledom1";
        String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        DomainMeta meta2 = new DomainMeta()
                .setAccount("acct")
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud")
                .setAuditEnabled(true);
        Domain d1 = zms.dbService.getDomain(domainName, false);
        zms.dbService.updateSystemMetaFields(d1, "auditenabled", false, meta2);

        Domain metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta2, "auditenabled", false, auditRef, "");

        Role role1 = createRoleObject(domainName, roleName, null,"user.joe", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole", false);

        RoleSystemMeta meta = new RoleSystemMeta().setAuditEnabled(true);
        zms.dbService.updateRoleSystemMetaFields(mockJdbcConn, role1, role1, "auditenabled", meta, "unit-test");

        zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, domainName, roleName, meta, "auditenabled", auditRef, "");

        Role role3 = zms.dbService.getRole(domainName, roleName, false, false, false);
        assertNotNull(role3);
        assertTrue(role3.getAuditEnabled());

        List<RoleMember> newMembers = new ArrayList<>();
        RoleMember rm1 = new RoleMember().setMemberName("user.john").setActive(true).setApproved(true);
        newMembers.add(rm1);
        role1.setRoleMembers(newMembers);
        try {
            zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "putRole", false);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 400);
        }
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutMembershipDecisionBadRequest() {

        final String domainName = "put-mbr-decision-bad-request";
        final String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,"Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, null, "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership", false);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob").setActive(false).setApproved(false),
                    auditRef, "putMembership", false);

        RoleMember roleMem = new RoleMember().setMemberName("user.doe").setActive(true).setApproved(true);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        Mockito.when(mockJdbcConn.getRole(domainName, roleName)).thenReturn(role1);
        Mockito.when(mockJdbcConn.confirmRoleMember(anyString(), anyString(), any(), anyString(),
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
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutMembershipDecisionWithExpiry() {

        final String domainName = "put-mbr-decision-expiry";
        final String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setApproved(false), auditRef, "putMembership", false);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutMembershipDecisionRetry() {

        final String domainName = "put-mbr-decision-retry";
        final String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,"Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,"user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership", false);

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob").setActive(false).setApproved(false),
                    auditRef, "putMembership", false);

        RoleMember roleMem = new RoleMember().setMemberName("user.doe").setActive(true).setApproved(true);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        zms.dbService.defaultRetryCount = 2;
        Mockito.when(mockJdbcConn.getRole(domainName, roleName)).thenReturn(role1);
        ResourceException rex = new ResourceException(409);
        Mockito.when(mockJdbcConn.confirmRoleMember(anyString(), anyString(), any(), anyString(),
                anyString())).thenThrow(rex);
        try {
            zms.dbService.executePutMembershipDecision(mockDomRsrcCtx, domainName, roleName,
                    roleMem, auditRef, "putMembershipDecision");
            fail();
        } catch (ResourceException r) {
            assertEquals(r.getCode(), 409);
            assertTrue(r.getMessage().contains("Conflict"));
        }
        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = 120;
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testGetPendingDomainRoleMembersListEmptyMap() {
        DomainRoleMembership domainRoleMembership = zms.dbService.getPendingDomainRoleMembers("user.user1", null);
        assertNotNull(domainRoleMembership);
        assertTrue(domainRoleMembership.getDomainRoleMembersList().isEmpty());
    }

    @Test
    public void testGetPendingDomainGroupMembersListEmptyMap() {
        DomainGroupMembership domainGroupMembership = zms.dbService.getPendingDomainGroupMembers("user.user1", null);
        assertNotNull(domainGroupMembership);
        assertTrue(domainGroupMembership.getDomainGroupMembersList().isEmpty());
    }

    @Test
    public void testGetPendingDomainGroupMembersList() {
        String domainName = "domain1";
        String principal = "user.user1";
        Map<String, List<DomainGroupMember>> dummyResult = new LinkedHashMap<>();
        dummyResult.put(domainName, Collections.singletonList(new DomainGroupMember()));
        dummyResult.put("domain2", Collections.singletonList(new DomainGroupMember()));

        Mockito.when(mockJdbcConn.getPendingDomainGroupMembersByPrincipal(principal)).thenReturn(dummyResult);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        DomainGroupMembership domainGroupMembership = zms.dbService.getPendingDomainGroupMembers(principal, domainName);
        assertNotNull(domainGroupMembership);
        assertEquals(domainGroupMembership.getDomainGroupMembersList().size(), 1);
        assertEquals(domainGroupMembership.getDomainGroupMembersList().get(0).domainName, domainName);

        domainGroupMembership = zms.dbService.getPendingDomainGroupMembers(principal, "domain2");
        assertNotNull(domainGroupMembership);
        assertEquals(domainGroupMembership.getDomainGroupMembersList().size(), 1);
        assertEquals(domainGroupMembership.getDomainGroupMembersList().get(0).domainName, "domain2");

        domainGroupMembership = zms.dbService.getPendingDomainGroupMembers(principal, "*");
        assertNotNull(domainGroupMembership);
        assertEquals(domainGroupMembership.getDomainGroupMembersList().size(), 2);

        domainGroupMembership = zms.dbService.getPendingDomainGroupMembers(principal, null);
        assertNotNull(domainGroupMembership);
        assertEquals(domainGroupMembership.getDomainGroupMembersList().size(), 2);

        zms.dbService.store = saveStore;
    }

    @Test
    public void testGetPendingDomainRoleMembersList() {
        String domainName = "domain1";
        String principal = "user.user1";
        Map<String, List<DomainRoleMember>> dummyResult = new LinkedHashMap<>();
        dummyResult.put(domainName, Collections.singletonList(new DomainRoleMember()));
        dummyResult.put("domain2", Collections.singletonList(new DomainRoleMember()));

        Mockito.when(mockJdbcConn.getPendingDomainRoleMembersByPrincipal(principal)).thenReturn(dummyResult);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        DomainRoleMembership domainRoleMembership = zms.dbService.getPendingDomainRoleMembers(principal, domainName);
        assertNotNull(domainRoleMembership);
        assertEquals(domainRoleMembership.getDomainRoleMembersList().size(), 1);
        assertEquals(domainRoleMembership.getDomainRoleMembersList().get(0).domainName, domainName);

        domainRoleMembership = zms.dbService.getPendingDomainRoleMembers(principal, "domain2");
        assertNotNull(domainRoleMembership);
        assertEquals(domainRoleMembership.getDomainRoleMembersList().size(), 1);
        assertEquals(domainRoleMembership.getDomainRoleMembersList().get(0).domainName, "domain2");

        domainRoleMembership = zms.dbService.getPendingDomainRoleMembers(principal, "*");
        assertNotNull(domainRoleMembership);
        assertEquals(domainRoleMembership.getDomainRoleMembersList().size(), 2);

        domainRoleMembership = zms.dbService.getPendingDomainRoleMembers(principal, null);
        assertNotNull(domainRoleMembership);
        assertEquals(domainRoleMembership.getDomainRoleMembersList().size(), 2);

        zms.dbService.store = saveStore;
    }

    @Test
    public void testGetRolePending() {

        final String domainName = "get-role-pending";
        final String roleName = "role1";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,"Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);
        Role role1 = createRoleObject(domainName, roleName, null,"user.joe", "user.jane");
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role1, auditRef, "testGetRolePending", false);
        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership", false);

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

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutDomainMetaForbidden() {

        TopLevelDomain dom1 = createTopLevelDomainObject("MetaDom1",
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

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
        Domain metaDomain = zms.dbService.getDomain("metadom1", true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, null, false, auditRef, "putDomainMeta");
        try {
            metaDomain = zms.dbService.getDomain("metadom1", true);
            zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, "org", false, auditRef, "putDomainMeta");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 403);
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, "MetaDom1", auditRef, null);
    }

    @Test
    public void testGetPendingMembershipNotifications() {

        TopLevelDomain dom1 = createTopLevelDomainObject("dom1", "Test Domain1", "testorg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

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
        zms.dbService.executePutRole(mockDomRsrcCtx, "dom2", "role2", role2, "test", "putrole", false);
        RoleSystemMeta rsm2 = new RoleSystemMeta();
        rsm2.setAuditEnabled(true);
        zms.dbService.executePutRoleSystemMeta(mockDomRsrcCtx, "dom2", "role2",
                rsm2,"auditenabled", auditRef, "putrolesystemmeta");

        zms.dbService.executePutMembership(mockDomRsrcCtx, "dom2", "role2",
                new RoleMember().setMemberName("user.poe").setActive(false).setApproved(false),
                    auditRef, "putMembership", false);

        Role role1 = createRoleObject("dom1", "role1", null,"user.joe", "user.jane");
        role1.setSelfServe(true);
        zms.dbService.executePutRole(mockDomRsrcCtx, "dom1", "role1", role1, auditRef,
                "testGetPendingMembershipNotifications", false);
        zms.dbService.executePutMembership(mockDomRsrcCtx, "dom1", "role1",
                new RoleMember().setMemberName("user.doe").setActive(false).setApproved(false),
                    auditRef, "putMembership", false);

        Role auditApproverRole = createRoleObject("sys.auth.audit.org", "testorg",
                null, "user.boe", adminUser);
        zms.dbService.executePutRole(mockDomRsrcCtx, "sys.auth.audit.org", "testorg",
                auditApproverRole, "test", "putrole", false);

        ZMSTestUtils.sleep(1000);
        Set<String> recipientRoles = zms.dbService.getPendingMembershipApproverRoles(0);

        assertNotNull(recipientRoles);
        assertTrue(recipientRoles.contains("dom1:role.admin"));
        assertTrue(recipientRoles.contains("sys.auth.audit.org:role.testorg"));

        zms.dbService.executeDeleteRole(mockDomRsrcCtx, "sys.auth.audit.org", "testorg", "cleanup", "unitttest");
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "dom1", auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, "dom2", auditRef, null);
    }

    @Test
    public void testGetPendingMembershipNotificationsEdge() {

        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        recipients.add("unix.moe");
        Mockito.when(mockJdbcConn.updatePendingRoleMembersNotificationTimestamp(anyString(), anyLong(), anyInt())).thenReturn(true);
        Mockito.when(mockJdbcConn.getPendingMembershipApproverRoles(anyString(), anyLong())).thenReturn(recipients);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Set<String> recipientsRes = zms.dbService.getPendingMembershipApproverRoles(0);

        assertNotNull(recipientsRes);
        assertTrue(recipientsRes.contains("user.joe"));

        zms.dbService.store = saveStore;
    }

    @Test
    public void testGetPendingMembershipNotificationsTimestampUpdateFailed() {

        Mockito.when(mockJdbcConn.updatePendingRoleMembersNotificationTimestamp(anyString(), anyLong(), anyInt())).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        Set<String> recipientsRes = zms.dbService.getPendingMembershipApproverRoles(0);
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

        Mockito.when(mockJdbcConn.getExpiredPendingDomainRoleMembers(30)).thenReturn(memberList);
        Mockito.when(mockJdbcConn.deletePendingRoleMember("dom1", "role1", "user.user1", "sys.auth.monitor",
                "Expired - auto reject")).thenReturn(true);
        Mockito.when(mockJdbcConn.deletePendingRoleMember("dom1", "role1", "user.user2", "sys.auth.monitor",
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
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        Role role1 = createRoleObject(domainName, roleName, null,
                "user.joe", "user.jane");
        zms.putRole(mockDomRsrcCtx, domainName, roleName, auditRef, false, null, role1);

        // we're creating one with current time

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.doe")
                        .setApproved(false)
                        .setRequestTime(Timestamp.fromCurrentTime()),
                auditRef, "putMembership", false);

        // second one is over 31 days old

        zms.dbService.executePutMembership(mockDomRsrcCtx, domainName, roleName,
                new RoleMember().setMemberName("user.bob")
                        .setApproved(false)
                        .setRequestTime(Timestamp.fromMillis(TimeUnit.MILLISECONDS.convert(31, TimeUnit.DAYS))),
                auditRef, "putMembership", false);

        // we should have 2 regular and 2 pending users

        Role role = zms.dbService.getRole(domainName, roleName, false, false, true);
        assertEquals(role.getRoleMembers().size(), 4);

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testExecutePutRoleMetaExpirationUpdate() {

        final String domainName = "role-meta-expiry";
        final String roleName = "role1";

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role = createRoleObject(domainName, roleName, null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true));
        role.getRoleMembers().add(new RoleMember().setMemberName("sys.tim").setExpiration(timExpiry).setApproved(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, roleName, role, "test", "putrole", false);

        RoleMeta rm = new RoleMeta();
        rm.setMemberExpiryDays(40);
        rm.setServiceExpiryDays(40);

        Role originalRole = zms.dbService.getRole(domainName, roleName, false, false, false);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, roleName, originalRole,
                rm, auditRef, "putrolemeta");

        Role resRole1 = zms.dbService.getRole(domainName, roleName, false, true, false);

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
        originalRole = zms.dbService.getRole(domainName, roleName, false, false, false);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, roleName, originalRole,
                rm, auditRef, "putrolemeta");

        resRole1 = zms.dbService.getRole(domainName, roleName, false, true, false);

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
        originalRole = zms.dbService.getRole(domainName, roleName, false, false, false);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, roleName, originalRole,
                rm, auditRef, "putrolemeta");

        resRole1 = zms.dbService.getRole(domainName, roleName, false, true, false);

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
        originalRole = zms.dbService.getRole(domainName, roleName, false, false, false);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, roleName, originalRole,
                rm, auditRef, "putrolemeta");

        resRole1 = zms.dbService.getRole(domainName, roleName, false, true, false);

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
    public void testUpdateRoleMembersDueDateFailures() {

        final String domainName = "role-meta-duedate";

        Role originalRole = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        originalRole.setMemberExpiryDays(10);
        originalRole.setMemberReviewDays(20);

        Role updateRole = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        updateRole.setMemberExpiryDays(5);
        updateRole.setMemberReviewDays(25);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                    Mockito.any(), Mockito.anyString()))
                .thenReturn(false)
                .thenThrow(new IllegalArgumentException());

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenThrow(new IllegalArgumentException());

        zms.dbService.updateRoleMembersDueDates(
                mockDomRsrcCtx,
                mockConn,
                domainName,
                "role1",
                originalRole,
                updateRole,
                auditRef,
                "testUpdateRoleMembersDueDateFailures");
    }

    @Test
    public void testUpdateRoleMembersDueDateTrust() {

        final String domainName = "role-meta-duedate";

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

        zms.dbService.updateRoleMembersDueDates(
                mockDomRsrcCtx,
                mockConn,
                domainName,
                "role1",
                role,
                role,
                auditRef,
                "testUpdateRoleMembersDueDateTrust");
    }

    @Test
    public void testUpdateRoleMembersDueDateNoRoleMembers() {

        final String domainName = "role-meta-duedate";

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

        zms.dbService.updateRoleMembersDueDates(
                mockDomRsrcCtx,
                mockConn,
                domainName,
                "role1",
                role,
                role,
                auditRef,
                "testUpdateRoleMembersDueDateNoRoleMembers");
    }

    @Test
    public void testExecutePutDomainMetaExpirationUpdate() {

        final String domainName = "domain-meta-expiry";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Group group1 = createGroupObject(domainName, "group1", "user.john", "user.jane");
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName, "group1", group1, "test", false);

        Group group2 = createGroupObject(domainName, "group2", null, null);
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName, "group2", group2, "test", false);

        long now = System.currentTimeMillis();
        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(now + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry)
                .setApproved(true));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user-headless.api").setApproved(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole", false);

        Role role2 = createRoleObject(domainName, "role2", null, "user.john", "user.jane");
        role2.getRoleMembers().get(0).setExpiration(timExpiry);
        role2.getRoleMembers().get(1).setExpiration(timExpiry);
        role2.setMemberExpiryDays(15);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2", role2, "test", "putrole", false);

        Role role3 = createRoleObject(domainName, "role3", "coretech", null, null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3", role3, "test", "putrole", false);

        Domain metaDomain = zms.dbService.getDomain(domainName, true);
        DomainMeta meta = new DomainMeta().setMemberExpiryDays(40);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, null, false, auditRef, "putDomainMeta");

        Role resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        // verify all users have an expiry of close to 40 days except tim who will maintain
        // his 10-day expiry value. the headless user and the group members are with no expiry

        long ext40Millis = TimeUnit.MILLISECONDS.convert(40, TimeUnit.DAYS);

        int membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(roleMember.getExpiration().millis() > now + ext40Millis - 5000 &&
                            roleMember.getExpiration().millis() < now + ext40Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(roleMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
                case "user-headless.api":
                    assertNull(roleMember.getExpiration());
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

        // verify all group members have an expiry of close to 40 days

        membersChecked = 0;
        Group resGroup1 = zms.dbService.getGroup(domainName, "group1", false, false);

        for (GroupMember groupMember : resGroup1.getGroupMembers()) {
            switch (groupMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertTrue(groupMember.getExpiration().millis() > now + ext40Millis - 5000 &&
                            groupMember.getExpiration().millis() < now + ext40Millis + 5000);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 2);

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

        // now reduce limit to 5 days and set service to 40 days

        meta.setMemberExpiryDays(5);
        meta.setServiceExpiryDays(40);
        metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, null, false, auditRef, "putDomainMeta");

        resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        // verify all users have an expiry of 5 days and headless user 40 days

        long ext5Millis = TimeUnit.MILLISECONDS.convert(5, TimeUnit.DAYS);

        membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                case "user.tim":
                    assertTrue(roleMember.getExpiration().millis() > now + ext5Millis - 5000 &&
                            roleMember.getExpiration().millis() < now + ext5Millis + 5000);
                    membersChecked += 1;
                    break;
                case "user-headless.api":
                    assertTrue(roleMember.getExpiration().millis() > now + ext40Millis - 5000 &&
                            roleMember.getExpiration().millis() < now + ext40Millis + 5000);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 4);

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
        metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, null, false, auditRef, "putDomainMeta");

        resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        membersChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                case "user.tim":
                    assertTrue(roleMember.getExpiration().millis() > now + ext5Millis - 5000 &&
                            roleMember.getExpiration().millis() < now + ext5Millis + 5000);
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
    public void testExecutePutDomainMetaUserAuthorityFilterUpdate() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.isAttributeSet("user.john", "employee")).thenReturn(true);
        Mockito.when(authority.isAttributeSet("user.jane", "employee")).thenReturn(false);
        Mockito.when(authority.isAttributeSet("user.joe", "employee")).thenReturn(true);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "domain-meta-user-authority-filter";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc",
                "org", false, "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        role1.getRoleMembers().add(new RoleMember().setMemberName("sys.auth.api").setApproved(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole", false);

        Role role2 = createRoleObject(domainName, "role2", null, null, null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2", role2, "test", "putrole", false);

        Role role3 = createRoleObject(domainName, "role3", "coretech", null, null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role3", role3, "test", "putrole", false);

        DomainMeta meta = new DomainMeta().setUserAuthorityFilter("employee");
        Domain metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, "userauthorityfilter", false, auditRef, "putDomainMeta");

        Role resRole1 = zms.dbService.getRole(domainName, "role1", false, true, false);

        // verify jane has been disabled due to authority check

        RoleMember member = getRoleMember(resRole1, "user.john");
        assertNull(member.getSystemDisabled());

        member = getRoleMember(resRole1, "user.jane");
        assertEquals(1, member.getSystemDisabled().intValue());

        member = getRoleMember(resRole1, "sys.auth.api");
        assertNull(member.getSystemDisabled());

        // verify that all users in role2 have not changed since the role already
        // has an expiration

        Role resRole2 = zms.dbService.getRole(domainName, "role2", false, true, false);
        assertTrue(resRole2.getRoleMembers().isEmpty());

        // verify our trust role

        Role resRole3 = zms.dbService.getRole(domainName, "role3", false, true, false);
        assertEquals(resRole3.getTrust(), "coretech");
        assertNull(resRole3.getRoleMembers());

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");

        // reset authority to its original value

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testUpdateDomainMembersExpirationNoChanges() {

        final String domainName = "domain-meta-expiry";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1998, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().get(0).setExpiration(timExpiry);
        role1.getRoleMembers().get(1).setExpiration(timExpiry);
        role1.setMemberExpiryDays(15);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole", false);

        Role role2 = createRoleObject(domainName, "role2", null, null, null);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role2", role2, "test", "putrole", false);

        RoleMeta rm = new RoleMeta().setMemberExpiryDays(10);
        Role originalRole = zms.dbService.getRole(domainName, "admin", false, false, false);
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName, "admin", originalRole,
                rm, auditRef, "putrolemeta");

        // we're going to set the meta but there will be no changes
        // since the both roles have values set.

        DomainMeta meta = new DomainMeta().setMemberExpiryDays(5);
        Domain metaDomain = zms.dbService.getDomain(domainName, true);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, metaDomain, meta, null, false, auditRef, "putDomainMeta");

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

        final String domainName = "expiration-failure";
        Domain domain = new Domain().setName(domainName).setMemberExpiryDays(100)
                .setModified(Timestamp.fromCurrentTime());
        Domain updateDomain = new Domain().setName(domainName).setMemberExpiryDays(50);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.getAthenzDomain(domainName)).thenThrow(new ResourceException(400));

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();
        Authority authority = Mockito.mock(Authority.class);
        zms.dbService.zmsConfig.setUserAuthority(authority);

        zms.dbService.updateDomainMembersExpiration(mockDomRsrcCtx, mockConn, domain, updateDomain, auditRef,
                "testUpdateMdomainMembersExpirationFailure");

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testUpdateDomainMembersExpirationObjectStoreFailure() {

        final String domainName = "domain-meta-expiry";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc",
                "org", false, "", 1999, "", 0), admins, null, auditRef);

        Domain domain = new Domain().setName(domainName).setMemberExpiryDays(100)
                .setModified(Timestamp.fromCurrentTime());
        Domain updateDomain = new Domain().setName(domainName).setMemberExpiryDays(50);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        AthenzDomain athenzDomain = new AthenzDomain(domainName);
        athenzDomain.setDomain(domain);
        Mockito.when(mockConn.getAthenzDomain(domainName)).thenReturn(athenzDomain);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(false);

        Group group1 = createGroupObject(domainName, "group1", "user.john", "user.jane");
        Group group2 = createGroupObject(domainName, "group1", "user.john", "user.jane");
        group2.setMemberExpiryDays(3);
        Group group3 = createGroupObject(domainName, "group1", "user.john", "user.jane");
        group3.setGroupMembers(null);
        List<Group> groupList = new ArrayList<>();
        groupList.add(group1);
        groupList.add(group2);
        groupList.add(group3);
        athenzDomain.setGroups(groupList);

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenThrow(new ResourceException(400));

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();
        Authority authority = Mockito.mock(Authority.class);
        zms.dbService.zmsConfig.setUserAuthority(authority);

        zms.dbService.updateDomainMembersExpiration(mockDomRsrcCtx, mockConn, domain, updateDomain, auditRef,
                "testUpdateDomainMembersExpirationFailure");

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testUpdateDomainMembersUserAuthorityFilterFailure() {

        final String domainName = "domain-meta-user-authority-filter";
        Domain domain = new Domain().setName(domainName).setUserAuthorityFilter("contractor")
                .setModified(Timestamp.fromCurrentTime());
        Domain updateDomain = new Domain().setName(domainName).setUserAuthorityFilter("employee");

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.getAthenzDomain(domainName)).thenThrow(new ResourceException(400));

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();
        Authority authority = Mockito.mock(Authority.class);
        zms.dbService.zmsConfig.setUserAuthority(authority);

        zms.dbService.updateDomainMembersUserAuthorityFilter(mockDomRsrcCtx, mockConn, domain, updateDomain,
                auditRef, "testUpdateDomainMembersUserAuthorityFilterFailure");

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testUpdateDomainMemberUserAuthorityFilterObjectStoreFailure() {

        final String domainName = "domain-meta-user-authority-filter";
        List<String> admins = new ArrayList<>();
        admins.add("user.john");

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc",
                "org", false, "", 1997, "", 0), admins, null, auditRef);

        AthenzDomain athenzDomain = zms.dbService.getAthenzDomain(domainName, false);
        Domain domain = new Domain().setName(domainName).setUserAuthorityFilter("contractor")
                .setModified(Timestamp.fromCurrentTime());
        Domain updateDomain = new Domain().setName(domainName).setUserAuthorityFilter("employee");

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.getAthenzDomain(domainName)).thenReturn(athenzDomain);
        Mockito.when(mockConn.updateRoleMemberDisabledState(Mockito.anyString(), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString(), Mockito.anyInt(), Mockito.anyString()))
                .thenReturn(false);

        // we're going to make sure to throw an exception here
        // since this should never be called

        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenThrow(new IllegalArgumentException());

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();
        Authority authority = Mockito.mock(Authority.class);
        zms.dbService.zmsConfig.setUserAuthority(authority);

        zms.dbService.updateDomainMembersUserAuthorityFilter(mockDomRsrcCtx, mockConn, domain, updateDomain,
                auditRef, "testUpdateDomainMemberUserAuthorityFilterObjectStoreFailure");

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testIsNumOfDaysReduced() {

        assertFalse(zms.dbService.isNumOfDaysReduced(null, null));
        assertFalse(zms.dbService.isNumOfDaysReduced(10, null));
        assertFalse(zms.dbService.isNumOfDaysReduced(0, null));
        assertFalse(zms.dbService.isNumOfDaysReduced(-1, null));

        assertFalse(zms.dbService.isNumOfDaysReduced(null, 0));
        assertFalse(zms.dbService.isNumOfDaysReduced(10, 0));
        assertFalse(zms.dbService.isNumOfDaysReduced(0, 0));
        assertFalse(zms.dbService.isNumOfDaysReduced(-1, 0));

        assertFalse(zms.dbService.isNumOfDaysReduced(null, -1));
        assertFalse(zms.dbService.isNumOfDaysReduced(10, -1));
        assertFalse(zms.dbService.isNumOfDaysReduced(0, -1));
        assertFalse(zms.dbService.isNumOfDaysReduced(-1, -1));

        assertTrue(zms.dbService.isNumOfDaysReduced(null, 10));
        assertTrue(zms.dbService.isNumOfDaysReduced(0, 10));
        assertTrue(zms.dbService.isNumOfDaysReduced(-1, 10));

        assertFalse(zms.dbService.isNumOfDaysReduced(5, 10));
        assertTrue(zms.dbService.isNumOfDaysReduced(10, 5));
    }

    @Test
    public void testGetServicePublicKeyEntryServiceUnavailable() {

        final String domainName = "test1";
        final String serviceName = "service1";
        final String keyId = "0";

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
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
        assertEquals(auditDetails.toString(), "{\"member\": \"user.joe\", \"approved\": true, \"system-disabled\": 0}");

        auditDetails.setLength(0);
        RoleMember rm2 = new RoleMember().setMemberName("user.joe").setApproved(true).setSystemDisabled(0);
        zms.dbService.auditLogRoleMember(auditDetails, rm2, true);
        assertEquals(auditDetails.toString(), "{\"member\": \"user.joe\", \"approved\": true, \"system-disabled\": 0}");

        auditDetails.setLength(0);
        RoleMember rm3 = new RoleMember().setMemberName("user.joe").setApproved(false).setSystemDisabled(1);
        zms.dbService.auditLogRoleMember(auditDetails, rm3, true);
        assertEquals(auditDetails.toString(), "{\"member\": \"user.joe\", \"approved\": false, \"system-disabled\": 1}");

        auditDetails.setLength(0);
        RoleMember rm4 = new RoleMember().setMemberName("user.joe")
                .setApproved(false).setExpiration(Timestamp.fromMillis(1000)).setSystemDisabled(3);
        zms.dbService.auditLogRoleMember(auditDetails, rm4, true);
        assertEquals(auditDetails.toString(), "{\"member\": \"user.joe\", \"expiration\": \"1970-01-01T00:00:01.000Z\", \"approved\": false, \"system-disabled\": 3}");
    }

    @Test
    public void testGetRoleExpiryMembers() {
        testGetNotificationMembers(true);
    }

    @Test
    public void testGetRoleReviewMembers() {
        testGetNotificationMembers(false);
    }

    private void testGetNotificationMembers(boolean isRoleExpire) {
        final String domainName1 = "role-members1";
        final String domainName2 = "role-members2";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        // Create domain
        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName1, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        // Create role1 with two members - oneday and sevenday
        Role role = createRoleObject(domainName1, "role1", null, "user.john", "user.jane");
        Timestamp oneDayFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        Timestamp sevenDaysFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(7, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        RoleMember roleMemberOneDay = new RoleMember().setMemberName("user.oneday").setApproved(true);
        RoleMember roleMemberSevenDays = new RoleMember().setMemberName("user.sevenday").setApproved(true);
        if (isRoleExpire) {
            roleMemberOneDay.setExpiration(oneDayFromNow);
            roleMemberSevenDays.setExpiration(sevenDaysFromNow);
        } else {
            roleMemberOneDay.setReviewReminder(oneDayFromNow);
            roleMemberSevenDays.setReviewReminder(sevenDaysFromNow);
        }
        role.getRoleMembers().add(roleMemberOneDay);
        role.getRoleMembers().add(roleMemberSevenDays);

        zms.dbService.executePutRole(mockDomRsrcCtx, domainName1, "role1", role, "test", "putrole", false);

        // Create role2 with one member - twoday
        Role role2 = createRoleObject(domainName1, "role2", null, "user.john", "user.jane");
        Timestamp twoDayFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(2, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        RoleMember roleMemberTwoDays = new RoleMember().setMemberName("user.twoday").setApproved(true);
        if (isRoleExpire) {
            roleMemberTwoDays.setExpiration(twoDayFromNow);
        } else {
            roleMemberTwoDays.setReviewReminder(twoDayFromNow);
        }
        role2.getRoleMembers().add(roleMemberTwoDays);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName1, "role2", role2, "test", "putrole", false);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName2, "test desc", "org", false,
                "", 1235, "", 0), admins, null, auditRef);

        // Create role3 with two members - tourteenday and thirtyfiveday
        Role role3 = createRoleObject(domainName2, "role3", null, "user.john", "user.jane");
        Timestamp fourteenDayFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(14, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        Timestamp thirtyfiveDayFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(35, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        RoleMember roleMemberFourteenDays = new RoleMember().setMemberName("user.fourteenday").setApproved(true);
        RoleMember roleMemberThirtyFiveDays = new RoleMember().setMemberName("user.thirtyfiveday").setApproved(true);
        if (isRoleExpire) {
            roleMemberFourteenDays.setExpiration(fourteenDayFromNow);
            roleMemberThirtyFiveDays.setExpiration(thirtyfiveDayFromNow);
        } else {
            roleMemberFourteenDays.setReviewReminder(fourteenDayFromNow);
            roleMemberThirtyFiveDays.setReviewReminder(thirtyfiveDayFromNow);
        }
        role3.getRoleMembers().add(roleMemberFourteenDays);
        role3.getRoleMembers().add(roleMemberThirtyFiveDays);

        zms.dbService.executePutRole(mockDomRsrcCtx, domainName2, "role3", role3, "test", "putrole", false);

        Map<String, DomainRoleMember> domainRoleMembers = isRoleExpire ?
                zms.dbService.getRoleExpiryMembers(0) : zms.dbService.getRoleReviewMembers(0);
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
    public void testGetGroupExpiryMembers() {

        final String domainName1 = "group-members1";
        final String domainName2 = "group-members2";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        // Create domain
        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName1, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        // Create group with two members - oneday and sevenday
        Group group = createGroupObject(domainName1, "group1", "user.john", "user.jane");
        Timestamp oneDayFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        Timestamp sevenDaysFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(7, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        GroupMember groupMemberOneDay = new GroupMember().setMemberName("user.oneday")
                .setApproved(true).setExpiration(oneDayFromNow);
        GroupMember groupMemberSevenDays = new GroupMember().setMemberName("user.sevenday")
                .setApproved(true).setExpiration(sevenDaysFromNow);
        group.getGroupMembers().add(groupMemberOneDay);
        group.getGroupMembers().add(groupMemberSevenDays);

        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName1, "group1", group, "putGroup", false);


        // Create group2 with one member - twoday
        Group group2 = createGroupObject(domainName1, "group2", "user.john", "user.jane");
        Timestamp twoDayFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(2, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        GroupMember groupMemberTwoDays = new GroupMember().setMemberName("user.twoday")
                .setApproved(true).setExpiration(twoDayFromNow);
        group2.getGroupMembers().add(groupMemberTwoDays);
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName1, "group2", group2, "putrole", false);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName2, "test desc", "org", false,
                "", 1235, "", 0), admins, null, auditRef);

        // Create group3 with two members - tourteenday and thirtyfiveday
        Group group3 = createGroupObject(domainName2, "group3", "user.john", "user.jane");
        Timestamp fourteenDayFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(14, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        Timestamp thirtyfiveDayFromNow = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(35, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));
        GroupMember groupMemberFourteenDays = new GroupMember().setMemberName("user.fourteenday")
                .setApproved(true).setExpiration(fourteenDayFromNow);
        GroupMember groupMemberThirtyFiveDays = new GroupMember().setMemberName("user.thirtyfiveday")
                .setApproved(true).setExpiration(thirtyfiveDayFromNow);
        group3.getGroupMembers().add(groupMemberFourteenDays);
        group3.getGroupMembers().add(groupMemberThirtyFiveDays);

        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName2, "group3", group3, "putrole", false);

        Map<String, DomainGroupMember> domainGroupMembers = zms.dbService.getGroupExpiryMembers(0);
        assertNotNull(domainGroupMembers);
        assertEquals(domainGroupMembers.size(), 3);

        DomainGroupMember groupMember = domainGroupMembers.get("user.oneday");
        assertNotNull(groupMember);

        groupMember = domainGroupMembers.get("user.sevenday");
        assertNotNull(groupMember);

        groupMember = domainGroupMembers.get("user.fourteenday");
        assertNotNull(groupMember);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName1, auditRef, "deletedomain");
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName2, auditRef, "deletedomain");
    }

    @Test
    public void testGetRoleExpiryMembersFailure() {

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
        Mockito.when(mockConn.updateRoleMemberExpirationNotificationTimestamp(anyString(), anyLong(), anyInt())).thenReturn(false);

        assertNull(zms.dbService.getRoleExpiryMembers(1));
        zms.dbService.store = saveStore;
    }

    @Test
    public void testListOverdueReviewRoleMembers() {
        final String domainName1 = "test-domain1";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        // Create domain
        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName1, "test desc", "org", false,
                "", 1996, "", 0), admins, null, auditRef);

        long currentTimeMillis = System.currentTimeMillis();
        Timestamp oldTimestamp = Timestamp.fromMillis(currentTimeMillis - 60000);
        Timestamp futureTimestamp = Timestamp.fromMillis(currentTimeMillis + 60000);

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.overduereview1").setReviewReminder(oldTimestamp));
        roleMembers.add(new RoleMember().setMemberName("user.overduereview2").setReviewReminder(oldTimestamp));
        roleMembers.add(new RoleMember().setMemberName("user.futurereview1").setReviewReminder(futureTimestamp));
        roleMembers.add(new RoleMember().setMemberName("user.noreview1"));

        // Create role1 with members
        Role role = createRoleObject(domainName1, "role1", null, roleMembers);
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName1, "role1", role, "test", "putrole", false);

        DomainRoleMembers responseMembers = zms.dbService.listOverdueReviewRoleMembers(domainName1);
        assertEquals("test-domain1", responseMembers.getDomainName());
        List<DomainRoleMember> responseRoleMemberList = responseMembers.getMembers();
        assertEquals(responseRoleMemberList.size(), 2);
        assertEquals(responseRoleMemberList.get(0).getMemberName(), "user.overduereview1");
        assertEquals(responseRoleMemberList.get(1).getMemberName(), "user.overduereview2");

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName1, auditRef, "deletedomain");
    }

    @Test
    public void testGetPrincipalRoles() {
        createMockDomain("domain1");
        createMockDomain("domain2");
        createMockDomain("domain3");

        String principal = "user.johndoe";

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName("user.test2"));
        roleMembers.add(new RoleMember().setMemberName(principal));

        // Create role1 in domain1 with members and principal
        Role role = createRoleObject("domain1", "role1", null, roleMembers);
        zms.dbService.executePutRole(mockDomRsrcCtx, "domain1", "role1", role, "test", "putrole", false);

        // Create role2 in domain1 with members and principal
        role = createRoleObject("domain1", "role2", null, roleMembers);
        zms.dbService.executePutRole(mockDomRsrcCtx, "domain1", "role2", role, "test", "putrole", false);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName("user.test2"));

        // Create role1 in domain2 with members but without the principal
        role = createRoleObject("domain2", "role1", null, roleMembers);
        zms.dbService.executePutRole(mockDomRsrcCtx, "domain2", "role1", role, "test", "putrole", false);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName(principal));

        // Create role1 in domain3 only principal
        role = createRoleObject("domain3", "role1", null, roleMembers);
        zms.dbService.executePutRole(mockDomRsrcCtx, "domain3", "role1", role, "test", "putrole", false);

        DomainRoleMember domainRoleMember = zms.dbService.getPrincipalRoles(principal, null, null);
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
        assertEquals(domainRoleMember.getMemberRoles().size(), 3);

        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole0));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole1));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole2));

        // Get all roles for a specific domain
        domainRoleMember = zms.dbService.getPrincipalRoles(principal, "domain1", null);
        assertEquals(domainRoleMember.getMemberName(), principal);
        assertEquals(domainRoleMember.getMemberRoles().size(), 2);
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole0));
        assertTrue(ZMSTestUtils.verifyDomainRoleMember(domainRoleMember, memberRole1));

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, "domain1", auditRef, "deletedomain");
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, "domain2", auditRef, "deletedomain");
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, "domain3", auditRef, "deletedomain");
    }

    private void createMockDomain(String domainName) {
        TopLevelDomain domain = createTopLevelDomainObject(domainName, "Test " + domainName, "testorg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, domain);
    }

    @Test
    public void testGetRoleReviewMembersFailure() {

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
        Mockito.when(mockConn.updateRoleMemberReviewNotificationTimestamp(anyString(), anyLong(), anyInt())).thenReturn(false);

        assertNull(zms.dbService.getRoleReviewMembers(1));
        zms.dbService.store = saveStore;
    }

    @Test
    public void testGetGroupExpiryMembersFailure() {

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
        Mockito.when(mockConn.updateGroupMemberExpirationNotificationTimestamp(anyString(), anyLong(), anyInt())).thenReturn(false);

        assertNull(zms.dbService.getGroupExpiryMembers(1));
        zms.dbService.store = saveStore;
    }

    private RoleMember createRoleMember (String name, boolean active, Timestamp expiry, boolean approved) {
        return new RoleMember().setMemberName(name).setActive(active).setApproved(approved).setExpiration(expiry);
    }

    @Test
    public void testApplyRoleMembershipChanges() {
        List<RoleMember> incomingMembers = new ArrayList<>(3);
        List<RoleMember> originalMembers = new ArrayList<>(5);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        Timestamp currentExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(4, TimeUnit.DAYS));

        incomingMembers.add(createRoleMember("user.user1", true, thirtyDayExpiry, true)
                .setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(createRoleMember("user.user2", true, thirtyDayExpiry, true)
                .setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(createRoleMember("user.user4", false, thirtyDayExpiry, true)
                .setPrincipalType(Principal.Type.USER.getValue()));

        Role incomingRole = new Role().setName("role1").setRoleMembers(incomingMembers);

        originalMembers.add(createRoleMember("user.user1", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user2", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user3", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user4", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user5", true, currentExpiry, true));

        Role originalRole = new Role().setName("role1").setRoleMembers(originalMembers)
                .setMemberExpiryDays(10).setServiceExpiryDays(10).setGroupExpiryDays(10);

        Role updatedRole = new Role().setName("role1");

        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), originalRole, MemberDueDays.Type.EXPIRY);
        MemberDueDays reminderDueDays = new MemberDueDays(new Domain(), originalRole, MemberDueDays.Type.REMINDER);

        zms.dbService.applyRoleMembershipChanges(updatedRole, originalRole, incomingRole,
                expiryDueDays, reminderDueDays, auditRef);

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

        List<RoleMember> noactionMembers = zms.dbService.applyRoleMembershipChanges(updatedRole, originalRole,
                incomingRole, expiryDueDays, reminderDueDays, auditRef);

        assertEquals(noactionMembers.size(), 2);
        int noActChecked = 0;
        for (RoleMember roleMember : noactionMembers) {
            switch (roleMember.getMemberName()) {
                case "user.user3":
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
    public void testApplyRoleMembershipChangesReviewEnabled() {
        List<RoleMember> incomingMembers = new ArrayList<>(3);
        List<RoleMember> originalMembers = new ArrayList<>(5);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS)
                + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        Timestamp currentExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(4, TimeUnit.DAYS));

        incomingMembers.add(createRoleMember("user.user1", true, thirtyDayExpiry, true)
                .setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(createRoleMember("user.user2", true, thirtyDayExpiry, true)
                .setPrincipalType(Principal.Type.USER.getValue()));

        Role incomingRole = new Role().setName("role1").setRoleMembers(incomingMembers);

        originalMembers.add(createRoleMember("user.user1", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user2", true, currentExpiry, true));
        originalMembers.add(createRoleMember("user.user3", true, currentExpiry, true));

        Role originalRole = new Role().setName("role1").setRoleMembers(originalMembers)
                .setMemberExpiryDays(10).setServiceExpiryDays(10).setGroupExpiryDays(10)
                .setReviewEnabled(true);

        Role updatedRole = new Role().setName("role1");

        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), originalRole, MemberDueDays.Type.EXPIRY);
        MemberDueDays reminderDueDays = new MemberDueDays(new Domain(), originalRole, MemberDueDays.Type.REMINDER);

        zms.dbService.applyRoleMembershipChanges(updatedRole, originalRole, incomingRole,
                expiryDueDays, reminderDueDays, auditRef);

        assertEquals(updatedRole.getRoleMembers().size(), 2);
        List<String> expectedMemberNames = Arrays.asList("user.user1", "user.user2");
        for (RoleMember roleMember : updatedRole.getRoleMembers()) {
            assertFalse(roleMember.getApproved());
            assertEquals(roleMember.getExpiration(), thirtyDayExpiry);
            assertTrue(expectedMemberNames.contains(roleMember.getMemberName()));
            assertEquals(roleMember.getAuditRef(), auditRef);
        }
    }

    private GroupMember createGroupMember (String name, boolean active, Timestamp expiry, boolean approved) {
        return new GroupMember().setMemberName(name).setActive(active).setApproved(approved).setExpiration(expiry);
    }

    @Test
    public void testApplyGroupMembershipChangesReviewEnabled() {
        List<GroupMember> incomingMembers = new ArrayList<>(3);
        List<GroupMember> originalMembers = new ArrayList<>(5);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS)
                + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        Timestamp currentExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(4, TimeUnit.DAYS));

        incomingMembers.add(createGroupMember("user.user1", true, thirtyDayExpiry, true)
                .setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(createGroupMember("user.user2", true, thirtyDayExpiry, true)
                .setPrincipalType(Principal.Type.USER.getValue()));

        Group incomingGroup = new Group().setName("role1").setGroupMembers(incomingMembers);

        originalMembers.add(createGroupMember("user.user1", true, currentExpiry, true));
        originalMembers.add(createGroupMember("user.user2", true, currentExpiry, true));
        originalMembers.add(createGroupMember("user.user3", true, currentExpiry, true));

        Group originalGroup = new Group().setName("role1").setGroupMembers(originalMembers)
                .setMemberExpiryDays(10).setServiceExpiryDays(10).setReviewEnabled(true);

        Group updatedGroup = new Group().setName("role1");
        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), originalGroup);

        zms.dbService.applyGroupMembershipChanges(updatedGroup, originalGroup, incomingGroup,
                expiryDueDays, auditRef);

        assertEquals(updatedGroup.getGroupMembers().size(), 2);
        List<String> expectedMemberNames = Arrays.asList("user.user1", "user.user2");
        for (GroupMember groupMember : updatedGroup.getGroupMembers()) {
            assertFalse(groupMember.getApproved());
            assertEquals(groupMember.getExpiration(), thirtyDayExpiry);
            assertTrue(expectedMemberNames.contains(groupMember.getMemberName()));
            assertEquals(groupMember.getAuditRef(), auditRef);
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
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole", false);

        Role incomingRole = new Role().setName("role1");

        try {
            zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole,
                    null, null, "review test", "putRoleReview", false);
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

        long now = System.currentTimeMillis();
        Timestamp thirtyDayExpiry = Timestamp.fromMillis(now + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS)
                + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        role1.getRoleMembers().add(new RoleMember().setMemberName("user-headless.joe")
                .setApproved(true).setActive(true));
        Timestamp timExpiry = Timestamp.fromMillis(now + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry)
                .setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole", false);

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new RoleMember().setMemberName("user.john").setActive(false)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(new RoleMember().setMemberName("user.jane").setActive(true)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(new RoleMember().setMemberName("user-headless.joe").setActive(true)
                .setPrincipalType(Principal.Type.USER_HEADLESS.getValue()));
        incomingRole.setRoleMembers(incomingMembers);

        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), new Role().setMemberExpiryDays(10),
                MemberDueDays.Type.EXPIRY);
        MemberDueDays reminderDueDays = new MemberDueDays(new Domain(), new Role(), MemberDueDays.Type.REMINDER);

        zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole,
                expiryDueDays, reminderDueDays, "review test", "putRoleReview", true);

        Role resRole = zms.dbService.getRole(domainName, "role1", false, false, false);

        assertEquals(resRole.getRoleMembers().size(), 3);

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
                case "user-headless.joe":
                    // user-headless is processed as service so no changes
                    assertNull(roleMember.getExpiration());
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);
        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutRoleReviewNoAction() {
        final String domainName = "role-review";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole", false);

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingRole.setRoleMembers(incomingMembers);

        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), new Role().setMemberExpiryDays(10), MemberDueDays.Type.EXPIRY);
        MemberDueDays reminderDueDays = new MemberDueDays(new Domain(), new Role(), MemberDueDays.Type.REMINDER);

        zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole,
                expiryDueDays, reminderDueDays, "review test", "putRoleReview", false);

        Role resRole = zms.dbService.getRole(domainName, "role1", false, false, false);

        assertEquals(resRole.getRoleMembers().size(), 3);

        int membersChecked = 0;

        for (RoleMember roleMember : resRole.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.john":
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
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole", false);

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new RoleMember().setMemberName("user.john").setActive(false)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(new RoleMember().setMemberName("user.jane").setActive(true)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingRole.setRoleMembers(incomingMembers);

        Domain resDom = zms.dbService.getDomain(domainName, true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
        Mockito.when(mockConn.getDomain(domainName)).thenReturn(resDom);
        Mockito.when(mockConn.getRole(domainName, "role1")).thenReturn(role1);
        Mockito.when(mockConn.listRoleMembers(domainName, "role1", false)).thenReturn(role1.getRoleMembers());
        Mockito.when(mockConn.deleteRoleMember(domainName, "role1", "user.john", adminUser, auditRef))
                .thenThrow(new ResourceException(ResourceException.NOT_FOUND));

        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), new Role().setMemberExpiryDays(10), MemberDueDays.Type.EXPIRY);
        MemberDueDays reminderDueDays = new MemberDueDays(new Domain(), new Role(), MemberDueDays.Type.REMINDER);

        try {
            zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole,
                    expiryDueDays, reminderDueDays, "review test", "putRoleReview", false);
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
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole", false);

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new RoleMember().setMemberName("user.john").setActive(false)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(new RoleMember().setMemberName("user.jane").setActive(true)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingRole.setRoleMembers(incomingMembers);

        Domain resDom = zms.dbService.getDomain(domainName, true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
        Mockito.when(mockConn.getDomain(domainName)).thenReturn(resDom);
        Mockito.when(mockConn.getRole(domainName, "role1")).thenReturn(role1);
        Mockito.when(mockConn.listRoleMembers(domainName, "role1", false)).thenReturn(role1.getRoleMembers());
        Mockito.when(mockConn.deleteRoleMember(anyString(), anyString(), anyString(), anyString(), anyString())).thenReturn(true);
        Mockito.when(mockConn.insertRoleMember(anyString(), anyString(), any(RoleMember.class), anyString(), anyString()))
                .thenReturn(false);

        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), new Role().setMemberExpiryDays(10), MemberDueDays.Type.EXPIRY);
        MemberDueDays reminderDueDays = new MemberDueDays(new Domain(), new Role(), MemberDueDays.Type.REMINDER);

        try {
            zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole,
                    expiryDueDays, reminderDueDays, "review test", "putRoleReview", false);
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
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Role role1 = createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        role1.getRoleMembers().add(new RoleMember().setMemberName("user.tim").setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutRole(mockDomRsrcCtx, domainName, "role1", role1, "test", "putrole", false);

        Role incomingRole = new Role().setName("role1");
        List<RoleMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new RoleMember().setMemberName("user.john").setActive(false)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(new RoleMember().setMemberName("user.jane").setActive(true)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingRole.setRoleMembers(incomingMembers);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
        Mockito.when(mockConn.getDomain(domainName)).thenThrow(new ResourceException(ResourceException.CONFLICT));

        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), new Role().setMemberExpiryDays(10), MemberDueDays.Type.EXPIRY);
        MemberDueDays reminderDueDays = new MemberDueDays(new Domain(), new Role(), MemberDueDays.Type.REMINDER);

        try {
            zms.dbService.executePutRoleReview(mockDomRsrcCtx, domainName, "role1", incomingRole,
                    expiryDueDays, reminderDueDays, "review test", "putRoleReview", false);
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
    public void testExecutePutGroupReviewRetry() {

        final String domainName = "group-review-retry";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Group group1 = createGroupObject(domainName, "group1", "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        group1.getGroupMembers().add(new GroupMember().setMemberName("user.tim")
                .setExpiration(timExpiry).setApproved(true).setActive(true));
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName, "group1", group1, "putgroup", false);

        Group incomingGroup = new Group().setName("group1");
        List<GroupMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new GroupMember().setMemberName("user.john").setActive(false)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(new GroupMember().setMemberName("user.jane").setActive(true)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingGroup.setGroupMembers(incomingMembers);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
        Mockito.when(mockConn.getDomain(domainName)).thenThrow(new ResourceException(ResourceException.CONFLICT));

        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), new Group().setMemberExpiryDays(10));

        try {
            zms.dbService.executePutGroupReview(mockDomRsrcCtx, domainName, "group1", incomingGroup,
                    expiryDueDays, "review test", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // getDomain gets called to check domain auditEnabled requirement. verification of 2 retries happened

        verify(mockConn, times(2)).getDomain(domainName);

        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = saveRetryCount;

        Group resGroup = zms.dbService.getGroup(domainName, "group1", false, false);

        assertEquals(resGroup.getGroupMembers().size(), 3);

        int membersChecked = 0;

        for (GroupMember groupMember : resGroup.getGroupMembers()) {
            switch (groupMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertNull(groupMember.getExpiration());
                    assertTrue(groupMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(groupMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutGroupReviewDelError() {

        final String domainName = "group-review-del-error";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Group group1 = createGroupObject(domainName, "group1", "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        group1.getGroupMembers().add(new GroupMember().setMemberName("user.tim").setExpiration(timExpiry)
                .setApproved(true).setActive(true));
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName, "group1", group1, "test", false);

        Group incomingGroup = new Group().setName("group1");
        List<GroupMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new GroupMember().setMemberName("user.john").setActive(false)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(new GroupMember().setMemberName("user.jane").setActive(true)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingGroup.setGroupMembers(incomingMembers);

        Domain resDom = zms.dbService.getDomain(domainName, true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
        Mockito.when(mockConn.getDomain(domainName)).thenReturn(resDom);
        Mockito.when(mockConn.getGroup(domainName, "group1")).thenReturn(group1);
        Mockito.when(mockConn.listGroupMembers(domainName, "group1", false)).thenReturn(group1.getGroupMembers());
        Mockito.when(mockConn.deleteRoleMember(domainName, "role1", "user.john", adminUser, auditRef))
                .thenThrow(new ResourceException(ResourceException.NOT_FOUND));

        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), new Group().setMemberExpiryDays(10));

        try {
            zms.dbService.executePutGroupReview(mockDomRsrcCtx, domainName, "group1", incomingGroup,
                    expiryDueDays, "review test", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        zms.dbService.store = saveStore;

        Group resGroup = zms.dbService.getGroup(domainName, "group1", false, false);

        assertEquals(group1.getGroupMembers().size(), 3);

        int membersChecked = 0;

        for (GroupMember groupMember : resGroup.getGroupMembers()) {
            switch (groupMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertNull(groupMember.getExpiration());
                    assertTrue(groupMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(groupMember.getExpiration(), timExpiry);
                    membersChecked += 1;
                    break;
            }
        }
        assertEquals(membersChecked, 3);

        zms.dbService.executeDeleteDomain(mockDomRsrcCtx, domainName, auditRef, "deletedomain");
    }

    @Test
    public void testExecutePutGroupReviewExtendError() {

        final String domainName = "group-review-extend-error";
        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        Timestamp thirtyDayExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(30, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES));

        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName, "test desc", "org", false,
                "", 1234, "", 0), admins, null, auditRef);

        Group group1 = createGroupObject(domainName, "group1", "user.john", "user.jane");
        Timestamp timExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        group1.getGroupMembers().add(new GroupMember().setMemberName("user.tim").setExpiration(timExpiry)
                .setApproved(true).setActive(true));
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName, "group1", group1, "test", false);

        Group incomingGroup = new Group().setName("group1");
        List<GroupMember> incomingMembers = new ArrayList<>();
        incomingMembers.add(new GroupMember().setMemberName("user.john").setActive(false)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingMembers.add(new GroupMember().setMemberName("user.jane").setActive(true)
                .setExpiration(thirtyDayExpiry).setPrincipalType(Principal.Type.USER.getValue()));
        incomingGroup.setGroupMembers(incomingMembers);

        Domain resDom = zms.dbService.getDomain(domainName, true);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);
        Mockito.when(mockConn.getDomain(domainName)).thenReturn(resDom);
        Mockito.when(mockConn.getGroup(domainName, "group1")).thenReturn(group1);
        Mockito.when(mockConn.listGroupMembers(domainName, "group1", false)).thenReturn(group1.getGroupMembers());
        Mockito.when(mockConn.deleteGroupMember(anyString(), anyString(), anyString(), anyString(), anyString())).thenReturn(true);
        Mockito.when(mockConn.insertGroupMember(anyString(), anyString(), any(GroupMember.class), anyString(), anyString()))
                .thenReturn(false);
        MemberDueDays expiryDueDays = new MemberDueDays(new Domain(), new Group().setMemberExpiryDays(10));

        try {
            zms.dbService.executePutGroupReview(mockDomRsrcCtx, domainName, "group1", incomingGroup,
                    expiryDueDays, "review test", false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
        zms.dbService.store = saveStore;

        Group resGroup = zms.dbService.getGroup(domainName, "group1", false, false);

        assertEquals(group1.getGroupMembers().size(), 3);

        int membersChecked = 0;

        for (GroupMember groupMember : resGroup.getGroupMembers()) {
            switch (groupMember.getMemberName()) {
                case "user.john":
                case "user.jane":
                    assertNull(groupMember.getExpiration());
                    assertTrue(groupMember.getApproved());
                    membersChecked += 1;
                    break;
                case "user.tim":
                    assertEquals(groupMember.getExpiration(), timExpiry);
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
        Mockito.when(mockJdbcConn.getAthenzDomain(domainName)).thenReturn(athenzDomain);

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
        Mockito.when(mockJdbcConn.getAthenzDomain(domainName)).thenReturn(athenzDomain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        AthenzDomain resAthenzDomain = zms.dbService.getAthenzDomain(domainName, false);
        assertNotNull(resAthenzDomain.getRoles());
        List<RoleMember> roleMembersResult = resAthenzDomain.getRoles().get(0).getRoleMembers();
        assertEquals(roleMembersResult.size(), 1);
        assertEquals(roleMembersResult.get(0).getMemberName(), "user.admin");

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePendingMemberFailureRetry() {

        final String domainName = "pendingdeletembrretry";
        final String roleName = "role1";
        final String memberName = "user.member1";
        final String adminName = "user.user1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deletePendingRoleMember(domainName, roleName, memberName, adminName, auditRef))
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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteRoleMember(domainName, roleName, memberName, adminName, auditRef))
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
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteRoleMember(domainName, roleName, memberName, adminName, auditRef))
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

    @Test
    public void testIsUserAuthorityValueChanged() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        // with authority null - always false

        zms.dbService.zmsConfig.setUserAuthority(null);
        assertFalse(zms.dbService.isUserAuthorityExpiryChanged("filter1", "filter2"));

        Authority authority = Mockito.mock(Authority.class);
        zms.dbService.zmsConfig.setUserAuthority(authority);

        assertFalse(zms.dbService.isUserAuthorityExpiryChanged("old", null));
        assertFalse(zms.dbService.isUserAuthorityExpiryChanged(null, null));
        assertFalse(zms.dbService.isUserAuthorityExpiryChanged("", null));
        assertFalse(zms.dbService.isUserAuthorityExpiryChanged("", ""));
        assertFalse(zms.dbService.isUserAuthorityExpiryChanged("old", "old"));

        assertFalse(zms.dbService.isUserAuthorityExpiryChanged("old", ""));
        assertFalse(zms.dbService.isUserAuthorityExpiryChanged(null, ""));

        assertTrue(zms.dbService.isUserAuthorityExpiryChanged("old", "new"));
        assertTrue(zms.dbService.isUserAuthorityExpiryChanged(null, "new"));
        assertTrue(zms.dbService.isUserAuthorityExpiryChanged("", "new"));

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testUpdateUserAuthorityExpiryRoleMember() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Date currentDate = new Date();
        Timestamp authorityDate = Timestamp.fromDate(currentDate);

        Mockito.when(authority.getDateAttribute("user.john", "elevated-clearance"))
                .thenReturn(currentDate);
        Mockito.when(authority.getDateAttribute("user.jane", "elevated-clearance"))
                .thenReturn(currentDate);
        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        // if not a user then it's always false

        RoleMember roleMember = new RoleMember().setMemberName("coretech.api");
        assertFalse(zms.dbService.updateUserAuthorityExpiry(roleMember, "elevated-clearance"));

        // user.joe - no expiry setting

        roleMember = new RoleMember().setMemberName("user.joe");
        assertTrue(zms.dbService.updateUserAuthorityExpiry(roleMember, "elevated-clearance"));
        assertNotNull(roleMember.getExpiration());

        // we'll change if the expiry date is in the future

        Timestamp expiryDate = Timestamp.fromMillis(System.currentTimeMillis() + 1000000);
        roleMember.setExpiration(expiryDate);
        assertTrue(zms.dbService.updateUserAuthorityExpiry(roleMember, "elevated-clearance"));
        assertNotEquals(roleMember.getExpiration(), expiryDate);

        // we will not change if the entry is already expired

        expiryDate = Timestamp.fromMillis(System.currentTimeMillis() - 1000000);
        roleMember.setExpiration(expiryDate);
        assertFalse(zms.dbService.updateUserAuthorityExpiry(roleMember, "elevated-clearance"));
        assertEquals(roleMember.getExpiration(), expiryDate);

        // now let's test a user with valid authority expiry date
        // if the user doesn't have an expiry, we'll default to the value
        // returned by the user authority

        roleMember = new RoleMember().setMemberName("user.jane");
        assertTrue(zms.dbService.updateUserAuthorityExpiry(roleMember, "elevated-clearance"));
        assertNotNull(roleMember.getExpiration());
        assertEquals(roleMember.getExpiration(), authorityDate);

        // if the value matches to our user authority value then no change

        roleMember.setExpiration(authorityDate);
        assertFalse(zms.dbService.updateUserAuthorityExpiry(roleMember, "elevated-clearance"));
        assertNotNull(roleMember.getExpiration());
        assertEquals(roleMember.getExpiration(), authorityDate);

        // if no match then we change the value

        roleMember.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 2000000));
        assertTrue(zms.dbService.updateUserAuthorityExpiry(roleMember, "elevated-clearance"));
        assertNotNull(roleMember.getExpiration());
        assertEquals(roleMember.getExpiration(), authorityDate);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testUpdateRoleMembersSystemDisabledState() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.isAttributeSet("user.john", "employee")).thenReturn(true);
        Mockito.when(authority.isAttributeSet("user.jane", "employee")).thenReturn(false);
        Mockito.when(authority.isAttributeSet("user.joe", "employee")).thenReturn(true);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.updateRoleMemberDisabledState(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyInt(), Mockito.anyString())).thenReturn(true);

        final String domainName = "user-auth-attrs";
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.john"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        roleMembers.add(new RoleMember().setMemberName("sports.api"));
        Timestamp tstamp = Timestamp.fromMillis(System.currentTimeMillis() - 10000);
        roleMembers.add(new RoleMember().setMemberName("weather.api").setExpiration(tstamp));

        Role originalRole = new Role()
                .setName(domainName + ":role.auth-role")
                .setRoleMembers(roleMembers);

        Role updatedRole = new Role().setName(domainName + ":role.auth-role")
                .setUserAuthorityFilter("employee")
                .setRoleMembers(roleMembers);

        zms.dbService.updateRoleMembersSystemDisabledState(mockDomRsrcCtx, mockConn, domainName,
                "auth-role", originalRole, updatedRole, auditRef, "unit-test");

        // john should not have an expiry while jane should have the disabled state
        // since jane no longer has the user attribute set

        RoleMember member = getRoleMember(updatedRole, "user.john");
        assertNull(member.getExpiration());
        assertNull(member.getSystemDisabled());

        member = getRoleMember(updatedRole, "user.jane");
        assertNull(member.getExpiration());
        assertEquals(member.getSystemDisabled(), Integer.valueOf(ZMSConsts.ZMS_DISABLED_AUTHORITY_FILTER));

        // sports api should not be disabled set since it's not a user

        member = getRoleMember(updatedRole, "sports.api");
        assertNull(member.getExpiration());
        assertNull(member.getSystemDisabled());

        // weather api expiry should not change since it's already expired

        member = getRoleMember(updatedRole, "weather.api");
        assertEquals(member.getExpiration(), tstamp);
        assertNull(member.getSystemDisabled());

        // now let's reset the state back to null which should
        // remove the filter disabled flag

        originalRole.setUserAuthorityFilter("employee");
        updatedRole.setUserAuthorityFilter(null);
        zms.dbService.updateRoleMembersSystemDisabledState(mockDomRsrcCtx, mockConn, domainName,
                "auth-role", originalRole, updatedRole, auditRef, "unit-test");

        member = getRoleMember(updatedRole, "user.john");
        assertNull(member.getExpiration());
        assertNull(member.getSystemDisabled());

        member = getRoleMember(updatedRole, "user.jane");
        assertNull(member.getExpiration());
        assertEquals(member.getSystemDisabled(), Integer.valueOf(0));

        member = getRoleMember(updatedRole, "sports.api");
        assertNull(member.getExpiration());
        assertNull(member.getSystemDisabled());

        member = getRoleMember(updatedRole, "weather.api");
        assertEquals(member.getExpiration(), tstamp);
        assertNull(member.getSystemDisabled());

        // reset authority to its original value

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testUpdateRoleMembersSystemDisabledStateTrustRole() {

        // we're going to throw an exception here since this should never be called

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.updateRoleMemberDisabledState(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyInt(), Mockito.anyString()))
                .thenThrow(new ResourceException(400, "Invalid request"));

        final String domainName = "user-auth-attrs";
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        Role originalRole = new Role().setTrust("trust-domain");

        // passing null for updated role - not used since original is a trust role

        zms.dbService.updateRoleMembersSystemDisabledState(mockDomRsrcCtx, mockConn, domainName,
                "auth-role", originalRole, null, auditRef, "unit-test");
    }

    @Test
    public void testUpdateRoleMembersSystemDisabledStateDBFailure() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.isAttributeSet("user.john", "employee")).thenReturn(true);
        Mockito.when(authority.isAttributeSet("user.jane", "employee")).thenReturn(false);
        Mockito.when(authority.isAttributeSet("user.joe", "employee")).thenReturn(true);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        // we're going to fail all the updates in the DB but this should
        // not cause any issues as we'll process them in next run

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.updateRoleMemberDisabledState(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyInt(), Mockito.anyString())).thenReturn(false);

        final String domainName = "user-auth-attrs";

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.john"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        roleMembers.add(new RoleMember().setMemberName("sports.api"));
        Timestamp tstamp = Timestamp.fromMillis(System.currentTimeMillis() - 10000);
        roleMembers.add(new RoleMember().setMemberName("weather.api").setExpiration(tstamp));

        Role originalRole = new Role()
                .setName(domainName + ":role.auth-role")
                .setRoleMembers(roleMembers);

        Role updatedRole = new Role().setName(domainName + ":role.auth-role")
                .setUserAuthorityFilter("employee")
                .setRoleMembers(roleMembers);

        zms.dbService.updateRoleMembersSystemDisabledState(mockDomRsrcCtx, mockConn, domainName,
                "auth-role", originalRole, updatedRole, auditRef, "unit-test");

        // reset authority to its original value

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testUpdateRoleMembersDueDatesUserAuthorityExpiry() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Date currentDate = new Date();
        Timestamp currentStamp = Timestamp.fromDate(currentDate);

        Mockito.when(authority.getDateAttribute("user.john", "elevated-clearance"))
                .thenReturn(currentDate);
        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);

        // we're going to make sure to throw an exception here
        // since this should never be called

        final String domainName = "user-auth-expiry";
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.john"));
        roleMembers.add(new RoleMember().setMemberName("sports.api"));
        Timestamp tstamp = Timestamp.fromMillis(System.currentTimeMillis() - 10000);
        roleMembers.add(new RoleMember().setMemberName("weather.api").setExpiration(tstamp));

        Role originalRole = new Role()
                .setName(domainName + ":role.auth-role")
                .setRoleMembers(roleMembers);

        Role updatedRole = new Role().setName(domainName + ":role.auth-role")
                .setUserAuthorityExpiration("elevated-clearance")
                .setRoleMembers(roleMembers);

        zms.dbService.updateRoleMembersDueDates(mockDomRsrcCtx, mockConn, domainName,
                "auth-role", originalRole, updatedRole, auditRef, "unit-test");

        // john should have an expiry matching our current timestamp

        RoleMember member = getRoleMember(updatedRole, "user.john");
        assertEquals(member.getExpiration(), currentStamp);

        // sports api should not have an expiry since it's not a user

        member = getRoleMember(updatedRole, "sports.api");
        assertNull(member.getExpiration());

        // weather api should not change since it's already expired

        member = getRoleMember(updatedRole, "weather.api");
        assertEquals(member.getExpiration(), tstamp);

        // reset authority to its original value

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    RoleMember getRoleMember(Role role, final String memberName) {
        List<RoleMember> members = role.getRoleMembers();
        if (members == null) {
            return null;
        }
        for (RoleMember member : members) {
            if (member.getMemberName().equalsIgnoreCase(memberName)) {
                return member;
            }
        }
        return null;
    }

    @Test
    public void testEnforceRoleUserAuthorityRestrictionsEmptyRoles() {

        // we're making sure we're going to return exception when there
        // are changes thus insert records

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString()))
                .thenThrow(new ResourceException(400, "invalid operation"));

        final String domainName = "authority-test";
        final String roleName = "auth-role";

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null role and then a role
        // with no members - in both cases we return without processing
        // any code

        Role role = new Role().setTrust("trust");
        Mockito.when(mockConn.getRole(domainName, roleName))
                .thenReturn(null)
                .thenReturn(role);

        Mockito.when(mockConn.updateDomain(any()))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // calling the enforce twice - first time we should get null role
        // and second time role with no members

        zms.dbService.enforceRoleUserAuthorityRestrictions(domainName, roleName, null);
        zms.dbService.enforceRoleUserAuthorityRestrictions(domainName, roleName, null);

        zms.dbService.store = savedStore;
    }

    @Test
    public void testEnforceRoleUserAuthorityExpiryRestrictionsUpdate() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String roleName = "auth-role";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null role and then a role
        // with no members - in both cases we return without processing
        // any code

        Role role = new Role().setUserAuthorityExpiration("elevated-clearance");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));

        Mockito.when(mockConn.getRole(domainName, roleName)).thenReturn(role);
        Mockito.when(mockConn.listRoleMembers(domainName, roleName, false))
                .thenReturn(roleMembers);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully

        zms.dbService.enforceRoleUserAuthorityRestrictions(domainName, roleName, null);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testEnforceRoleUserAuthorityFilterRestrictionsUpdate() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.isAttributeSet("user.joe", "employee"))
                .thenReturn(false);
        Mockito.when(authority.isAttributeSet("user.jane", "employee"))
                .thenReturn(true);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String roleName = "auth-role";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null role and then a role
        // with no members - in both cases we return without processing
        // any code

        Role role = new Role().setUserAuthorityFilter("employee");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));

        Mockito.when(mockConn.getRole(domainName, roleName)).thenReturn(role);
        Mockito.when(mockConn.listRoleMembers(domainName, roleName, false))
                .thenReturn(roleMembers);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully

        zms.dbService.enforceRoleUserAuthorityRestrictions(domainName, roleName, null);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testEnforceRoleUserAuthorityRestrictionsNoUpdate() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String roleName = "auth-role";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null role and then a role
        // with no members - in both cases we return without processing
        // any code

        Role role = new Role().setUserAuthorityExpiration("elevated-clearance");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 10000)));

        Mockito.when(mockConn.getRole(domainName, roleName)).thenReturn(role);
        Mockito.when(mockConn.listRoleMembers(domainName, roleName, false))
                .thenReturn(roleMembers);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully

        zms.dbService.enforceRoleUserAuthorityRestrictions(domainName, roleName, null);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessRoleUserAuthorityRestrictions() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String roleName = "auth-role";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null role and then a role
        // with no members - in both cases we return without processing
        // any code

        Role role = new Role().setUserAuthorityExpiration("elevated-clearance");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));

        Mockito.when(mockConn.getRole(domainName, roleName)).thenReturn(role);
        Mockito.when(mockConn.listRoleMembers(domainName, roleName, false))
                .thenReturn(roleMembers);

        // first we're going to return no roles and then list of roles
        // in the second one

        List<PrincipalRole> roles = new ArrayList<>();
        PrincipalRole prRole = new PrincipalRole();
        prRole.setDomainName(domainName);
        prRole.setRoleName(roleName);
        roles.add(prRole);

        Mockito.when(mockConn.listRolesWithUserAuthorityRestrictions())
                .thenReturn(null)
                .thenReturn(roles);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully
        // first time we'll get no roles so no work is done
        // second time we'll get a single role that we'll process

        zms.dbService.processRoleUserAuthorityRestrictions();
        zms.dbService.processRoleUserAuthorityRestrictions();

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessRoleUserAuthorityRestrictionsExceptions() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String roleName1 = "auth-role1";
        final String roleName2 = "auth-role2";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertRoleMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        // we're going to return an exception for the first insert role member
        // and then success for the second one

        Mockito.reset(mockObjStore);
        Mockito.when(mockObjStore.getConnection(true, true))
                .thenThrow(new ResourceException(500, "DB Error"))
                .thenReturn(mockConn);
        Mockito.when(mockObjStore.getConnection(true, false)).thenReturn(mockConn);

        // first we're going to return a null role and then a role
        // with no members - in both cases we return without processing
        // any code

        Role role1 = new Role().setUserAuthorityExpiration("elevated-clearance");
        List<RoleMember> roleMembers1 = new ArrayList<>();
        roleMembers1.add(new RoleMember().setMemberName("user.joe"));

        Mockito.when(mockConn.getRole(domainName, roleName1)).thenReturn(role1);
        Mockito.when(mockConn.listRoleMembers(domainName, roleName1, false))
                .thenReturn(roleMembers1);

        Role role2 = new Role().setUserAuthorityExpiration("elevated-clearance");
        List<RoleMember> roleMembers2 = new ArrayList<>();
        roleMembers2.add(new RoleMember().setMemberName("user.joe"));

        Mockito.when(mockConn.getRole(domainName, roleName2)).thenReturn(role2);
        Mockito.when(mockConn.listRoleMembers(domainName, roleName2, false))
                .thenReturn(roleMembers2);

        List<PrincipalRole> roles = new ArrayList<>();
        PrincipalRole prRole1 = new PrincipalRole();
        prRole1.setDomainName(domainName);
        prRole1.setRoleName(roleName1);
        roles.add(prRole1);
        PrincipalRole prRole2 = new PrincipalRole();
        prRole2.setDomainName(domainName);
        prRole2.setRoleName(roleName2);
        roles.add(prRole2);

        Mockito.when(mockConn.listRolesWithUserAuthorityRestrictions())
                .thenReturn(roles);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully
        // for the first role we'll get an exception but we'll just log
        // for the second role we'll get success

        zms.dbService.processRoleUserAuthorityRestrictions();

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testUserAuthorityFilterEnforcerException() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();
        Authority authority = Mockito.mock(Authority.class);
        zms.dbService.zmsConfig.setUserAuthority(authority);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
                .thenThrow(new ResourceException(400, "invalid request"));

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        DBService.UserAuthorityFilterEnforcer enforcer = zms.dbService.new UserAuthorityFilterEnforcer();

        // make sure no exceptions are thrown from the run call even if
        // processing call throws an exceptions

        enforcer.run();

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testAutoApplySolutionTemplate() {

        String caller = "testAutoApplySolutionTemplate";
        String domainName = "solutiontemplate-autoapply";
        Map<String, Integer> templateVersionMapping = new HashMap<>();
        templateVersionMapping.put("templateWithService", 11);
        templateVersionMapping.put("user_provisioning", 12);
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "domain-autoapply-test", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        List<String> templates = new ArrayList<>();
        templates.add("templateWithService");
        templates.add("user_provisioning");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        Map<String, List<String>> domainTemplateUpdateMapping = zms.dbService.applyTemplatesForListOfDomains(templateVersionMapping);
        assertEquals(domainTemplateUpdateMapping.size(), 1);
        for (String domain : domainTemplateUpdateMapping.keySet()) {
            assertEquals(templates , domainTemplateUpdateMapping.get(domain));
        }

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testApplySolutionTemplateWithRoleMetaData() {

        String domainName = "solutiontemplate-rolemeta";
        String caller = "testApplySolutionTemplateWithRoleMetaData";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        // apply the template

        List<String> templates = new ArrayList<>();
        templates.add("templateWithRoleMeta");
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
        assertTrue(role.getRoleMembers().isEmpty());
        assertNotNull(role.getNotifyRoles());
        assertNull(role.getSelfServe());
        assertEquals(role.getMemberExpiryDays().intValue(), 90);
        assertEquals(role.getTokenExpiryMins().intValue(), 30);
        assertEquals(role.getCertExpiryMins().intValue(), 10);
        assertEquals(role.getSignAlgorithm(), "test");
        assertEquals(role.getServiceExpiryDays().intValue(), 50);
        assertEquals(role.getMemberReviewDays().intValue(), 65);
        assertEquals(role.getServiceReviewDays().intValue(), 15);
        assertEquals(role.getGroupExpiryDays().intValue(), 70);
        assertEquals(role.getGroupReviewDays().intValue(), 80);
        assertTrue(role.getReviewEnabled());
        assertEquals(role.getNotifyRoles(), "testnotify-role");
        assertEquals(role.getUserAuthorityFilter(), "none");
        assertEquals(role.getDescription(), "testroledescription");
        assertNull(role.getUserAuthorityExpiration());

        // verify that our policy collections includes the policies defined in the template

        names = zms.dbService.listPolicies(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));

        // Try applying the template again. This time, there should be no changes.

        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        names = zms.dbService.listPolicies(domainName);
        assertEquals(2, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));

        // remove the templateWithRoleMeta template

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "templateWithRoleMeta",
                auditRef, caller);

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        // remove templateWithRoleMeta again to ensure same result

        zms.dbService.executeDeleteDomainTemplate(mockDomRsrcCtx, domainName, "templateWithRoleMeta",
                auditRef, caller);

        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testApplySolutionTemplateOnExistingRoleWithRoleMetaData() {
        String domainName = "solutiontemplate-existing-rolemeta";
        String caller = "testApplySolutionTemplateOnExistingRoleWithRoleMetaData";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        // apply the template

        List<String> templates = new ArrayList<>();
        templates.add("templateWithRoleMeta");
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

        //For the same role apply new role meta values to test whether it is overriding existing values.
        templates = new ArrayList<>();
        templates.add("templateWithExistingRoleMeta");
        domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);
        role = zms.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        //selfserve is overwritten so expect true
        assertTrue(role.getSelfServe()); //assert for updated Value
        assertEquals(role.getMemberExpiryDays().intValue(), 999); //Overwritten value. assert for updated Value
        assertEquals(role.getUserAuthorityExpiration(), "newValue"); //Overwritten value. assert for updated Value
        assertEquals(role.getTokenExpiryMins().intValue(), 30); //Existing Value
        assertEquals(role.getCertExpiryMins().intValue(), 10); //Existing Value
        assertEquals(role.getSignAlgorithm(), "test"); //Existing Value
        assertEquals(role.getServiceExpiryDays().intValue(), 50); //Existing Value
        assertEquals(role.getMemberReviewDays().intValue(), 65); //Existing Value
        assertEquals(role.getServiceReviewDays().intValue(), 15); //Existing Value
        assertEquals(role.getGroupExpiryDays().intValue(), 70); //Existing Value
        assertEquals(role.getGroupReviewDays().intValue(), 80); //Existing Value
        assertTrue(role.getReviewEnabled()); //Existing Value
        assertEquals(role.getNotifyRoles(), "testnotify-role"); //Existing Value
        assertEquals(role.getUserAuthorityFilter(), "none"); //Existing Value
        assertEquals(role.getDescription(), "testroledescription"); //Existing Value

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testUpdateUserAuthorityFilter() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.isAttributeSet("user.john", "employee")).thenReturn(true);
        Mockito.when(authority.isAttributeSet("user.jane", "employee")).thenReturn(false);
        Mockito.when(authority.isAttributeSet("user.joe", "employee")).thenReturn(true);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        RoleMember roleMemberJohn = new RoleMember().setMemberName("user.john").setSystemDisabled(null);
        assertFalse(zms.dbService.updateUserAuthorityFilter(roleMemberJohn, "employee"));

        roleMemberJohn.setSystemDisabled(0);
        assertFalse(zms.dbService.updateUserAuthorityFilter(roleMemberJohn, "employee"));

        roleMemberJohn.setSystemDisabled(1);
        assertTrue(zms.dbService.updateUserAuthorityFilter(roleMemberJohn, "employee"));
        assertEquals(roleMemberJohn.getSystemDisabled(), Integer.valueOf(0));

        RoleMember roleMemberJane = new RoleMember().setMemberName("user.jane").setSystemDisabled(null);
        assertTrue(zms.dbService.updateUserAuthorityFilter(roleMemberJane, "employee"));
        assertEquals(roleMemberJane.getSystemDisabled(), Integer.valueOf(1));

        assertFalse(zms.dbService.updateUserAuthorityFilter(roleMemberJane, "employee"));
        assertEquals(roleMemberJane.getSystemDisabled(), Integer.valueOf(1));

        // reset authority to its original value

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testIsUserAuthorityFilterChanged() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        // with authority null - always false

        zms.dbService.zmsConfig.setUserAuthority(null);
        assertFalse(zms.dbService.isUserAuthorityFilterChanged("filter1", "filter2"));

        Authority authority = Mockito.mock(Authority.class);
        zms.dbService.zmsConfig.setUserAuthority(authority);

        assertFalse(zms.dbService.isUserAuthorityFilterChanged(null, null));
        assertFalse(zms.dbService.isUserAuthorityFilterChanged("", null));
        assertFalse(zms.dbService.isUserAuthorityFilterChanged(null, ""));
        assertFalse(zms.dbService.isUserAuthorityFilterChanged("", ""));

        assertTrue(zms.dbService.isUserAuthorityFilterChanged("old", null));
        assertTrue(zms.dbService.isUserAuthorityFilterChanged("old", ""));

        assertTrue(zms.dbService.isUserAuthorityFilterChanged(null, "new"));
        assertTrue(zms.dbService.isUserAuthorityFilterChanged("", "new"));

        assertTrue(zms.dbService.isUserAuthorityFilterChanged("old", "new"));
        assertFalse(zms.dbService.isUserAuthorityFilterChanged("old", "old"));

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testUpdateRoleMemberDisabledState() {

        final String domainName = "test-domain";
        final String roleName = "role-name";
        final String adminUser = "user.admin";

        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.updateRoleMemberDisabledState(domainName, roleName, "user.john", "user.admin", 1, "auditref"))
                .thenReturn(true)
                .thenReturn(false)
                .thenThrow(new ResourceException(500, "invalid operation"));

        RoleMember roleMember = new RoleMember().setMemberName("user.john").setSystemDisabled(1);
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(roleMember);

        // first time we get successful response

        assertTrue(zms.dbService.updateRoleMemberDisabledState(null, con, roleMembers, domainName,
                roleName, adminUser, "auditref", "unit-test"));

        // second time we're getting false so no changes

        assertFalse(zms.dbService.updateRoleMemberDisabledState(null, con, roleMembers, domainName,
                roleName, adminUser, "auditref", "unit-test"));

        // last time exception so no changes

        assertFalse(zms.dbService.updateRoleMemberDisabledState(null, con, roleMembers, domainName,
                roleName, adminUser, "auditref", "unit-test"));
    }

    @Test
    public void testGetRolesByDomain() {
        ObjectStore saveStore = zms.dbService.store;
        AthenzDomain athenzDomain = new AthenzDomain("test1");
        Domain domain = new Domain().setName("test1").setMemberExpiryDays(100).setModified(Timestamp.fromCurrentTime());
        athenzDomain.setDomain(domain);
        Role testRole = new Role();
        testRole.setName("admin");
        List<Role> roles = new ArrayList<>();
        roles.add(testRole);
        athenzDomain.setRoles(roles);

        Mockito.when(mockJdbcConn.getDomain(eq("test1"))).thenReturn(domain);
        Mockito.when(mockJdbcConn.getAthenzDomain(eq("test1"))).thenReturn(athenzDomain);

        zms.dbService.store = mockObjStore;

        List<Role> rolesFetched = zms.dbService.getRolesByDomain("test1");
        assertEquals(1, rolesFetched.size());
        assertEquals("admin", rolesFetched.get(0).getName());
        zms.dbService.store = saveStore;
    }

    @Test
    public void testGetRolesByDomainUnknown() {

        try {
            zms.dbService.getRolesByDomain("unknownDomain");
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testGetDomainUserAuthorityFilter() {

        String domainName = "getdomain-user-authority-filter";

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();
        Authority authority = Mockito.mock(Authority.class);
        zms.dbService.zmsConfig.setUserAuthority(authority);

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);

        Domain domain = ZMSTestUtils.makeDomainObject(domainName, "test desc", "testOrg",
                false, "", 1234, "", 0);
        domain.setUserAuthorityFilter("employee");
        zms.dbService.makeDomain(mockDomRsrcCtx, domain, admins, null, auditRef);

        ObjectStoreConnection conn = zms.dbService.store.getConnection(true, false);
        assertEquals("employee", zms.dbService.getDomainUserAuthorityFilter(conn, domainName));

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testProcessGroupFailure() {

        final String domainName = "failure-group-domain";

        // group object without the domain part

        Group group1 = new Group().setName("group1");
        StringBuilder auditDetails = new StringBuilder("testAudit");
        try {
            zms.dbService.processGroup(zms.dbService.store.getConnection(true, true), null, domainName,
                    "group1", group1, adminUser, auditRef, auditDetails);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        // mock returning failure

        group1 = new Group().setName(domainName + ":group.group1");

        Mockito.when(mockJdbcConn.insertGroup(anyString(), any(Group.class)))
                .thenReturn(false);

        assertFalse(zms.dbService.processGroup(mockJdbcConn, null, domainName,
                "group1", group1, adminUser, auditRef, auditDetails));

        Mockito.when(mockJdbcConn.insertGroup(anyString(), any(Group.class)))
                .thenReturn(true);
        Mockito.when(mockJdbcConn.insertGroupMember(anyString(), anyString(), any(GroupMember.class),
                anyString(), anyString())).thenReturn(false);

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user1"));
        group1.setGroupMembers(groupMembers);
        assertFalse(zms.dbService.processGroup(mockJdbcConn, null, domainName,
                "group1", group1, adminUser, auditRef, auditDetails));
    }

    @Test
    public void testProcessGroupMemberFailure() {

        final String domainName = "failure-group-mbr-domain";
        final String groupName = "group1";

        // mock returning failure

        Group groupOriginal = createGroupObject(domainName, groupName, "user.user1", "user.user2");
        Group groupUpdated = createGroupObject(domainName, groupName, "user.user2", "user.user3");

        Mockito.when(mockJdbcConn.updateGroup(anyString(), any(Group.class)))
                .thenReturn(true);

        // first any update delete is marked as failure

        StringBuilder auditDetails = new StringBuilder("testAudit");
        Mockito.when(mockJdbcConn.deleteGroupMember(anyString(), anyString(), anyString(),
                anyString(), anyString())).thenReturn(false);

        assertFalse(zms.dbService.processGroup(mockJdbcConn, groupOriginal, domainName,
                groupName, groupUpdated, adminUser, auditRef, auditDetails));

        // now we're going to allow deletes to work but inserts fail

        Mockito.when(mockJdbcConn.deleteGroupMember(anyString(), anyString(), anyString(),
                anyString(), anyString())).thenReturn(true);
        Mockito.when(mockJdbcConn.insertGroupMember(anyString(), anyString(), any(GroupMember.class),
                anyString(), anyString())).thenReturn(false);

        Mockito.when(mockJdbcConn.insertGroup(anyString(), any(Group.class)))
                .thenReturn(true);

        assertFalse(zms.dbService.processGroup(mockJdbcConn, groupOriginal, domainName,
                groupName, groupUpdated, adminUser, auditRef, auditDetails));
    }

    @Test
    public void testExecutePutGroupFailure() {

        final String domainName = "put-group-failure";
        final String groupName = "group1";

        Group group = createGroupObject(domainName, groupName, "user.user2", "user.user3");

        Mockito.when(mockJdbcConn.insertGroup(anyString(), any(Group.class)))
                .thenReturn(false);
        Domain domain = new Domain().setName(domainName);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutGroup(mockDomRsrcCtx, domainName, groupName, group, auditRef, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutGroupMemberFailure() {

        final String domainName = "failure-put-group-mbr-domain";
        final String groupName = "group1";
        final String memberName = "user.member1";
        final String adminName = "user.user1";

        GroupMember groupMember = new GroupMember().setMemberName(memberName);
        Group group = new Group().setName(ResourceUtils.groupResourceName(domainName, groupName));

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.insertGroupMember(domainName, groupName, groupMember, adminName, auditRef))
                .thenReturn(false);
        GroupMembership groupMembership = new GroupMembership().setMemberName(memberName).setIsMember(false);
        Mockito.when(mockJdbcConn.getGroupMember(domainName, groupName, memberName, 0, false)).thenReturn(groupMembership);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executePutGroupMembership(mockDomRsrcCtx, domainName, group, groupMember, auditRef, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.BAD_REQUEST, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteGroupMemberFailureNotFound() {

        final String domainName = "failure-del-group-mbr-domain";
        final String groupName = "group1";
        final String memberName = "user.member1";
        final String adminName = "user.user1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteGroupMember(domainName, groupName, memberName, adminName, auditRef))
                .thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeleteGroupMembership(mockDomRsrcCtx, domainName, groupName,
                    memberName, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeletePendingGroupMemberFailureNotFound() {

        final String domainName = "failure-del-pending-group-mbr-domain";
        final String groupName = "group1";
        final String memberName = "user.member1";
        final String adminName = "user.user1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deletePendingGroupMember(domainName, groupName, memberName, adminName, auditRef))
                .thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeletePendingGroupMembership(mockDomRsrcCtx, domainName, groupName,
                    memberName, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecuteDeleteGroupFailure() {

        final String domainName = "failure-del-groupdomain";
        final String groupName = "group1";

        Domain domain = new Domain().setAuditEnabled(false);
        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(domain);
        Mockito.when(mockJdbcConn.deleteGroup(domainName, groupName)).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        try {
            zms.dbService.executeDeleteGroup(mockDomRsrcCtx, domainName, groupName, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testUpdateUserAuthorityExpiryGroupMember() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Date currentDate = new Date();
        Timestamp authorityDate = Timestamp.fromDate(currentDate);

        Mockito.when(authority.getDateAttribute("user.john", "elevated-clearance"))
                .thenReturn(currentDate);
        Mockito.when(authority.getDateAttribute("user.jane", "elevated-clearance"))
                .thenReturn(currentDate);
        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        // service users are not processed

        GroupMember groupMember = new GroupMember().setMemberName("sports.api");
        assertFalse(zms.dbService.updateUserAuthorityExpiry(groupMember, "elevated-clearance"));

        // user.joe - no expiry setting

        groupMember = new GroupMember().setMemberName("user.joe");
        assertTrue(zms.dbService.updateUserAuthorityExpiry(groupMember, "elevated-clearance"));
        assertNotNull(groupMember.getExpiration());

        // we'll change if the expiry date is in the future

        Timestamp expiryDate = Timestamp.fromMillis(System.currentTimeMillis() + 1000000);
        groupMember.setExpiration(expiryDate);
        assertTrue(zms.dbService.updateUserAuthorityExpiry(groupMember, "elevated-clearance"));
        assertNotEquals(groupMember.getExpiration(), expiryDate);

        // we will not change if the entry is already expired

        expiryDate = Timestamp.fromMillis(System.currentTimeMillis() - 1000000);
        groupMember.setExpiration(expiryDate);
        assertFalse(zms.dbService.updateUserAuthorityExpiry(groupMember, "elevated-clearance"));
        assertEquals(groupMember.getExpiration(), expiryDate);

        // now let's test a user with valid authority expiry date
        // if the user doesn't have an expiry, we'll default to the value
        // returned by the user authority

        groupMember = new GroupMember().setMemberName("user.jane");
        assertTrue(zms.dbService.updateUserAuthorityExpiry(groupMember, "elevated-clearance"));
        assertNotNull(groupMember.getExpiration());
        assertEquals(groupMember.getExpiration(), authorityDate);

        // if the value matches to our user authority value then no change

        groupMember.setExpiration(authorityDate);
        assertFalse(zms.dbService.updateUserAuthorityExpiry(groupMember, "elevated-clearance"));
        assertNotNull(groupMember.getExpiration());
        assertEquals(groupMember.getExpiration(), authorityDate);

        // if no match then we change the value

        groupMember.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 2000000));
        assertTrue(zms.dbService.updateUserAuthorityExpiry(groupMember, "elevated-clearance"));
        assertNotNull(groupMember.getExpiration());
        assertEquals(groupMember.getExpiration(), authorityDate);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testGetGroupMembersWithUpdatedDueDatesUserAuthority() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Date currentDate = new Date();
        Timestamp authorityDate = Timestamp.fromDate(currentDate);

        Mockito.when(authority.getDateAttribute("user.john", "elevated-clearance"))
                .thenReturn(currentDate);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        // service users are not processed with regard to elevated-clearance

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("sports.api"));

        List<GroupMember> members = zms.dbService.getGroupMembersWithUpdatedDueDates(groupMembers, null, 0, null,
                0, "elevated-clearance");
        assertTrue(members.isEmpty());

        // no expiry and no user filter - no changes

        groupMembers.clear();
        groupMembers.add(new GroupMember().setMemberName("user.john"));
        groupMembers.add(new GroupMember().setMemberName("user-headless.joe"));
        members = zms.dbService.getGroupMembersWithUpdatedDueDates(groupMembers, null, 0, null, 0, null);
        assertTrue(members.isEmpty());

        // if group member expiry was set and we have no userAuthorityExpiry - we'll keep the original expiration

        groupMembers.clear();
        Timestamp currentTimeExpiration = Timestamp.fromCurrentTime();
        groupMembers.add(new GroupMember().setMemberName("user.john").setExpiration(currentTimeExpiration));
        members = zms.dbService.getGroupMembersWithUpdatedDueDates(groupMembers, null, 0, null, 0, null);
        assertTrue(members.isEmpty());

        // if no expiry and user authority expiry is set - we'll update

        groupMembers.clear();
        groupMembers.add(new GroupMember().setMemberName("user.john"));
        members = zms.dbService.getGroupMembersWithUpdatedDueDates(groupMembers, null, 0, null, 0, "elevated-clearance");
        assertFalse(members.isEmpty());
        assertEquals(members.get(0).getExpiration(), authorityDate);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testGetGroupMembersWithUpdatedDueDates() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        long authorityMillis = System.currentTimeMillis();
        Date currentDate = new Date(authorityMillis);
        Timestamp authorityDate = Timestamp.fromMillis(authorityMillis);

        Mockito.when(authority.getDateAttribute("user.john", "elevated-clearance"))
                .thenReturn(currentDate);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        long serviceExpiryMillis = System.currentTimeMillis();
        Timestamp serviceExpiration = Timestamp.fromMillis(serviceExpiryMillis);
        long userExpiryMillis = System.currentTimeMillis();
        Timestamp userExpiration = Timestamp.fromMillis(userExpiryMillis);

        // Process services (ignore authority expiry)
        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("sports.api"));

        List<GroupMember> members = zms.dbService.getGroupMembersWithUpdatedDueDates(groupMembers, userExpiration, userExpiryMillis, serviceExpiration, userExpiryMillis, "elevated-clearance");
        assertFalse(members.isEmpty());
        assertEquals(members.get(0).getExpiration(), serviceExpiration);

        // Process users. Authority will take precedence.
        groupMembers.clear();
        groupMembers.add(new GroupMember().setMemberName("user.john"));
        members = zms.dbService.getGroupMembersWithUpdatedDueDates(groupMembers, userExpiration, userExpiryMillis, serviceExpiration, userExpiryMillis, "elevated-clearance");
        assertFalse(members.isEmpty());
        assertEquals(members.get(0).getExpiration().millis(), authorityDate.millis());

        // Process users. Without authority user expiration will take precedence.
        groupMembers.clear();
        groupMembers.add(new GroupMember().setMemberName("user.john"));
        members = zms.dbService.getGroupMembersWithUpdatedDueDates(groupMembers, userExpiration, userExpiryMillis, serviceExpiration, userExpiryMillis, null);
        assertFalse(members.isEmpty());
        assertEquals(members.get(0).getExpiration(), userExpiration);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
    }

    @Test
    public void testInsertGroupMembersFailure() {

        final String domainName = "insert-group-members-errs";
        final String groupName = "group1";

        Mockito.when(mockJdbcConn.insertGroupMember(anyString(), anyString(), any(GroupMember.class), anyString(),
                anyString())).thenReturn(false).thenThrow(new ResourceException(400));

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe"));
        groupMembers.add(new GroupMember().setMemberName("user.jane"));

        assertFalse(zms.dbService.insertGroupMembers(mockDomRsrcCtx, mockJdbcConn, groupMembers,
                domainName, groupName, adminUser, auditRef, "unit-test"));

        zms.dbService.store = saveStore;
    }

    @Test
    public void testUpdateGroupMemberDisabledStateFailure() {

        final String domainName = "update-group-members-disabled-errs";
        final String groupName = "group1";

        Mockito.when(mockJdbcConn.updateGroupMemberDisabledState(anyString(), anyString(), anyString(), anyString(),
                anyInt(), anyString())).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe").setSystemDisabled(1));
        groupMembers.add(new GroupMember().setMemberName("user.jane").setSystemDisabled(1));

        assertFalse(zms.dbService.updateGroupMemberDisabledState(mockDomRsrcCtx, mockJdbcConn, groupMembers,
                domainName, groupName, adminUser, auditRef, "unit-test"));

        zms.dbService.store = saveStore;
    }

    @Test
    public void testExecutePutGroupMembershipDecisionFailure() {

        final String domainName = "put-group-mbr-dec-err";
        final String groupName = "group1";

        Mockito.when(mockJdbcConn.confirmGroupMember(anyString(), anyString(), any(GroupMember.class),
                anyString(), anyString())).thenReturn(false).thenThrow(new ResourceException(409));
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        zms.dbService.defaultRetryCount = 2;

        Group group = createGroupObject(domainName, groupName, "user.joe", "user.jane");
        GroupMember groupMember = new GroupMember().setMemberName("user.john");

        // first time we should get false and stand bad request

        try {
            zms.dbService.executePutGroupMembershipDecision(mockDomRsrcCtx, domainName, group, groupMember, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.BAD_REQUEST, ex.getCode());
        }

        // next we should get back our exception

        try {
            zms.dbService.executePutGroupMembershipDecision(mockDomRsrcCtx, domainName, group, groupMember, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.CONFLICT, ex.getCode());
        }

        zms.dbService.store = saveStore;
    }

    @Test
    public void testGetPendingGroupMembershipNotifications() {

        final String domainName1 = "pend-group-members";
        final String domainName2 = "pend-group-members2";
        final String groupName1 = "group1";
        final String groupName2 = "group2";

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName1, "Test Domain1", "testorg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        List<String> admins = new ArrayList<>();
        admins.add(adminUser);
        zms.dbService.makeDomain(mockDomRsrcCtx, ZMSTestUtils.makeDomainObject(domainName2, "test dom2",
                "testorg", true, "acct", 1234, "", 0), admins, null, auditRef);

        DomainMeta meta2 = new DomainMeta()
                .setAccount("acct")
                .setYpmId(1234)
                .setOrg("testorg")
                .setAuditEnabled(true)
                .setCertDnsDomain("athenz.cloud");

        Domain domres2 = new Domain()
                .setName(domainName2)
                .setAuditEnabled(true)
                .setYpmId(1234)
                .setCertDnsDomain("athenz.cloud");

        zms.dbService.updateSystemMetaFields(domres2, "auditenabled", false, meta2);
        Group group2 = createGroupObject(domainName2, groupName2, "user.john", "user.jane");
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName2, groupName2, group2, "test", false);

        GroupSystemMeta rsm2 = new GroupSystemMeta();
        rsm2.setAuditEnabled(true);
        zms.dbService.executePutGroupSystemMeta(mockDomRsrcCtx, domainName2, groupName2, rsm2, "auditenabled", auditRef);

        group2.setAuditEnabled(true);
        zms.dbService.executePutGroupMembership(mockDomRsrcCtx, domainName2, group2,
                new GroupMember().setMemberName("user.poe").setActive(false).setApproved(false), auditRef, false);

        Group group1 = createGroupObject(domainName1, groupName1, "user.john", "user.jane");
        group1.setSelfServe(true);
        zms.dbService.executePutGroup(mockDomRsrcCtx, domainName1, groupName1, group1, auditRef, false);
        zms.dbService.executePutGroupMembership(mockDomRsrcCtx, domainName1, group1,
                new GroupMember().setMemberName("user.doe").setActive(false).setApproved(false), auditRef, false);

        Role auditApproverRole = createRoleObject("sys.auth.audit.org", "testorg",
                null, "user.boe", adminUser);
        zms.dbService.executePutRole(mockDomRsrcCtx, "sys.auth.audit.org", "testorg",
                auditApproverRole, "test", "putrole", false);

        ZMSTestUtils.sleep(1000);
        Set<String> recipientRoles = zms.dbService.getPendingGroupMembershipApproverRoles(0);

        assertNotNull(recipientRoles);
        assertTrue(recipientRoles.contains(domainName1 + ":role.admin"));
        assertTrue(recipientRoles.contains("sys.auth.audit.org:role.testorg"));

        zms.dbService.executeDeleteRole(mockDomRsrcCtx, "sys.auth.audit.org", "testorg", "cleanup", "unitttest");
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName1, auditRef, null);
        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName2, auditRef, null);
    }

    @Test
    public void testGetPendingGroupMembershipNotificationsEdge() {

        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        recipients.add("unix.moe");
        Mockito.when(mockJdbcConn.updatePendingGroupMembersNotificationTimestamp(anyString(), anyLong(), anyInt())).thenReturn(true);
        Mockito.when(mockJdbcConn.getPendingGroupMembershipApproverRoles(anyString(), anyLong())).thenReturn(recipients);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Set<String> recipientsRes = zms.dbService.getPendingGroupMembershipApproverRoles(0);

        assertNotNull(recipientsRes);
        assertTrue(recipientsRes.contains("user.joe"));

        zms.dbService.store = saveStore;
    }

    @Test
    public void testGetPendingGroupMembershipNotificationsTimestampUpdateFailed() {

        Mockito.when(mockJdbcConn.updatePendingGroupMembersNotificationTimestamp(anyString(), anyLong(), anyInt())).thenReturn(false);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        Set<String> recipientsRes = zms.dbService.getPendingGroupMembershipApproverRoles(0);
        assertNull(recipientsRes);
        zms.dbService.store = saveStore;
    }

    @Test
    public void testProcessExpiredPendingGroupMembers() {

        Map<String, List<DomainGroupMember>> memberList = new LinkedHashMap<>();

        DomainGroupMember domainGroupMember1 = new DomainGroupMember();
        domainGroupMember1.setMemberName("user.user1");
        List<GroupMember> memberGroups1 = new ArrayList<>();
        memberGroups1.add(new GroupMember().setGroupName("group1"));
        domainGroupMember1.setMemberGroups(memberGroups1);

        DomainGroupMember domainGroupMember2 = new DomainGroupMember();
        domainGroupMember2.setMemberName("user.user2");
        List<GroupMember> memberGroups2 = new ArrayList<>();
        memberGroups2.add(new GroupMember().setGroupName("group1"));
        domainGroupMember2.setMemberGroups(memberGroups2);

        List<DomainGroupMember> domainGroupMembers = new ArrayList<>();
        domainGroupMembers.add(domainGroupMember1);
        domainGroupMembers.add(domainGroupMember2);
        memberList.put("dom1", domainGroupMembers);

        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Mockito.when(mockJdbcConn.getExpiredPendingDomainGroupMembers(30)).thenReturn(memberList);
        Mockito.when(mockJdbcConn.deletePendingGroupMember("dom1", "role1", "user.user1", "sys.auth.monitor",
                "Expired - auto reject")).thenReturn(true);
        Mockito.when(mockJdbcConn.deletePendingGroupMember("dom1", "role1", "user.user2", "sys.auth.monitor",
                "Expired - auto reject")).thenReturn(false);

        zms.dbService.processExpiredPendingGroupMembers(30, "sys.auth.monitor");
        zms.dbService.store = saveStore;
    }

    @Test
    public void testEnforceGroupUserAuthorityRestrictionsEmptyGroups() {

        // we're making sure we're going to return exception when there
        // are changes thus insert records

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertGroupMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString()))
                .thenThrow(new ResourceException(400, "invalid operation"));

        final String domainName = "authority-test";
        final String groupName = "auth-group";

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null group and then a group
        // with no members - in both cases we return without processing
        // any code

        Group group = new Group();
        Mockito.when(mockConn.getGroup(domainName, groupName))
                .thenReturn(null)
                .thenReturn(group);

        Mockito.when(mockConn.updateDomain(any()))
                .thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // calling the enforce twice - first time we should get null group
        // and second time group with no members

        zms.dbService.enforceGroupUserAuthorityRestrictions(domainName, groupName, null);
        zms.dbService.enforceGroupUserAuthorityRestrictions(domainName, groupName, null);

        zms.dbService.store = savedStore;
    }

    @Test
    public void testEnforceGroupUserAuthorityExpiryRestrictionsUpdate() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String groupName = "auth-group";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertGroupMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null group and then a group
        // with no members - in both cases we return without processing
        // any code

        Group group = new Group().setUserAuthorityExpiration("elevated-clearance");
        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe"));

        Mockito.when(mockConn.getGroup(domainName, groupName)).thenReturn(group);
        Mockito.when(mockConn.listGroupMembers(domainName, groupName, false))
                .thenReturn(groupMembers);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully

        zms.dbService.enforceGroupUserAuthorityRestrictions(domainName, groupName, null);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testEnforceGroupUserAuthorityFilterRestrictionsUpdate() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.isAttributeSet("user.joe", "employee"))
                .thenReturn(false);
        Mockito.when(authority.isAttributeSet("user.jane", "employee"))
                .thenReturn(true);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String groupName = "auth-group";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertGroupMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null group and then a group
        // with no members - in both cases we return without processing
        // any code

        Group group = new Group().setUserAuthorityFilter("employee");
        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe"));
        groupMembers.add(new GroupMember().setMemberName("user.jane"));

        Mockito.when(mockConn.getGroup(domainName, groupName)).thenReturn(group);
        Mockito.when(mockConn.listGroupMembers(domainName, groupName, false))
                .thenReturn(groupMembers);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully

        zms.dbService.enforceGroupUserAuthorityRestrictions(domainName, groupName, null);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testEnforceGroupUserAuthorityRestrictionsNoUpdate() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String groupName = "auth-group";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertGroupMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null group and then a group
        // with no members - in both cases we return without processing
        // any code

        Group group = new Group().setUserAuthorityExpiration("elevated-clearance");
        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 10000)));

        Mockito.when(mockConn.getGroup(domainName, groupName)).thenReturn(group);
        Mockito.when(mockConn.listGroupMembers(domainName, groupName, false))
                .thenReturn(groupMembers);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully

        zms.dbService.enforceGroupUserAuthorityRestrictions(domainName, groupName, null);

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessGroupUserAuthorityRestrictions() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String groupName = "auth-group";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertGroupMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockConn);

        // first we're going to return a null group and then a group
        // with no members - in both cases we return without processing
        // any code

        Group group = new Group().setUserAuthorityExpiration("elevated-clearance");
        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe"));

        Mockito.when(mockConn.getGroup(domainName, groupName)).thenReturn(group);
        Mockito.when(mockConn.listGroupMembers(domainName, groupName, false))
                .thenReturn(groupMembers);

        // first we're going to return no groups and then list of groups
        // in the second one

        List<PrincipalGroup> groups = new ArrayList<>();
        PrincipalGroup prGroup = new PrincipalGroup();
        prGroup.setDomainName(domainName);
        prGroup.setGroupName(groupName);
        groups.add(prGroup);

        Mockito.when(mockConn.listGroupsWithUserAuthorityRestrictions())
                .thenReturn(null)
                .thenReturn(groups);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully
        // first time we'll get no groups so no work is done
        // second time we'll get a single group that we'll process

        zms.dbService.processGroupUserAuthorityRestrictions();
        zms.dbService.processGroupUserAuthorityRestrictions();

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessGroupUserAuthorityRestrictionsExceptions() {

        Authority savedAuthority = zms.dbService.zmsConfig.getUserAuthority();

        Authority authority = Mockito.mock(Authority.class);

        Mockito.when(authority.getDateAttribute("user.joe", "elevated-clearance"))
                .thenReturn(null);

        zms.dbService.zmsConfig.setUserAuthority(authority);

        final String domainName = "authority-test";
        final String groupName1 = "auth-group1";
        final String groupName2 = "auth-group2";

        ObjectStoreConnection mockConn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(mockConn.insertGroupMember(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
                Mockito.any(), Mockito.anyString())).thenReturn(true);
        Mockito.when(mockConn.updateDomainModTimestamp(domainName)).thenReturn(true);

        // we're going to return an exception for the first insert group member
        // and then success for the second one

        Mockito.reset(mockObjStore);
        Mockito.when(mockObjStore.getConnection(true, true))
                .thenThrow(new ResourceException(500, "DB Error"))
                .thenReturn(mockConn);
        Mockito.when(mockObjStore.getConnection(true, false)).thenReturn(mockConn);

        // first we're going to return a null group and then a group
        // with no members - in both cases we return without processing
        // any code

        Group group1 = new Group().setUserAuthorityExpiration("elevated-clearance");
        List<GroupMember> groupMembers1 = new ArrayList<>();
        groupMembers1.add(new GroupMember().setMemberName("user.joe"));

        Mockito.when(mockConn.getGroup(domainName, groupName1)).thenReturn(group1);
        Mockito.when(mockConn.listGroupMembers(domainName, groupName1, false))
                .thenReturn(groupMembers1);

        Group group2 = new Group().setUserAuthorityExpiration("elevated-clearance");
        List<GroupMember> groupMembers2 = new ArrayList<>();
        groupMembers2.add(new GroupMember().setMemberName("user.joe"));

        Mockito.when(mockConn.getGroup(domainName, groupName2)).thenReturn(group2);
        Mockito.when(mockConn.listGroupMembers(domainName, groupName2, false))
                .thenReturn(groupMembers2);

        List<PrincipalGroup> groups = new ArrayList<>();
        PrincipalGroup prGroup1 = new PrincipalGroup();
        prGroup1.setDomainName(domainName);
        prGroup1.setGroupName(groupName1);
        groups.add(prGroup1);
        PrincipalGroup prGroup2 = new PrincipalGroup();
        prGroup2.setDomainName(domainName);
        prGroup2.setGroupName(groupName2);
        groups.add(prGroup2);

        Mockito.when(mockConn.listGroupsWithUserAuthorityRestrictions())
                .thenReturn(groups);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        // the request should complete successfully
        // for the first group we'll get an exception but we'll just log
        // for the second group we'll get success

        zms.dbService.processGroupUserAuthorityRestrictions();

        zms.dbService.zmsConfig.setUserAuthority(savedAuthority);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testAuditLogBooleanDefault() {

        // our default value is false so if we have null or false
        // we have to output value of false otherwise true
        // so we're going to check for explicit value of true

        assertEquals(zms.dbService.auditLogBooleanDefault(null, Boolean.TRUE), "false");
        assertEquals(zms.dbService.auditLogBooleanDefault(Boolean.FALSE, Boolean.TRUE), "false");
        assertEquals(zms.dbService.auditLogBooleanDefault(Boolean.TRUE, Boolean.TRUE), "true");

        // our default value is true so if we have null or true
        // we have to output value of true otherwise false
        // so we're going to check for explicit value of false

        assertEquals(zms.dbService.auditLogBooleanDefault(null, Boolean.FALSE), "true");
        assertEquals(zms.dbService.auditLogBooleanDefault(Boolean.TRUE, Boolean.FALSE), "true");
        assertEquals(zms.dbService.auditLogBooleanDefault(Boolean.FALSE, Boolean.FALSE), "false");
    }

    @Test
    public void testUpdateRoleSystemMetaFieldsInvalidGroup() {

        Role updatedRole = new Role().setAuditEnabled(true);
        RoleMember roleMember = new RoleMember().setMemberName("coretech:group.group1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(roleMember);
        Role originalRole = new Role().setRoleMembers(roleMembers);
        RoleSystemMeta meta = new RoleSystemMeta().setAuditEnabled(true);

        try {
            zms.dbService.updateRoleSystemMetaFields(mockJdbcConn, updatedRole, originalRole, "auditenabled",
                    meta, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("role has invalid group member"), ex.getMessage());
        }
    }

    @Test
    public void testGetDomainUserAuthorityFilterFromMap() {

        // if the map already have an entry we return that and no
        // connection object is necessary

        Map<String, String> map = new HashMap<>();
        map.put("coretech", "OnShore-US");

        assertEquals("OnShore-US", zms.dbService.getDomainUserAuthorityFilterFromMap(null, map, "coretech"));

        // we have a domain that is null

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.getDomain("coretech")).thenReturn(null);

        // in this case we should get back ""

        map.clear();
        assertTrue(zms.dbService.getDomainUserAuthorityFilterFromMap(conn, map, "coretech").isEmpty());

        // we're going to return domain without authority filter
        // so we'll return "" as well

        Domain domain = new Domain();
        Mockito.when(conn.getDomain("coretech")).thenReturn(domain);

        map.clear();
        assertTrue(zms.dbService.getDomainUserAuthorityFilterFromMap(conn, map, "coretech").isEmpty());

        // now we're going to return with domain filter value

        domain = new Domain().setUserAuthorityFilter("OnShore-US");
        Mockito.when(conn.getDomain("coretech")).thenReturn(domain);

        map.clear();
        assertEquals("OnShore-US", zms.dbService.getDomainUserAuthorityFilterFromMap(conn, map, "coretech"));
    }

    @Test
    public void testValidateGroupUserAuthorityAttrRequirements() {

        Group originalGroup = new Group().setName("group1").setUserAuthorityFilter("OnShore-US");
        Group updatedGroup = new Group().setName("group1");

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.getPrincipalRoles("group1", null)).thenThrow(new ResourceException(ResourceException.BAD_REQUEST));

        try {
            zms.dbService.validateGroupUserAuthorityAttrRequirements(conn, originalGroup, updatedGroup, "unittest");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        // now we're going to mock the use case where the role no longer exists

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setDomainName("coretech").setRoleName("role1"));
        DomainRoleMember domainRoleMember = new DomainRoleMember();
        domainRoleMember.setMemberRoles(memberRoles);
        ObjectStoreConnection conn2 = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn2.getPrincipalRoles("group1", null)).thenReturn(domainRoleMember);
        Mockito.when(conn2.getRole("coretech", "role1")).thenReturn(null);

        // the call will complete without any exceptions and no changes

        zms.dbService.validateGroupUserAuthorityAttrRequirements(conn2, originalGroup, updatedGroup, "unittest");
    }

    @Test
    public void testMemberStrictExpiration() {

        assertNull(zms.dbService.memberStrictExpiration(null, null));
        Timestamp now = Timestamp.fromCurrentTime();
        assertEquals(zms.dbService.memberStrictExpiration(null, now), now);

        assertEquals(zms.dbService.memberStrictExpiration(now, null), now);

        Timestamp past = Timestamp.fromMillis(System.currentTimeMillis() - 100000);
        Timestamp future = Timestamp.fromMillis(System.currentTimeMillis() + 100000);

        assertEquals(zms.dbService.memberStrictExpiration(now, future), now);
        assertEquals(zms.dbService.memberStrictExpiration(now, past), past);
    }

    @Test
    public void testGetPrincipals() {
        List<String> dbPrincipals = Arrays.asList("user.user1","user.user2","dom1.svc1");
        Mockito.when(mockJdbcConn.getPrincipals(2)).thenReturn(dbPrincipals);

        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        List<Principal> principals = zms.dbService.getPrincipals(2);
        assertNotNull(principals);
        assertEquals(principals.size(), 3);

        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdatePrincipalByStateFromAuthority() {
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        DomainRoleMember drm = new DomainRoleMember();
        MemberRole mr1 = new MemberRole().setMemberName("user.user1").setRoleName("role1").setDomainName("dom1").setSystemDisabled(null);
        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(mr1);
        drm.setMemberRoles(memberRoles);

        DomainGroupMember dgm = new DomainGroupMember();
        GroupMember gm1 = new GroupMember().setMemberName("user.user1").setGroupName("grp1").setDomainName("dom1").setSystemDisabled(null);
        List<GroupMember> memberGroups = new ArrayList<>();
        memberGroups.add(gm1);
        dgm.setMemberGroups(memberGroups);

        Mockito.when(mockJdbcConn.updatePrincipal("user.user1", 2)).thenReturn(true);

        Mockito.when(mockJdbcConn.getPrincipalRoles("user.user1", null)).thenReturn(drm);
        Mockito.when(mockJdbcConn.updateRoleMemberDisabledState("dom1", "role1", "user.user1",
                ZMSConsts.SYS_AUTH_MONITOR, 2, "Athenz User Authority Enforcer")).thenReturn(true);
        Mockito.when(mockJdbcConn.updateRoleModTimestamp(anyString(), anyString())).thenReturn(true);
        Mockito.when(mockJdbcConn.updateDomainModTimestamp(anyString())).thenReturn(true);

        Mockito.when(mockJdbcConn.getPrincipalGroups("user.user1", null)).thenReturn(dgm);
        Mockito.when(mockJdbcConn.updateGroupMemberDisabledState("dom1", "grp1", "user.user1",
                ZMSConsts.SYS_AUTH_MONITOR, 2, "Athenz User Authority Enforcer")).thenReturn(true);
        Mockito.when(mockJdbcConn.updateGroupModTimestamp(anyString(), anyString())).thenReturn(true);
        Mockito.when(mockJdbcConn.updateDomainModTimestamp(anyString())).thenReturn(true);

        List<Principal> changedPrincipals = new ArrayList<>();
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user1", "user", null));

        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, true);

        }catch (ResourceException rex) {
            fail();
        }

        Mockito.when(mockJdbcConn.updatePrincipal("user.user1", 0)).thenReturn(true);

        Mockito.when(mockJdbcConn.getPrincipalRoles("user.user1", null)).thenReturn(drm);
        Mockito.when(mockJdbcConn.updateRoleMemberDisabledState("dom1", "role1", "user.user1",
                ZMSConsts.SYS_AUTH_MONITOR, 0, "Athenz User Authority Enforcer")).thenReturn(true);
        Mockito.when(mockJdbcConn.updateRoleModTimestamp(anyString(), anyString())).thenReturn(true);
        Mockito.when(mockJdbcConn.updateDomainModTimestamp(anyString())).thenReturn(true);

        Mockito.when(mockJdbcConn.getPrincipalGroups("user.user1", null)).thenReturn(dgm);
        Mockito.when(mockJdbcConn.updateGroupMemberDisabledState("dom1", "grp1", "user.user1",
                ZMSConsts.SYS_AUTH_MONITOR, 0, "Athenz User Authority Enforcer")).thenReturn(true);
        Mockito.when(mockJdbcConn.updateGroupModTimestamp(anyString(), anyString())).thenReturn(true);
        Mockito.when(mockJdbcConn.updateDomainModTimestamp(anyString())).thenReturn(true);

        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, false);
        } catch (ResourceException rex) {
            fail();
        }
        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdatePrincipalByStateFromAuthorityExistingDisabled() {
        JDBCConnection jdbcConn = Mockito.mock(JDBCConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(jdbcConn);
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        DomainRoleMember drm = new DomainRoleMember();
        MemberRole mr1 = new MemberRole().setMemberName("user.user1").setRoleName("role1").setDomainName("dom1").setSystemDisabled(1);
        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(mr1);
        drm.setMemberRoles(memberRoles);

        DomainGroupMember dgm = new DomainGroupMember();
        GroupMember gm1 = new GroupMember().setMemberName("user.user1").setGroupName("grp1").setDomainName("dom1").setSystemDisabled(1);
        List<GroupMember> memberGroups = new ArrayList<>();
        memberGroups.add(gm1);
        dgm.setMemberGroups(memberGroups);

        Mockito.when(jdbcConn.updatePrincipal("user.user1", 2)).thenReturn(true);

        Mockito.when(jdbcConn.getPrincipalRoles("user.user1", null)).thenReturn(drm);
        Mockito.when(jdbcConn.updateRoleMemberDisabledState("dom1", "role1", "user.user1",
                ZMSConsts.SYS_AUTH_MONITOR, 2, "Athenz User Authority Enforcer")).thenReturn(true);
        Mockito.when(jdbcConn.updateRoleModTimestamp(anyString(), anyString())).thenReturn(true);
        Mockito.when(jdbcConn.updateDomainModTimestamp(anyString())).thenReturn(true);

        Mockito.when(jdbcConn.getPrincipalGroups("user.user1", null)).thenReturn(dgm);
        Mockito.when(jdbcConn.updateGroupMemberDisabledState("dom1", "grp1", "user.user1",
                ZMSConsts.SYS_AUTH_MONITOR, 2, "Athenz User Authority Enforcer")).thenReturn(true);
        Mockito.when(jdbcConn.updateGroupModTimestamp(anyString(), anyString())).thenReturn(true);
        Mockito.when(jdbcConn.updateDomainModTimestamp(anyString())).thenReturn(true);

        List<Principal> changedPrincipals = new ArrayList<>();
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user1", "user", null));

        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, true);

        }catch (ResourceException rex) {
            fail();
        }

        Mockito.when(jdbcConn.updatePrincipal("user.user1", 0)).thenReturn(true);

        Mockito.when(jdbcConn.getPrincipalRoles("user.user1", null)).thenReturn(drm);
        Mockito.when(jdbcConn.updateRoleMemberDisabledState("dom1", "role1", "user.user1",
                ZMSConsts.SYS_AUTH_MONITOR, 0, "Athenz User Authority Enforcer")).thenReturn(true);
        Mockito.when(jdbcConn.updateRoleModTimestamp(anyString(), anyString())).thenReturn(true);
        Mockito.when(jdbcConn.updateDomainModTimestamp(anyString())).thenReturn(true);

        Mockito.when(jdbcConn.getPrincipalGroups("user.user1", null)).thenReturn(dgm);
        Mockito.when(jdbcConn.updateGroupMemberDisabledState("dom1", "grp1", "user.user1",
                ZMSConsts.SYS_AUTH_MONITOR, 0, "Athenz User Authority Enforcer")).thenReturn(true);
        Mockito.when(jdbcConn.updateGroupModTimestamp(anyString(), anyString())).thenReturn(true);
        Mockito.when(jdbcConn.updateDomainModTimestamp(anyString())).thenReturn(true);

        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, false);
        } catch (ResourceException rex) {
            fail();
        }
        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdatePrincipalByStateFromAuthorityExceptionUpdatePrincipal() {
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Mockito.when(mockJdbcConn.updatePrincipal("user.user1", 2)).thenThrow(new ResourceException(ResourceException.NOT_FOUND, "not found"));
        Mockito.when(mockJdbcConn.updatePrincipal("user.user2", 2)).thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        List<Principal> changedPrincipals = new ArrayList<>();
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user1", "user", null));
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user2", "user", null));
        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, true);
        } catch (ResourceException rex) {
            fail();
        }
        Mockito.verify(mockJdbcConn, atLeast(2)).updatePrincipal(anyString(), anyInt());
        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdatePrincipalByStateFromAuthorityInvalidUpdatePrincipal() {
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Mockito.when(mockJdbcConn.updatePrincipal(anyString(), anyInt())).thenReturn(false).thenReturn(false);

        List<Principal> changedPrincipals = new ArrayList<>();
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user3", "user", null));
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user4", "user", null));
        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, true);
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, false);
        } catch (ResourceException rex) {
            fail();
        }
        Mockito.verify(mockJdbcConn, atLeast(4)).updatePrincipal(anyString(), anyInt());
        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdatePrincipalByStateFromAuthorityExceptionUpdateRoleMembership() {
        JDBCConnection jdbcConn = Mockito.mock(JDBCConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(jdbcConn);
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Mockito.when(jdbcConn.updatePrincipal("user.user3", 2)).thenReturn(true);
        Mockito.when(jdbcConn.updatePrincipal("user.user4", 2)).thenReturn(true);

        Mockito.when(jdbcConn.getPrincipalRoles("user.user3", null)).thenThrow(new ResourceException(ResourceException.NOT_FOUND, "not found"));
        Mockito.when(jdbcConn.getPrincipalRoles("user.user4", null)).thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        List<Principal> changedPrincipals = new ArrayList<>();
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user3", "user", null));
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user4", "user", null));
        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, true);
            fail();
        } catch (ResourceException rex) {
            assertEquals(rex.getCode(), ResourceException.CONFLICT);
        }
        Mockito.verify(jdbcConn, atLeastOnce()).getPrincipalRoles("user.user3", null);
        Mockito.verify(jdbcConn, atLeastOnce()).getPrincipalRoles("user.user4", null);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdatePrincipalByStateFromAuthorityExceptionUpdateGroupMembership() {
        JDBCConnection jdbcConn = Mockito.mock(JDBCConnection.class);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(jdbcConn);
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Mockito.when(jdbcConn.updatePrincipal("user.user1", 2)).thenReturn(true);
        Mockito.when(jdbcConn.updatePrincipal("user.user2", 2)).thenReturn(true);

        DomainRoleMember drm = new DomainRoleMember();
        List<MemberRole> memberRoles = new ArrayList<>();
        drm.setMemberRoles(memberRoles);

        Mockito.when(jdbcConn.getPrincipalRoles("user.user1", null)).thenReturn(drm);
        Mockito.when(jdbcConn.getPrincipalRoles("user.user2", null)).thenReturn(drm);

        Mockito.when(jdbcConn.getPrincipalGroups("user.user1", null)).thenThrow(new ResourceException(ResourceException.NOT_FOUND, "not found"));
        Mockito.when(jdbcConn.getPrincipalGroups("user.user2", null)).thenThrow(new ResourceException(ResourceException.CONFLICT, "conflict"));

        List<Principal> changedPrincipals = new ArrayList<>();
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user1", "user", null));
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user2", "user", null));
        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, true);
            fail();
        } catch (ResourceException rex) {
            assertEquals(rex.getCode(), ResourceException.CONFLICT);
        }
        Mockito.verify(jdbcConn, atLeastOnce()).getPrincipalGroups("user.user1", null);
        Mockito.verify(jdbcConn, atLeastOnce()).getPrincipalGroups("user.user2", null);

        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdatePrincipalByStateFromAuthorityEmptyPrincipal() {
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        List<Principal> changedPrincipals = new ArrayList<>();
        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, true);
        } catch (ResourceException rex) {
            fail();
        }
        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdatePrincipalByStateFromAuthorityEmptyMembershipInDB() {
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        DomainRoleMember drm = new DomainRoleMember();
        List<MemberRole> memberRoles = new ArrayList<>();
        drm.setMemberRoles(memberRoles);

        DomainGroupMember dgm = new DomainGroupMember();
        List<GroupMember> memberGroups = new ArrayList<>();
        dgm.setMemberGroups(memberGroups);

        Mockito.when(mockJdbcConn.updatePrincipal("user.user1", 2)).thenReturn(true);
        Mockito.when(mockJdbcConn.getPrincipalRoles("user.user1", null)).thenReturn(drm);
        Mockito.when(mockJdbcConn.getPrincipalGroups("user.user1", null)).thenReturn(dgm);

        List<Principal> changedPrincipals = new ArrayList<>();
        changedPrincipals.add(ZMSUtils.createPrincipalForName("user.user1", "user", null));

        try {
            zms.dbService.updatePrincipalByStateFromAuthority(changedPrincipals, true);
        } catch (ResourceException rex) {
            fail();
        }

        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessRoleWithTagsInsert() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> roleTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        Role role = new Role().setName("newRole").setTags(roleTags);
        Mockito.when(conn.insertRole("sys.auth", role)).thenReturn(true);
        Mockito.when(conn.insertRoleTags("newRole", "sys.auth", roleTags)).thenReturn(true);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processRole(conn, null, "sys.auth", "newRole",
                role, adminUser, auditRef, false, auditDetails);

       assertTrue(success);
    }

    @Test
    public void testProcessRoleWithTagsUpdate() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> roleTags = new HashMap<>();
        roleTags.put("tagToBeRemoved", new TagValueList().setList(Collections.singletonList("val0")));
        roleTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));

        Role role = new Role().setName("newRole").setTags(roleTags);
        Mockito.when(conn.insertRole(anyString(), any())).thenReturn(true);
        Mockito.when(conn.insertRoleTags("newRole", "sys.auth", roleTags)).thenReturn(true);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processRole(conn, null, "sys.auth", "newRole",
                role, adminUser, auditRef, false, auditDetails);

        assertTrue(success);

        // new role
        Map<String, TagValueList> newRoleTags = new HashMap<>();
        newRoleTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));
        newRoleTags.put("newTagKey", new TagValueList().setList(Arrays.asList("val3", "val4")));
        newRoleTags.put("newTagKey2", new TagValueList().setList(Arrays.asList("val5", "val6")));

        Role newRole = new Role().setName("newRole").setTags(newRoleTags);

        Mockito.when(conn.updateRole("sys.auth", newRole)).thenReturn(true);
        Mockito.when(conn.deleteRoleTags(anyString(), anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertRoleTags(anyString(), anyString(), anyMap())).thenReturn(true);

        success = zms.dbService.processRole(conn, role, "sys.auth", "newRole",
                newRole, adminUser, auditRef, false, auditDetails);

        assertTrue(success);

        // assert tags to remove
        Set<String> expectedTagsToBeRemoved = new HashSet<>(Collections.singletonList("tagToBeRemoved")) ;

        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> roleCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteRoleTags(roleCapture.capture(), domainCapture.capture(), tagCapture.capture());
        assertEquals("newRole", roleCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        assertTrue(tagCapture.getValue().containsAll(expectedTagsToBeRemoved));

        // assert tags to add
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertRoleTags(roleCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals("newRole", roleCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(1);
        assertTrue(resultInsertTags.keySet().containsAll(Arrays.asList("newTagKey", "newTagKey2")));
        assertTrue(resultInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("val3", "val4", "val5", "val6")));

        // assert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertTrue(resultFirstInsertTags.keySet().containsAll(Arrays.asList("tagKey", "tagToBeRemoved")));
        assertTrue(resultFirstInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("val0", "val1", "val2")));
    }

    @Test
    public void testProcessServiceWithTagsInsert() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> serviceTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        ServiceIdentity service = new ServiceIdentity().setName("newService").setTags(serviceTags);
        Mockito.when(conn.insertServiceIdentity("sys.auth", service)).thenReturn(true);
        Mockito.when(conn.insertServiceTags("newService", "sys.auth", serviceTags)).thenReturn(true);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processServiceIdentity(null, conn, null, "sys.auth", "newService",
                service, false, auditDetails);

        ArgumentCaptor<String> serviceCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Map<String, TagValueList>> tagCapture = ArgumentCaptor.forClass(Map.class);

        Mockito.verify(conn, times(1)).insertServiceTags(serviceCapture.capture(), domainCapture.capture(), tagCapture.capture());
        assertTrue(tagCapture.getValue().containsKey("tagKey"));
        assertTrue(tagCapture.getValue().values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("tagVal")));

        assertTrue(success);
    }

    @Test
    public void testProcessServiceWithTagsUpdate() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> serviceTags = new HashMap<>();
        serviceTags.put("tagToBeRemoved", new TagValueList().setList(Collections.singletonList("val0")));
        serviceTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));

        ServiceIdentity service = new ServiceIdentity().setName("newService").setTags(serviceTags);
        Mockito.when(conn.insertServiceIdentity(anyString(), any())).thenReturn(true);
        Mockito.when(conn.insertServiceTags("newService", "sys.auth", serviceTags)).thenReturn(true);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processServiceIdentity(null, conn, null, "sys.auth", "newService",
                service, false, auditDetails);

        assertTrue(success);

        // new service
        Map<String, TagValueList> newServiceTags = new HashMap<>();
        newServiceTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));
        newServiceTags.put("newTagKey", new TagValueList().setList(Arrays.asList("val3", "val4")));
        newServiceTags.put("newTagKey2", new TagValueList().setList(Arrays.asList("val5", "val6")));

        ServiceIdentity newService = new ServiceIdentity().setName("newService").setTags(newServiceTags);

        Mockito.when(conn.updateServiceIdentity("sys.auth", newService)).thenReturn(true);
        Mockito.when(conn.deleteServiceTags(anyString(), anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertServiceTags(anyString(), anyString(), anyMap())).thenReturn(true);


        success = zms.dbService.processServiceIdentity(null, conn, service, "sys.auth", "newService",
                newService, false, auditDetails);

        assertTrue(success);

        // assert tags to remove
        Set<String> expectedTagsToBeRemoved = new HashSet<>(Collections.singletonList("tagToBeRemoved")) ;

        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> serviceCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteServiceTags(serviceCapture.capture(), domainCapture.capture(), tagCapture.capture());
        assertEquals("newService", serviceCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        assertTrue(tagCapture.getValue().containsAll(expectedTagsToBeRemoved));

        // assert tags to add
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertServiceTags(serviceCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals("newService", serviceCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(1);
        assertTrue(resultInsertTags.keySet().containsAll(Arrays.asList("newTagKey", "newTagKey2")));
        assertTrue(resultInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("val3", "val4", "val5", "val6")));

        // assert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertTrue(resultFirstInsertTags.keySet().containsAll(Arrays.asList("tagKey", "tagToBeRemoved")));
        assertTrue(resultFirstInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("val0", "val1", "val2")));
    }

    @Test
    public void testServiceSameTagKeyValues() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> serviceTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        ServiceIdentity service = new ServiceIdentity().setName("service").setTags(serviceTags);
        Mockito.when(conn.insertServiceIdentity(anyString(), any())).thenReturn(true);
        Mockito.when(conn.insertServiceTags(anyString(), anyString(), any())).thenReturn(true);
        StringBuilder auditDetails = new StringBuilder("testAudit");

        boolean success = zms.dbService.processServiceIdentity(null, conn, null, "sys.auth", "newService",
                service, false, auditDetails);

        assertTrue(success);

        // process the same service again with the same tags
        ServiceIdentity newService = new ServiceIdentity().setName("service").setTags(serviceTags);

        Mockito.when(conn.updateServiceIdentity("sys.auth", newService)).thenReturn(true);
        Mockito.when(conn.deleteServiceTags(anyString(), anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertServiceTags(anyString(), anyString(), anyMap())).thenReturn(true);

        success = zms.dbService.processServiceIdentity(null, conn, service, "sys.auth", "newService",
                newService, false, auditDetails);

        assertTrue(success);

        // assert tags to remove should be empty
        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> serviceCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteServiceTags(serviceCapture.capture(), domainCapture.capture(), tagCapture.capture());
        assertEquals("newService", serviceCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        assertTrue(tagCapture.getValue().isEmpty());

        // assert tags to add should be empty
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertServiceTags(serviceCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals("newService", serviceCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(1);
        assertTrue(resultInsertTags.isEmpty());

        // asert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertTrue(resultFirstInsertTags.containsKey("tagKey"));
        assertTrue(resultFirstInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .contains("tagVal"));

    }

    @Test
    public void testRoleSameTagKeyValues() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> roleTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        Role role = new Role().setName("role").setTags(roleTags);
        Mockito.when(conn.insertRole(anyString(), any())).thenReturn(true);
        Mockito.when(conn.insertRoleTags(anyString(), anyString(), any())).thenReturn(true);
        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processRole(conn, null, "sys.auth", "newRole",
                role, adminUser, auditRef, false, auditDetails);
        assertTrue(success);

        // process the same role again with the same tags
        Role newRole = new Role().setName("role").setTags(roleTags);

        Mockito.when(conn.updateRole("sys.auth", newRole)).thenReturn(true);
        Mockito.when(conn.deleteRoleTags(anyString(), anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertRoleTags(anyString(), anyString(), anyMap())).thenReturn(true);

        success = zms.dbService.processRole(conn, role, "sys.auth", "newRole",
                newRole, adminUser, auditRef, false, auditDetails);

        assertTrue(success);

        // assert tags to remove should be empty
        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> roleCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteRoleTags(roleCapture.capture(), domainCapture.capture(), tagCapture.capture());
        assertEquals("newRole", roleCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        assertTrue(tagCapture.getValue().isEmpty());

        // assert tags to add should be empty
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertRoleTags(roleCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals("newRole", roleCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(1);
        assertTrue(resultInsertTags.isEmpty());

        // assert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertTrue(resultFirstInsertTags.containsKey("tagKey"));
        assertTrue(resultFirstInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .contains("tagVal"));

    }

    @Test
    public void testUpdateRoleMetaWithoutTag() {
        final String domainName = "sys.auth";
        final String updateRoleMetaTag = "tag-key-update-role-meta-without-tag";
        final List<String> updateRoleMetaTagValues = Collections.singletonList("update-meta-value");
        final String roleName = "roleWithTagUpdateMeta";
        ObjectStore savedStore = zms.dbService.store;

        Role role = new Role().setName(roleName);
        RoleMeta rm = new RoleMeta()
            .setTags(Collections.singletonMap(updateRoleMetaTag,
                new TagValueList().setList(updateRoleMetaTagValues)));

        // mock dbService store
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.updateRole(any(), any())).thenReturn(true);
        Mockito.when(conn.insertRoleTags(anyString(), anyString(), anyMap())).thenReturn(true);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        zms.dbService.store = mockObjStore;

        // update role meta
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName , roleName, role, rm, auditRef, "testUpdateRoleMetaWithoutTag");

        // assert tags to add contains role meta tags
        ArgumentCaptor<String> roleCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);

        Mockito.verify(conn, times(1)).insertRoleTags(roleCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals(roleName, roleCapture.getValue());
        assertEquals(domainName, domainCapture.getValue());

        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(0);
        TagValueList tagValues = resultInsertTags.get(updateRoleMetaTag);
        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(updateRoleMetaTagValues));
        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdateRoleMetaWithExistingTag() {
        final String domainName = "sys.auth";
        final String initialTagKey = "initial-tag-key";
        final List<String> initialTagValues = Collections.singletonList("initial-tag-value");
        final String updateRoleMetaTag = "tag-key-update-role-meta-exist-tag";
        final List<String> updateRoleMetaTagValues = Collections.singletonList("update-meta-value");
        final String roleName = "roleWithTagUpdateMeta";
        ObjectStore savedStore = zms.dbService.store;

        // initial role with tags
        Role role = new Role().setName(roleName)
            .setTags(Collections.singletonMap(initialTagKey,
                new TagValueList().setList(initialTagValues)));

        // role meta with updated tags
        RoleMeta rm = new RoleMeta()
            .setTags(Collections.singletonMap(updateRoleMetaTag,
                new TagValueList().setList(updateRoleMetaTagValues)));

        // mock dbService store
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.updateRole(any(), any())).thenReturn(true);
        Mockito.when(conn.deleteRoleTags(anyString(), anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertRoleTags(anyString(), anyString(), anyMap())).thenReturn(true);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        zms.dbService.store = mockObjStore;

        // update role meta
        zms.dbService.executePutRoleMeta(mockDomRsrcCtx, domainName , roleName, role, rm, auditRef, "testUpdateRoleMetaWithoutTag");

        // assert tags to removed
        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> roleCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteRoleTags(roleCapture.capture(), domainCapture.capture(), tagCapture.capture());
        assertEquals(roleName, roleCapture.getValue());
        assertEquals(domainName, domainCapture.getValue());
        assertTrue(tagCapture.getValue().contains(initialTagKey));

        // assert tags to add
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(1)).insertRoleTags(roleCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals(roleName, roleCapture.getValue());
        assertEquals(domainName, domainCapture.getValue());

        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(0);
        TagValueList tagValues = resultInsertTags.get(updateRoleMetaTag);
        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(updateRoleMetaTagValues));
        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessDomainWithTagsInsert() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        ObjectStore savedStore = zms.dbService.store;

        Map<String, TagValueList> domainTags = Collections.singletonMap(
            "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        Domain domain = new Domain().setName("newDomainTagInsert").setTags(domainTags);
        Mockito.when(conn.insertDomain(domain)).thenReturn(true);
        Mockito.when(conn.insertDomainTags("newDomainTagInsert", domainTags)).thenReturn(true);
        Mockito.when(conn.insertRole(anyString(), any(Role.class))).thenReturn(true);
        Mockito.when(conn.insertRoleMember(any(), any(), any(), any(), any())).thenReturn(true);
        Mockito.when(conn.insertPolicy(any(), any())).thenReturn(true);
        Mockito.when(conn.insertAssertion(any(), any(), any(), any())).thenReturn(true);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
            .thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn);
        zms.dbService.store = mockObjStore;

        Domain createdDomain = zms.dbService.makeDomain(mockDomRsrcCtx, domain, Collections.singletonList(adminUser), null, auditRef);

        assertEquals(createdDomain.getTags(), domainTags);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessDomainWithTagsUpdate() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        ObjectStore savedStore = zms.dbService.store;

        Map<String, TagValueList> domainTags = new HashMap<>();
        domainTags.put("tagToBeRemoved", new TagValueList().setList(Collections.singletonList("val0")));
        domainTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));

        Domain domain = new Domain().setName("newDomain").setTags(domainTags);
        Mockito.when(conn.insertDomain(domain)).thenReturn(true);
        Mockito.when(conn.insertDomainTags("newDomain", domainTags)).thenReturn(true);
        Mockito.when(conn.insertRole(anyString(), any(Role.class))).thenReturn(true);
        Mockito.when(conn.insertRoleMember(any(), any(), any(), any(), any())).thenReturn(true);
        Mockito.when(conn.insertPolicy(any(), any())).thenReturn(true);
        Mockito.when(conn.insertAssertion(any(), any(), any(), any())).thenReturn(true);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
            .thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn);
        zms.dbService.store = mockObjStore;

        Domain createdDomain = zms.dbService.makeDomain(mockDomRsrcCtx, domain, Collections.singletonList(adminUser), null, auditRef);
        assertEquals(createdDomain.getTags(), domainTags);

        // new tags
        Map<String, TagValueList> newDomainTags = new HashMap<>();
        newDomainTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));
        newDomainTags.put("newTagKey", new TagValueList().setList(Arrays.asList("val3", "val4")));
        newDomainTags.put("newTagKey2", new TagValueList().setList(Arrays.asList("val5", "val6")));

        Mockito.when(conn.updateDomain(any(Domain.class))).thenReturn(true);
        Mockito.when(conn.deleteDomainTags(anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertDomainTags(anyString(), anyMap())).thenReturn(true);
        Mockito.when(conn.getDomain("newDomain")).thenReturn(domain);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
            .thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn);

        // update domain meta
        DomainMeta meta = new DomainMeta().setTags(newDomainTags);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domain, meta, null, false, auditRef, "putDomainMeta");

        // assert tags to remove
        Set<String> expectedTagsToBeRemoved = new HashSet<>(Collections.singletonList("tagToBeRemoved")) ;

        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteDomainTags(domainCapture.capture(), tagCapture.capture());
        assertEquals("newDomain", domainCapture.getValue());
        assertTrue(tagCapture.getValue().containsAll(expectedTagsToBeRemoved));

        // assert tags to add
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertDomainTags(domainCapture.capture(), tagInsertCapture.capture());
        assertEquals("newDomain", domainCapture.getValue());
        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(1);
        assertTrue(resultInsertTags.keySet().containsAll(Arrays.asList("newTagKey", "newTagKey2")));
        assertTrue(resultInsertTags.values().stream()
            .flatMap(l -> l.getList().stream())
            .collect(Collectors.toList())
            .containsAll(Arrays.asList("val3", "val4", "val5", "val6")));

        // assert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertTrue(resultFirstInsertTags.keySet().containsAll(Arrays.asList("tagKey", "tagToBeRemoved")));
        assertTrue(resultFirstInsertTags.values().stream()
            .flatMap(l -> l.getList().stream())
            .collect(Collectors.toList())
            .containsAll(Arrays.asList("val0", "val1", "val2")));
        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessDomainWithUpdateNullTags() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        ObjectStore savedStore = zms.dbService.store;

        Map<String, TagValueList> domainTags = new HashMap<>();
        domainTags.put("tagToBeRemoved", new TagValueList().setList(Collections.singletonList("val0")));
        domainTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));

        Domain domain = new Domain().setName("newDomain").setTags(domainTags);
        Mockito.when(conn.insertDomain(domain)).thenReturn(true);
        Mockito.when(conn.insertDomainTags("newDomain", domainTags)).thenReturn(true);
        Mockito.when(conn.insertRole(anyString(), any(Role.class))).thenReturn(true);
        Mockito.when(conn.insertRoleMember(any(), any(), any(), any(), any())).thenReturn(true);
        Mockito.when(conn.insertPolicy(any(), any())).thenReturn(true);
        Mockito.when(conn.insertAssertion(any(), any(), any(), any())).thenReturn(true);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
                .thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn);
        zms.dbService.store = mockObjStore;

        Domain createdDomain = zms.dbService.makeDomain(mockDomRsrcCtx, domain, Collections.singletonList(adminUser), null, auditRef);
        assertEquals(createdDomain.getTags(), domainTags);

        Mockito.when(conn.updateDomain(any(Domain.class))).thenReturn(true);
        Mockito.when(conn.deleteDomainTags(anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertDomainTags(anyString(), anyMap())).thenReturn(true);
        Mockito.when(conn.getDomain("newDomain")).thenReturn(domain);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
                .thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn);

        // update domain meta
        DomainMeta meta = new DomainMeta().setTags(null);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domain, meta, null, false, auditRef, "putDomainMeta");

        assertEquals(createdDomain.getTags(), domainTags);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessDomainWithSameTagsUpdate() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        ObjectStore savedStore = zms.dbService.store;

        Map<String, TagValueList> domainTags = Collections.singletonMap("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));

        Domain domain = new Domain().setName("newDomainTagsUpdate").setTags(domainTags);
        Mockito.when(conn.insertDomain(domain)).thenReturn(true);
        Mockito.when(conn.insertDomainTags("newDomainTagsUpdate", domainTags)).thenReturn(true);
        Mockito.when(conn.insertRole(anyString(), any(Role.class))).thenReturn(true);
        Mockito.when(conn.insertRoleMember(any(), any(), any(), any(), any())).thenReturn(true);
        Mockito.when(conn.insertPolicy(any(), any())).thenReturn(true);
        Mockito.when(conn.insertAssertion(any(), any(), any(), any())).thenReturn(true);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
            .thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn);
        zms.dbService.store = mockObjStore;

        Domain createdDomain = zms.dbService.makeDomain(mockDomRsrcCtx, domain, Collections.singletonList(adminUser), null, auditRef);
        assertEquals(createdDomain.getTags(), domainTags);

        // same tags tags
        Map<String, TagValueList> newDomainTags = Collections.singletonMap("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));

        Mockito.when(conn.updateDomain(any(Domain.class))).thenReturn(true);
        Mockito.when(conn.deleteDomainTags(anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertDomainTags(anyString(), anyMap())).thenReturn(true);
        Mockito.when(conn.getDomain("newDomainTagsUpdate")).thenReturn(domain);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
            .thenReturn(conn).thenReturn(conn).thenReturn(conn).thenReturn(conn);

        // update domain meta
        DomainMeta meta = new DomainMeta().setTags(newDomainTags);
        zms.dbService.executePutDomainMeta(mockDomRsrcCtx, domain, meta, null, false, auditRef, "putDomainMeta");

        // assert tags to remove is empty
        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteDomainTags(domainCapture.capture(), tagCapture.capture());

        // assert tags to add is empty
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertDomainTags(domainCapture.capture(), tagInsertCapture.capture());

        // assert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertEquals(resultFirstInsertTags, Collections.singletonMap("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2"))));
        zms.dbService.store = savedStore;
    }

    @Test
    public void testAuditLogPolicy() {

        StringBuilder auditDetails = new StringBuilder();
        Timestamp currentTime = Timestamp.fromMillis(1629802092416L);
        Policy policyVer1 = new Policy().setName("policy1").setVersion("version1").setModified(currentTime).setAssertions(null);
        Policy policyVer2 = new Policy().setName("policy1").setVersion("version2").setAssertions(null);
        List<Policy> policyVersions = new ArrayList<>();
        policyVersions.add(policyVer1);
        policyVersions.add(policyVer2);

        zms.dbService.auditLogPolicy(auditDetails, policyVersions, "delete-policy-versions");
        assertEquals(auditDetails.toString(), "{\"name\": \"policy1\", \"delete-policy-versions\": " +
                "[{\"name\": \"policy1\", \"version\": \"version1\", \"active\": \"null\", \"modified\": \"2021-08-24T10:48:12.416Z\"}," +
                "{\"name\": \"policy1\", \"version\": \"version2\", \"active\": \"null\", \"modified\": \"null\"}]}");

        Assertion assertion = new Assertion().setAction("update")
                .setResource("table").setRole("reader");
        policyVer1.setAssertions(new ArrayList<>());
        policyVer1.getAssertions().add(assertion);

        Assertion assertionVer2 = new Assertion().setAction("update2")
                .setResource("table2").setRole("reader2");
        policyVer2.setAssertions(new ArrayList<>());
        policyVer2.getAssertions().add(assertionVer2);

        auditDetails.setLength(0);
        zms.dbService.auditLogPolicy(auditDetails, policyVersions, "delete-policy-versions");
        assertEquals(auditDetails.toString(), "{\"name\": \"policy1\", \"delete-policy-versions\": [" +
                "{\"name\": \"policy1\", \"version\": \"version1\", \"active\": \"null\", \"modified\": \"2021-08-24T10:48:12.416Z\", \"deleted-assertions\": [" +
                    "{\"role\": \"reader\", \"action\": \"update\", \"effect\": \"ALLOW\", \"resource\": \"table\"}]}," +
                "{\"name\": \"policy1\", \"version\": \"version2\", \"active\": \"null\", \"modified\": \"null\", \"deleted-assertions\": [" +
                    "{\"role\": \"reader2\", \"action\": \"update2\", \"effect\": \"ALLOW\", \"resource\": \"table2\"}]}]}");
    }

    @Test
    public void testExecutePutAssertionConditions() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        String domain = "assertion-conditions-dom";
        String policy = "assertion-conditions-pol";
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Domain dom = new Domain().setName(domain);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        Mockito.when(conn.getDomain(anyString())).thenReturn(dom);

        Map<String, AssertionConditionData> m1 = new HashMap<>();
        AssertionConditionData cd11 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("host1");
        m1.put("instances", cd11);
        AssertionConditionData cd12 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("ENFORCE");
        m1.put("enforcementState", cd12);
        AssertionConditionData cd13 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("1");
        m1.put("scope", cd13);
        AssertionCondition c1 = new AssertionCondition().setId(1).setConditionsMap(m1);

        Map<String, AssertionConditionData> m2 = new HashMap<>();
        AssertionConditionData cd21 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("host2");
        m2.put("instances", cd21);
        AssertionConditionData cd22 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("REPORT");
        m2.put("enforcementState", cd22);
        AssertionConditionData cd23 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("1");
        m2.put("scope", cd23);
        AssertionCondition c2 = new AssertionCondition().setId(2).setConditionsMap(m2);

        AssertionConditions ac1 = new AssertionConditions().setConditionsList(new ArrayList<>());
        ac1.getConditionsList().add(c1);
        ac1.getConditionsList().add(c2);

        Mockito.when(conn.insertAssertionConditions(1, ac1))
                .thenReturn(true).thenReturn(false)
                .thenThrow(new ResourceException(ResourceException.CONFLICT));

        int savedRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutAssertionConditions(mockDomRsrcCtx, domain, policy,
                    1L, ac1, auditRef, "PutAssertionConditions");
        }catch (ResourceException ignored){
            fail();
        }

        try {
            zms.dbService.executePutAssertionConditions(mockDomRsrcCtx, domain, policy,
                    1L, ac1, auditRef, "PutAssertionConditions");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.BAD_REQUEST);
        }


        try {
            zms.dbService.executePutAssertionConditions(mockDomRsrcCtx, domain, policy,
                    1L, ac1, auditRef, "PutAssertionConditions");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = savedRetryCount;
        zms.dbService.store = savedStore;
    }

    @Test
    public void testExecutePutAssertionCondition() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        String domain = "assertion-condition-dom";
        String policy = "assertion-condition-pol";
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Domain dom = new Domain().setName(domain);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        Mockito.when(conn.getDomain(anyString())).thenReturn(dom);
        Mockito.when(conn.getNextConditionId(anyLong(), anyString())).thenReturn(1);

        Map<String, AssertionConditionData> m1 = new HashMap<>();
        AssertionConditionData cd11 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("host1");
        m1.put("instances", cd11);
        AssertionConditionData cd12 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("ENFORCE");
        m1.put("enforcementState", cd12);
        AssertionConditionData cd13 = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("1");
        m1.put("scope", cd13);
        AssertionCondition c1 = new AssertionCondition().setConditionsMap(m1);

        Mockito.when(conn.insertAssertionCondition( 1, c1))
                .thenReturn(true) // no condition id in DB. insert works
                .thenReturn(false) // no condition id in DB. insert fails
                .thenReturn(true) // condition id in DB. insert works
                .thenReturn(false); // condition id in DB. insert fails

        // no condition id in the request. insertion is successful
        try {
            zms.dbService.executePutAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, c1, auditRef, "PutAssertionCondition");
        }catch (ResourceException ignored){
            fail();
        }

        // no condition id in the request. insertion failed
        c1.setId(null);
        try {
            zms.dbService.executePutAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, c1, auditRef, "PutAssertionCondition");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.BAD_REQUEST);
        }

        // condition id found in request
        Mockito.when(conn.deleteAssertionCondition(1, 1))
                .thenReturn(true) //delete works
                .thenReturn(false) // delete fails
                .thenReturn(true)
                .thenThrow(new ResourceException(ResourceException.CONFLICT));

        c1.setId(1);
        try {
            zms.dbService.executePutAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, c1, auditRef, "PutAssertionCondition");
        }catch (ResourceException ignored){
            fail();
        }
        c1.setId(1);
        try {
            zms.dbService.executePutAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, c1, auditRef, "PutAssertionCondition");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.NOT_FOUND);
        }

        try {
            zms.dbService.executePutAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, c1, auditRef, "PutAssertionCondition");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.BAD_REQUEST);
        }

        // retry test
        int savedRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        try {
            zms.dbService.executePutAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, c1, auditRef, "PutAssertionCondition");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = savedRetryCount;
        zms.dbService.store = savedStore;
    }

    @Test
    public void testExecuteDeleteAssertionConditions() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        String domain = "assertion-condition-dom";
        String policy = "assertion-condition-pol";
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Domain dom = new Domain().setName(domain);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        Mockito.when(conn.getDomain(anyString())).thenReturn(dom);
        List<AssertionCondition> acList = new ArrayList<>();
        Mockito.when(conn.getAssertionConditions(anyLong()))
                .thenReturn(acList).thenReturn(acList).thenReturn(null).thenReturn(acList);
        Mockito.when(conn.deleteAssertionConditions(anyLong()))
                .thenReturn(true).thenReturn(false)
                .thenThrow(new ResourceException(ResourceException.CONFLICT));

        int savedRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        //happy path
        try {
            zms.dbService.executeDeleteAssertionConditions(mockDomRsrcCtx, domain, policy,
                    1L, auditRef, "DeleteAssertionConditions");
        }catch (ResourceException ignored){
            fail();
        }
        //db call failed
        try {
            zms.dbService.executeDeleteAssertionConditions(mockDomRsrcCtx, domain, policy,
                    1L, auditRef, "DeleteAssertionConditions");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.NOT_FOUND);
        }

        // null assertion condition from db
        try {
            zms.dbService.executeDeleteAssertionConditions(mockDomRsrcCtx, domain, policy,
                    1L, auditRef, "DeleteAssertionConditions");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.NOT_FOUND);
        }

        try {
            zms.dbService.executeDeleteAssertionConditions(mockDomRsrcCtx, domain, policy,
                    1L, auditRef, "DeleteAssertionConditions");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = savedRetryCount;
        zms.dbService.store = savedStore;
    }

    @Test
    public void testExecuteDeleteAssertionCondition() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        String domain = "assertion-condition-dom";
        String policy = "assertion-condition-pol";
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        Domain dom = new Domain().setName(domain);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        Mockito.when(conn.getDomain(anyString())).thenReturn(dom);
        AssertionCondition ac = new AssertionCondition();
        ac.setConditionsMap(new HashMap<>());
        Mockito.when(conn.getAssertionCondition(anyLong(), anyInt()))
                .thenReturn(ac).thenReturn(ac).thenReturn(null).thenReturn(ac);
        Mockito.when(conn.deleteAssertionCondition(anyLong(), anyInt()))
                .thenReturn(true).thenReturn(false)
                .thenThrow(new ResourceException(ResourceException.CONFLICT));

        int savedRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        //happy path
        try {
            zms.dbService.executeDeleteAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, 1, auditRef, "DeleteAssertionCondition");
        }catch (ResourceException ignored){
            fail();
        }
        //db call failed
        try {
            zms.dbService.executeDeleteAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, 1, auditRef, "DeleteAssertionCondition");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.NOT_FOUND);
        }

        // null assertion condition from db
        try {
            zms.dbService.executeDeleteAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, 1, auditRef, "DeleteAssertionCondition");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.NOT_FOUND);
        }

        try {
            zms.dbService.executeDeleteAssertionCondition(mockDomRsrcCtx, domain, policy,
                    1L, 1, auditRef, "DeleteAssertionCondition");
            fail();
        }catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.CONFLICT);
        }

        zms.dbService.defaultRetryCount = savedRetryCount;
        zms.dbService.store = savedStore;
    }

    @Test
    public void testProcessGroupInsert() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Group group = new Group().setName("newGroup").setAuditEnabled(true);
        StringBuilder auditDetails = new StringBuilder("testAudit");
        zms.dbService.processGroup(conn, null, "sys.auth", "testGroup1",
                group, adminUser, auditRef, auditDetails);
        assertTrue(group.getAuditEnabled());
    }

    @Test
    public void testProcessGroupWithTagsInsert() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> groupTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        Group group = new Group().setName("newGroup").setTags(groupTags);
        Mockito.when(conn.insertGroup("sys.auth", group)).thenReturn(true);
        Mockito.when(conn.insertGroupTags("newGroup", "sys.auth", groupTags)).thenReturn(true);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processGroup(conn, null, "sys.auth", "newGroup",
                group, adminUser, auditRef, auditDetails);

        assertTrue(success);
    }

    @Test
    public void testProcessGroupWithTagsUpdate() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> groupTags = new HashMap<>();
        groupTags.put("tagToBeRemoved", new TagValueList().setList(Collections.singletonList("val0")));
        groupTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));

        Group group = new Group().setName("newGroup").setTags(groupTags);
        Mockito.when(conn.insertGroup(anyString(), any())).thenReturn(true);
        Mockito.when(conn.insertGroupTags("newGroup", "sys.auth", groupTags)).thenReturn(true);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processGroup(conn, null, "sys.auth", "newGroup",
                group, adminUser, auditRef, auditDetails);

        assertTrue(success);

        // new group
        Map<String, TagValueList> newGroupTags = new HashMap<>();
        newGroupTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));
        newGroupTags.put("newTagKey", new TagValueList().setList(Arrays.asList("val3", "val4")));
        newGroupTags.put("newTagKey2", new TagValueList().setList(Arrays.asList("val5", "val6")));

        Group newGroup = new Group().setName("newGroup").setTags(newGroupTags);

        Mockito.when(conn.updateGroup("sys.auth", newGroup)).thenReturn(true);
        Mockito.when(conn.deleteGroupTags(anyString(), anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertGroupTags(anyString(), anyString(), anyMap())).thenReturn(true);

        success = zms.dbService.processGroup(conn, group, "sys.auth", "newGroup",
                newGroup, adminUser, auditRef, auditDetails);

        assertTrue(success);

        // assert tags to remove
        Set<String> expectedTagsToBeRemoved = new HashSet<>(Collections.singletonList("tagToBeRemoved")) ;

        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> groupCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteGroupTags(groupCapture.capture(), domainCapture.capture(), tagCapture.capture());
        assertEquals("newGroup", groupCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        assertTrue(tagCapture.getValue().containsAll(expectedTagsToBeRemoved));

        // assert tags to add
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertGroupTags(groupCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals("newGroup", groupCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(1);
        assertTrue(resultInsertTags.keySet().containsAll(Arrays.asList("newTagKey", "newTagKey2")));
        assertTrue(resultInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("val3", "val4", "val5", "val6")));

        // assert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertTrue(resultFirstInsertTags.keySet().containsAll(Arrays.asList("tagKey", "tagToBeRemoved")));
        assertTrue(resultFirstInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("val0", "val1", "val2")));
    }

    @Test
    public void testGroupSameTagKeyValues() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> groupTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        Group group = new Group().setName("group").setTags(groupTags);
        Mockito.when(conn.insertGroup(anyString(), any())).thenReturn(true);
        Mockito.when(conn.insertGroupTags(anyString(), anyString(), any())).thenReturn(true);
        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processGroup(conn, null, "sys.auth", "newGroup",
                group, adminUser, auditRef, auditDetails);
        assertTrue(success);

        // process the same group again with the same tags
        Group newGroup = new Group().setName("group").setTags(groupTags);

        Mockito.when(conn.updateGroup("sys.auth", newGroup)).thenReturn(true);
        Mockito.when(conn.deleteGroupTags(anyString(), anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertGroupTags(anyString(), anyString(), anyMap())).thenReturn(true);

        success = zms.dbService.processGroup(conn, group, "sys.auth", "newGroup",
                newGroup, adminUser, auditRef, auditDetails);

        assertTrue(success);

        // assert tags to remove should be empty
        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> groupCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteGroupTags(groupCapture.capture(), domainCapture.capture(), tagCapture.capture());
        assertEquals("newGroup", groupCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        assertTrue(tagCapture.getValue().isEmpty());

        // assert tags to add should be empty
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertGroupTags(groupCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals("newGroup", groupCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(1);
        assertTrue(resultInsertTags.isEmpty());

        // asert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertTrue(resultFirstInsertTags.containsKey("tagKey"));
        assertTrue(resultFirstInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .contains("tagVal"));

    }

    @Test
    public void testUpdateGroupMetaWithoutTag() {
        final String domainName = "sys.auth";
        final String updateGroupMetaTag = "tag-key-update-group-meta-without-tag";
        final List<String> updateGroupMetaTagValues = Collections.singletonList("update-meta-value");
        final String groupName = "groupWithTagUpdateMeta";
        ObjectStore savedStore = zms.dbService.store;

        Group group = new Group().setName(groupName);
        GroupMeta rm = new GroupMeta()
                .setTags(Collections.singletonMap(updateGroupMetaTag,
                        new TagValueList().setList(updateGroupMetaTagValues)));

        // mock dbService store
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.updateGroup(any(), any())).thenReturn(true);
        Mockito.when(conn.getGroup(domainName, groupName)).thenReturn(group);
        Mockito.when(conn.insertGroupTags(anyString(), anyString(), anyMap())).thenReturn(true);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        zms.dbService.store = mockObjStore;

        // update group meta
        Group originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
        zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName , groupName, originalGroup, rm, auditRef);

        // assert tags to add contains group meta tags
        ArgumentCaptor<String> groupCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);

        Mockito.verify(conn, times(1)).insertGroupTags(groupCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals(groupName, groupCapture.getValue());
        assertEquals(domainName, domainCapture.getValue());

        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(0);
        TagValueList tagValues = resultInsertTags.get(updateGroupMetaTag);
        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(updateGroupMetaTagValues));
        zms.dbService.store = savedStore;
    }

    @Test
    public void testUpdateGroupMetaWithExistingTag() {
        final String domainName = "sys.auth";
        final String initialTagKey = "initial-tag-key";
        final List<String> initialTagValues = Collections.singletonList("initial-tag-value");
        final String updateGroupMetaTag = "tag-key-update-group-meta-exist-tag";
        final List<String> updateGroupMetaTagValues = Collections.singletonList("update-meta-value");
        final String groupName = "groupWithTagUpdateMeta";
        ObjectStore savedStore = zms.dbService.store;

        // initial group with tags
        Group group = new Group().setName(groupName);

        // initial group tags
        Map<String, TagValueList> initialGroupTag = Collections.singletonMap(initialTagKey,
                new TagValueList().setList(initialTagValues));

        // group meta with updated tags
        GroupMeta gm = new GroupMeta()
                .setTags(Collections.singletonMap(updateGroupMetaTag,
                        new TagValueList().setList(updateGroupMetaTagValues)));

        // mock dbService store
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.updateGroup(any(), any())).thenReturn(true);
        Mockito.when(conn.deleteGroupTags(anyString(), anyString(), anySet())).thenReturn(true);
        Mockito.when(conn.insertGroupTags(anyString(), anyString(), anyMap())).thenReturn(true);
        Mockito.when(conn.getGroup(domainName, groupName)).thenReturn(group);
        Mockito.when(conn.getGroupTags(domainName, groupName)).thenReturn(initialGroupTag);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        zms.dbService.store = mockObjStore;

        // update group meta
        Group originalGroup = zms.dbService.getGroup(domainName, groupName, false, false);
        zms.dbService.executePutGroupMeta(mockDomRsrcCtx, domainName , groupName, originalGroup, gm, auditRef);

        // assert tags to removed
        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> groupCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deleteGroupTags(groupCapture.capture(), domainCapture.capture(), tagCapture.capture());
        assertEquals(groupName, groupCapture.getValue());
        assertEquals(domainName, domainCapture.getValue());
        assertTrue(tagCapture.getValue().contains(initialTagKey));

        // assert tags to add
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(1)).insertGroupTags(groupCapture.capture(), domainCapture.capture(), tagInsertCapture.capture());
        assertEquals(groupName, groupCapture.getValue());
        assertEquals(domainName, domainCapture.getValue());

        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(0);
        TagValueList tagValues = resultInsertTags.get(updateGroupMetaTag);
        assertNotNull(tagValues);
        assertTrue(tagValues.getList().containsAll(updateGroupMetaTagValues));
        zms.dbService.store = savedStore;
    }

    @Test
    public void testExecuteDeleteAllExpiredRoleMemberships() {

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        ObjectStore savedStore = zms.dbService.store;
        DynamicConfigInteger savedMaxDbCallConfig = zms.dbService.purgeMembersMaxDbCallsPerRun;
        DynamicConfigInteger savedLimitConfig = zms.dbService.purgeMembersLimitPerCall;

        zms.dbService.store = mockObjStore;

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        Mockito.when(conn.deleteExpiredRoleMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), anyString())).thenReturn(true);

        List<ExpiryMember> purgeMemberList;
        ExpiryMember member1 = new ExpiryMember().setDomainName("dom1").setCollectionName("role1")
                .setPrincipalName("user.test1").setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member2 = new ExpiryMember().setDomainName("dom1").setCollectionName("role1")
                .setPrincipalName("user.test2").setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member3 = new ExpiryMember().setDomainName("dom1").setCollectionName("role2")
                .setPrincipalName("user.test3").setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member4 = new ExpiryMember().setDomainName("dom2").setCollectionName("role3")
                .setPrincipalName("user.test4").setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member5 = new ExpiryMember().setDomainName("dom2").setCollectionName("role1")
                .setPrincipalName("user.test3").setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member6 = new ExpiryMember().setDomainName("dom3").setCollectionName("role4")
                .setPrincipalName("user.test5").setExpiration(Timestamp.fromMillis(100));

        purgeMemberList = List.of(member1, member2, member3, member4, member5, member6);
        Mockito.when(conn.getAllExpiredRoleMembers(ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF, 0, 180)).thenReturn(purgeMemberList);
        zms.dbService.executeDeleteAllExpiredRoleMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(1)).getAllExpiredRoleMembers(anyInt(), anyInt(), anyInt());
        Mockito.verify(conn, times(6)).deleteExpiredRoleMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));

        // needs more than one call for delete all expired group members

        Mockito.clearInvocations(conn);

        zms.dbService.purgeMembersLimitPerCall = new DynamicConfigInteger(4);

        Mockito.when(conn.getAllExpiredRoleMembers(4, 0, 180)).thenReturn(List.of(member1, member2, member3, member4));
        Mockito.when(conn.getAllExpiredRoleMembers(4, 4, 180)).thenReturn(List.of(member5, member6));

        zms.dbService.executeDeleteAllExpiredRoleMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(2)).getAllExpiredRoleMembers(anyInt(), anyInt(), anyInt());
        Mockito.verify(conn, times(6)).deleteExpiredRoleMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));

        Mockito.clearInvocations(conn);

        zms.dbService.purgeMembersLimitPerCall = new DynamicConfigInteger(3);

        Mockito.when(conn.getAllExpiredRoleMembers(3, 0, 180)).thenReturn(List.of(member1, member2, member3));
        Mockito.when(conn.getAllExpiredRoleMembers(3, 3, 180)).thenReturn(List.of(member4, member5, member6));
        Mockito.when(conn.getAllExpiredRoleMembers(3, 6, 180)).thenReturn(List.of());

        zms.dbService.executeDeleteAllExpiredRoleMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(3)).getAllExpiredRoleMembers(anyInt(), anyInt(), anyInt());
        Mockito.verify(conn, times(6)).deleteExpiredRoleMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));

        // not delete all because expired_members > num_of_db_call * limit_per_call

        Mockito.clearInvocations(conn);

        zms.dbService.purgeMembersMaxDbCallsPerRun = new DynamicConfigInteger(2);
        zms.dbService.purgeMembersLimitPerCall = new DynamicConfigInteger(2);

        Mockito.when(conn.getAllExpiredRoleMembers(2, 0, 180)).thenReturn(List.of(member1, member2));
        Mockito.when(conn.getAllExpiredRoleMembers(2, 2, 180)).thenReturn(List.of(member3, member4));
        // third iteration - should not happen
        Mockito.when(conn.getAllExpiredRoleMembers(2, 4, 180)).thenReturn(List.of(member5, member6));

        zms.dbService.executeDeleteAllExpiredRoleMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(2)).getAllExpiredRoleMembers(anyInt(), anyInt(), anyInt());
        Mockito.verify(conn, times(4)).deleteExpiredRoleMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));

        zms.dbService.purgeMembersMaxDbCallsPerRun = savedMaxDbCallConfig;
        zms.dbService.purgeMembersLimitPerCall = savedLimitConfig;
        zms.dbService.store = savedStore;
    }

    @Test
    public void testExecuteDeleteAllExpiredRoleMembershipsDeleteMemberFailure() {

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ExpiryMember member1 = new ExpiryMember().setDomainName("dom1").setCollectionName("role1")
                .setPrincipalName("user.test1").setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member2 = new ExpiryMember().setDomainName("dom1").setCollectionName("role1")
                .setPrincipalName("user.test2").setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member3 = new ExpiryMember().setDomainName("dom1").setCollectionName("role2")
                .setPrincipalName("user.test3").setExpiration(Timestamp.fromMillis(100));
        List<ExpiryMember> purgeMemberList = List.of(member1, member2, member3);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        Mockito.when(conn.getAllExpiredRoleMembers(ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF, 0, 180)).thenReturn(purgeMemberList);
        Mockito.when(conn.deleteExpiredRoleMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), anyString())).thenReturn(true).thenReturn(false).thenReturn(true);

        /*  Added an appender to the db service logger, so when deleting expired role members,
         this appender allows seeing whether an error was recorded in the log file. */

        int[] deleteFailureCount = new int[1];
        Logger dbServiceLogger = (Logger)LoggerFactory.getLogger(DBService.class);
        AppenderBase testAppender = new AppenderBase() {
            @Override
            protected void append(Object o) {
                if (o instanceof LoggingEvent) {
                    String message = ((LoggingEvent) o).getMessage();
                    if (message.startsWith("failed to delete expired role member")) {
                        deleteFailureCount[0]++;
                    }
                }
            }
        };
        testAppender.start();
        dbServiceLogger.addAppender(testAppender);

        zms.dbService.executeDeleteAllExpiredRoleMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(3)).deleteExpiredRoleMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));
        assertEquals(deleteFailureCount[0], 1);

        testAppender.stop();
        dbServiceLogger.detachAppender(testAppender);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testExecuteDeleteAllExpiredRoleMembershipsConnectionFailure() {

        ObjectStore mockObjStore = Mockito.mock(ObjectStore.class);
        ObjectStore saveStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int saveRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
                .thenThrow(new ResourceException(500, "DB Error"));

        try {
            zms.dbService.executeDeleteAllExpiredRoleMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 500);
        }

        zms.dbService.store = saveStore;
        zms.dbService.defaultRetryCount = saveRetryCount;
    }

    @Test
    public void testExecuteDeleteAllExpiredGroupMemberships() {

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        ObjectStore savedStore = zms.dbService.store;
        DynamicConfigInteger savedMaxDbCallConfig = zms.dbService.purgeMembersMaxDbCallsPerRun;
        DynamicConfigInteger savedLimitConfig = zms.dbService.purgeMembersLimitPerCall;

        zms.dbService.store = mockObjStore;

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        Mockito.when(conn.deleteExpiredGroupMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), anyString())).thenReturn(true);

        ExpiryMember member1 = new ExpiryMember()
                .setDomainName("dom1")
                .setCollectionName("group1")
                .setPrincipalName("user.test1")
                .setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member2 = new ExpiryMember()
                .setDomainName("dom1")
                .setCollectionName("group1")
                .setPrincipalName("user.test2")
                .setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member3 = new ExpiryMember()
                .setDomainName("dom1")
                .setCollectionName("group2")
                .setPrincipalName("user.test3")
                .setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member4 = new ExpiryMember()
                .setDomainName("dom2")
                .setCollectionName("group3")
                .setPrincipalName("user.test4")
                .setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member5 = new ExpiryMember()
                .setDomainName("dom2")
                .setCollectionName("group1")
                .setPrincipalName("user.test3")
                .setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member6 = new ExpiryMember()
                .setDomainName("dom3")
                .setCollectionName("group4")
                .setPrincipalName("user.test4")
                .setExpiration(Timestamp.fromMillis(100));
        List<ExpiryMember> purgeMemberList = List.of(member1, member2, member3, member4, member5, member6);

        Mockito.when(conn.getAllExpiredGroupMembers(ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF, 0, 180)).thenReturn(purgeMemberList);
        zms.dbService.executeDeleteAllExpiredGroupMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(1)).getAllExpiredGroupMembers(anyInt(), anyInt(), anyInt());
        Mockito.verify(conn, times(6)).deleteExpiredGroupMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));

        // needs more than one call for delete all expired group members

        Mockito.clearInvocations(conn);

        zms.dbService.purgeMembersLimitPerCall = new DynamicConfigInteger(4);

        Mockito.when(conn.getAllExpiredGroupMembers(4, 0, 180)).thenReturn(List.of(member1, member2, member3, member4));
        Mockito.when(conn.getAllExpiredGroupMembers(4, 4, 180)).thenReturn(List.of(member5, member6));

        zms.dbService.executeDeleteAllExpiredGroupMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(2)).getAllExpiredGroupMembers(anyInt(), anyInt(), anyInt());
        Mockito.verify(conn, times(6)).deleteExpiredGroupMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));

        Mockito.clearInvocations(conn);

        zms.dbService.purgeMembersLimitPerCall = new DynamicConfigInteger(3);

        Mockito.when(conn.getAllExpiredGroupMembers(3, 0, 180)).thenReturn(List.of(member1, member2, member3));
        Mockito.when(conn.getAllExpiredGroupMembers(3, 3, 180)).thenReturn(List.of(member4, member5, member6));
        Mockito.when(conn.getAllExpiredGroupMembers(3, 6, 180)).thenReturn(List.of());

        zms.dbService.executeDeleteAllExpiredGroupMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(3)).getAllExpiredGroupMembers(anyInt(), anyInt(), anyInt());
        Mockito.verify(conn, times(6)).deleteExpiredGroupMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));

        // not delete all because expired_members > num_of_db_call * limit_per_call

        Mockito.clearInvocations(conn);

        zms.dbService.purgeMembersMaxDbCallsPerRun = new DynamicConfigInteger(2);
        zms.dbService.purgeMembersLimitPerCall = new DynamicConfigInteger(2);

        Mockito.when(conn.getAllExpiredGroupMembers(2, 0, 180)).thenReturn(List.of(member1, member2));
        Mockito.when(conn.getAllExpiredGroupMembers(2, 2, 180)).thenReturn(List.of(member3, member4));
        // third iteration - should not happen
        Mockito.when(conn.getAllExpiredGroupMembers(2, 4, 180)).thenReturn(List.of(member5, member6));

        zms.dbService.executeDeleteAllExpiredGroupMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(2)).getAllExpiredGroupMembers(anyInt(), anyInt(), anyInt());
        Mockito.verify(conn, times(4)).deleteExpiredGroupMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));

        zms.dbService.purgeMembersMaxDbCallsPerRun = savedMaxDbCallConfig;
        zms.dbService.purgeMembersLimitPerCall = savedLimitConfig;
        zms.dbService.store = savedStore;
    }

    @Test
    public void testExecuteDeleteAllExpiredMembershipsEmptySet() {
        DynamicConfigInteger savedExpiryDays = zms.dbService.purgeMemberExpiryDays;
        zms.dbService.purgeMemberExpiryDays = new DynamicConfigInteger(0);

        List<ExpiryMember> members = zms.dbService.executeDeleteAllExpiredRoleMemberships(mockDomRsrcCtx,
                auditRef, "deleteExpiredMembers");
        assertTrue(members.isEmpty());

        members = zms.dbService.executeDeleteAllExpiredGroupMemberships(mockDomRsrcCtx,
                auditRef, "deleteExpiredMembers");
        assertTrue(members.isEmpty());
        zms.dbService.purgeMemberExpiryDays = savedExpiryDays;
    }

    @Test
    public void testExecuteDeleteAllExpiredGroupMembershipsDeleteMemberFailure() {

        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;

        ExpiryMember member1 = new ExpiryMember()
                .setDomainName("dom1")
                .setCollectionName("group1")
                .setPrincipalName("user.test1")
                .setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member2 = new ExpiryMember()
                .setDomainName("dom1")
                .setCollectionName("group1")
                .setPrincipalName("user.test2")
                .setExpiration(Timestamp.fromMillis(100));
        ExpiryMember member3 = new ExpiryMember()
                .setDomainName("dom1")
                .setCollectionName("group2")
                .setPrincipalName("user.test3")
                .setExpiration(Timestamp.fromMillis(100));
        List<ExpiryMember> purgeMemberList = List.of(member1, member2, member3);

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(conn);
        Mockito.when(conn.getAllExpiredGroupMembers(ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF, 0, 180)).thenReturn(purgeMemberList);
        Mockito.when(conn.deleteExpiredGroupMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), anyString())).thenReturn(true).thenReturn(false).thenReturn(true);

        /*  Added an appender to the db service logger, so when deleting expired group members,
         this appender allows seeing whether an error was recorded in the log file. */

        int[] deleteFailureCount = new int[1];
        Logger dbServiceLogger = (Logger)LoggerFactory.getLogger(DBService.class);
        AppenderBase testAppender = new AppenderBase() {
            @Override
            protected void append(Object o) {
                if (o instanceof LoggingEvent) {
                    String message= ((LoggingEvent) o).getMessage();
                    if (message.startsWith("failed to delete expired group member")) {
                        deleteFailureCount[0]++;
                    }
                }
            }
        };
        testAppender.start();
        dbServiceLogger.addAppender(testAppender);

        zms.dbService.executeDeleteAllExpiredGroupMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
        Mockito.verify(conn, times(3)).deleteExpiredGroupMember(anyString(), anyString(), anyString(), anyString(),
                eq(Timestamp.fromMillis(100)), eq(auditRef));
        assertEquals(deleteFailureCount[0], 1);

        testAppender.stop();
        dbServiceLogger.detachAppender(testAppender);
        zms.dbService.store = savedStore;
    }

    @Test
    public void testExecuteDeleteAllExpiredGroupMembershipsConnectionFailure() {

        ObjectStore mockObjStore = Mockito.mock(ObjectStore.class);
        ObjectStore savedStore = zms.dbService.store;
        zms.dbService.store = mockObjStore;
        int savedRetryCount = zms.dbService.defaultRetryCount;
        zms.dbService.defaultRetryCount = 2;

        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean()))
                .thenThrow(new ResourceException(500, "DB Error"));

        try {
            zms.dbService.executeDeleteAllExpiredGroupMemberships(mockDomRsrcCtx, auditRef, "deleteExpiredMembers");
            fail();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 500);
        }

        zms.dbService.store = savedStore;
        zms.dbService.defaultRetryCount = savedRetryCount;
    }

    @Test
    public void testAssertionDomainCheck() {
        assertNull(zms.dbService.assertionDomainCheck("", "resource.value"));
        assertNull(zms.dbService.assertionDomainCheck("", ":resource.value"));
        assertNull(zms.dbService.assertionDomainCheck("role.value", "athenz:resource.value"));
        assertNull(zms.dbService.assertionDomainCheck(":role.value", "athenz:resource.value"));
        assertNull(zms.dbService.assertionDomainCheck("ads:role.value", "athenz:resource.value"));
        assertNull(zms.dbService.assertionDomainCheck("sports:role.value", "athenz:resource.value"));
        assertEquals("athenz", zms.dbService.assertionDomainCheck("athenz:role.value", "athenz:resource.value"));
    }

    @Test
    public void testProcessNoTags() {
        assertTrue(zms.dbService.processUpdateTags(null, null, null, null, null));
        assertTrue(zms.dbService.processUpdateTags(Collections.emptyMap(), null, null, null, null));
        assertTrue(zms.dbService.processUpdateTags(null, Collections.emptyMap(), null, null, null));
        assertTrue(zms.dbService.processUpdateTags(Collections.emptyMap(), Collections.emptyMap(), null, null, null));
    }

    private AssertionCondition createAssertionConditionObject(Integer conditionId, String key, String value) {
        Map<String, AssertionConditionData> map = new HashMap<>();
        AssertionConditionData cd = new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue(value);
        map.put(key, cd);
        return new AssertionCondition().setId(conditionId).setConditionsMap(map);
    }

    @Test
    public void testMapAssertionsToConditions() {
        Map<Long, List<AssertionCondition>> assertionConditionsMap = new HashMap<>();
        zms.dbService.mapAssertionsToConditions(null, assertionConditionsMap);
        assertTrue(assertionConditionsMap.isEmpty());
        List<Assertion> assertions = new ArrayList<>();
        zms.dbService.mapAssertionsToConditions(assertions, assertionConditionsMap);
        assertTrue(assertionConditionsMap.isEmpty());

        Assertion a1 = new Assertion().setId(1L);
        assertions.add(a1);

        AssertionCondition ac1 = createAssertionConditionObject(1, "test1", "test1");
        AssertionCondition ac2 = createAssertionConditionObject(2, "test2", "test2");
        Assertion a2 = new Assertion().setId(2L).setConditions(
                new AssertionConditions()
                        .setConditionsList(List.of(ac1, ac2))
        );
        assertions.add(a2);

        AssertionCondition ac3 = createAssertionConditionObject(1, "test3", "test3");
        Assertion a3 = new Assertion().setId(3L).setConditions(
                new AssertionConditions()
                        .setConditionsList(List.of(ac3))
        );
        assertions.add(a3);

        zms.dbService.mapAssertionsToConditions(assertions, assertionConditionsMap);
        assertEquals(assertionConditionsMap.size(), 2);
        assertEquals(assertionConditionsMap.get(2L), List.of(ac1, ac2));
        assertEquals(assertionConditionsMap.get(3L), List.of(ac3));

    }

    @Test
    public void testIsAssertionConditionsHasChanged() {
        List<AssertionCondition> list1 = null;
        List<AssertionCondition> list2 = null;
        assertFalse(zms.dbService.isAssertionConditionsHasChanged(list1, list2));

        list1 = new ArrayList<>();
        list1.add(createAssertionConditionObject(1, "test1", "test1"));
        assertTrue(zms.dbService.isAssertionConditionsHasChanged(list1, list2));

        list2 = new ArrayList<>();
        list2.add(createAssertionConditionObject(null, "test1", "test1"));
        assertFalse(zms.dbService.isAssertionConditionsHasChanged(list1, list2));

        list1.add(createAssertionConditionObject(2, "test2", "test2"));
        list2.add(createAssertionConditionObject(null, "test2", "test2"));
        assertFalse(zms.dbService.isAssertionConditionsHasChanged(list1, list2));

        list1.add(createAssertionConditionObject(3, "test3", "test3"));
        assertTrue(zms.dbService.isAssertionConditionsHasChanged(list1, list2));

        list2.add(createAssertionConditionObject(null, "test4", "test4"));
        assertTrue(zms.dbService.isAssertionConditionsHasChanged(list1, list2));
    }

    @Test
    public void testProcessPolicyConReturnFalse() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);


        Policy policy = new Policy().setName("newPolicy");

        Assertion policyAssertion = new Assertion();
        policy.setAssertions(new LinkedList<>(Collections.singletonList(policyAssertion)));
        Mockito.when(conn.insertAssertion("sys.auth", "newPolicy", null, policyAssertion)).thenReturn(false).thenReturn(true);
        Mockito.when(conn.insertPolicy("sys.auth", policy)).thenReturn(true).thenReturn(true);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processPolicy(conn, null, "sys.auth", "newPolicy",
                policy, false, auditDetails);

        assertFalse(success);

    }

    @Test
    public void testProcessPolicyAssertionConditionsConReturnFalse() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Policy policy = new Policy().setName("newPolicy");

        Assertion policyAssertion = new Assertion()
                .setId(1L)
                .setAction("testAction")
                .setResource("sys.auth:testResource")
                .setRole("sys.auth:role.testRole")
                .setEffect(AssertionEffect.ALLOW)
                .setConditions(
                        new AssertionConditions()
                                .setConditionsList(List.of(createAssertionConditionObject(1, "test1", "test1")))
                );

        policy.setAssertions(new LinkedList<>(Collections.singletonList(policyAssertion)));
        Mockito.when(conn.insertAssertionConditions(1L, policyAssertion.getConditions())).thenReturn(false).thenReturn(true);
        Mockito.when(conn.insertAssertion("sys.auth", "newPolicy", null, policyAssertion)).thenReturn(true).thenReturn(true);
        Mockito.when(conn.insertPolicy("sys.auth", policy)).thenReturn(true).thenReturn(true);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processPolicy(conn, null, "sys.auth", "newPolicy",
                policy, false, auditDetails);
        assertFalse(success);

        Policy oldPolicy = new Policy().setName("oldPolicy");
        Assertion oldPolicyAssertion = new Assertion()
                .setId(1L)
                .setAction("testAction")
                .setResource("sys.auth:testResource")
                .setRole("sys.auth:role.testRole")
                .setEffect(AssertionEffect.ALLOW);
        oldPolicy.setAssertions(new LinkedList<>(Collections.singletonList(oldPolicyAssertion)));
        Mockito.when(conn.updatePolicy("sys.auth", policy)).thenReturn(true).thenReturn(true);
        Mockito.when(conn.insertAssertion("sys.auth", "newPolicy", null, policyAssertion)).thenReturn(true).thenReturn(true);
        Mockito.when(conn.insertAssertionConditions(1L, policyAssertion.getConditions())).thenReturn(false).thenReturn(true);
        success = zms.dbService.processPolicy(conn, oldPolicy, "sys.auth", "newPolicy",
                policy, false, auditDetails);
        assertFalse(success);

        oldPolicy.setAssertions(policy.getAssertions());
        policy.setAssertions(new LinkedList<>(Collections.singletonList(oldPolicyAssertion)));
        Mockito.when(conn.updatePolicy("sys.auth", policy)).thenReturn(true).thenReturn(true);
        Mockito.when(conn.deleteAssertionConditions(1L)).thenReturn(false).thenReturn(true);
        success = zms.dbService.processPolicy(conn, oldPolicy, "sys.auth", "newPolicy",
                policy, false, auditDetails);
        assertFalse(success);


    }
    @Test
    public void testProcessPolicyWithTagsInsert() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> policyTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        Policy policy = new Policy().setName("newPolicy").setTags(policyTags);
        Mockito.when(conn.insertPolicy("sys.auth", policy)).thenReturn(true).thenReturn(true);
        Mockito.when(conn.insertPolicyTags("newPolicy", "sys.auth", policyTags, null)).thenReturn(true).thenReturn(false);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processPolicy(conn, null, "sys.auth", "newPolicy",
                policy, false, auditDetails);

        ArgumentCaptor<String> policyCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> versionCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Map<String, TagValueList>> tagCapture = ArgumentCaptor.forClass(Map.class);

        Mockito.verify(conn, times(1)).insertPolicyTags(policyCapture.capture(), domainCapture.capture(), tagCapture.capture(), versionCapture.capture());
        assertTrue(tagCapture.getValue().containsKey("tagKey"));
        assertTrue(tagCapture.getValue().values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("tagVal")));

        assertTrue(success);
    }

    @Test
    public void testProcessPolicyWithTagsUpdate() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> policyTags = new HashMap<>();
        policyTags.put("tagToBeRemoved", new TagValueList().setList(Collections.singletonList("val0")));
        policyTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));

        Policy policy = new Policy().setName("newPolicy").setTags(policyTags);
        Mockito.when(conn.insertPolicy(anyString(), any())).thenReturn(true);
        Mockito.when(conn.insertPolicyTags("newPolicy", "sys.auth", policyTags, null)).thenReturn(true);

        StringBuilder auditDetails = new StringBuilder("testAudit");
        boolean success = zms.dbService.processPolicy(conn, null, "sys.auth", "newPolicy",
                policy, false, auditDetails);

        assertTrue(success);

        // new policy
        Map<String, TagValueList> newPolicyTags = new HashMap<>();
        newPolicyTags.put("tagKey", new TagValueList().setList(Arrays.asList("val1", "val2")));
        newPolicyTags.put("newTagKey", new TagValueList().setList(Arrays.asList("val3", "val4")));
        newPolicyTags.put("newTagKey2", new TagValueList().setList(Arrays.asList("val5", "val6")));

        Policy newPolicy = new Policy().setName("newPolicy").setTags(newPolicyTags);

        Mockito.when(conn.updatePolicy("sys.auth", newPolicy)).thenReturn(true);
        Mockito.when(conn.deletePolicyTags(anyString(), anyString(), anySet(), any())).thenReturn(true);
        Mockito.when(conn.insertPolicyTags(anyString(), anyString(), anyMap(), any())).thenReturn(true);


        success = zms.dbService.processPolicy(conn, policy, "sys.auth", "newPolicy",
                newPolicy, false, auditDetails);

        assertTrue(success);

        // assert tags to remove
        Set<String> expectedTagsToBeRemoved = new HashSet<>(Collections.singletonList("tagToBeRemoved")) ;

        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> policyCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> versionCapture = ArgumentCaptor.forClass(String.class);

        Mockito.verify(conn, times(1)).deletePolicyTags(policyCapture.capture(), domainCapture.capture(), tagCapture.capture(), versionCapture.capture());
        assertEquals("newPolicy", policyCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        assertTrue(tagCapture.getValue().containsAll(expectedTagsToBeRemoved));

        // assert tags to add
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertPolicyTags(policyCapture.capture(), domainCapture.capture(), tagInsertCapture.capture(), versionCapture.capture());
        assertEquals("newPolicy", policyCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(1);
        assertTrue(resultInsertTags.keySet().containsAll(Arrays.asList("newTagKey", "newTagKey2")));
        assertTrue(resultInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("val3", "val4", "val5", "val6")));

        // assert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertTrue(resultFirstInsertTags.keySet().containsAll(Arrays.asList("tagKey", "tagToBeRemoved")));
        assertTrue(resultFirstInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .containsAll(Arrays.asList("val0", "val1", "val2")));
    }

    @Test
    public void testProcessPolicyUpdateTagKeyValues() {
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);

        Map<String, TagValueList> policyTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(Collections.singletonList("tagVal"))
        );
        Policy policy = new Policy().setName("policy").setTags(policyTags);
        Mockito.when(conn.insertPolicy(anyString(), any())).thenReturn(true);
        Mockito.when(conn.insertPolicyTags(anyString(), anyString(), any(), any())).thenReturn(true);
        StringBuilder auditDetails = new StringBuilder("testAudit");

        boolean success = zms.dbService.processPolicy(conn, null, "sys.auth", "newPolicy",
                policy, false, auditDetails);

        assertTrue(success);

        Map<String, TagValueList> newPolicyTags = Collections.singletonMap(
                "tagKey", new TagValueList().setList(List.of("tagVal3", "tagVal2"))
        );
        // process the same policy again with the same tags
        Policy newPolicy = new Policy().setName("policy").setTags(newPolicyTags);

        Mockito.when(conn.updatePolicy("sys.auth", newPolicy)).thenReturn(true);
        Mockito.when(conn.deletePolicyTags(anyString(), anyString(), anySet(), any())).thenReturn(true);
        Mockito.when(conn.insertPolicyTags(anyString(), anyString(), anyMap(), any())).thenReturn(true);

        success = zms.dbService.processPolicy(conn, policy, "sys.auth", "policy",
                newPolicy, false, auditDetails);

        assertTrue(success);

        // assert tags to remove should be empty
        ArgumentCaptor<Set<String>> tagCapture = ArgumentCaptor.forClass(Set.class);
        ArgumentCaptor<String> policyCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domainCapture = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> versionCapture = ArgumentCaptor.forClass(String.class);


        Mockito.verify(conn, times(1)).deletePolicyTags(policyCapture.capture(), domainCapture.capture(), tagCapture.capture(), versionCapture.capture());
        assertEquals("policy", policyCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        assertTrue(tagCapture.getValue().contains("tagKey"));

        // assert tags to add should be empty
        ArgumentCaptor<Map<String, TagValueList>> tagInsertCapture = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(conn, times(2)).insertPolicyTags(policyCapture.capture(), domainCapture.capture(), tagInsertCapture.capture(), versionCapture.capture());
        assertEquals("policy", policyCapture.getValue());
        assertEquals("sys.auth", domainCapture.getValue());
        Map<String, TagValueList> resultInsertTags = tagInsertCapture.getAllValues().get(1);
        assertEquals(resultInsertTags, newPolicyTags);

        // assert first tag insertion
        Map<String, TagValueList> resultFirstInsertTags = tagInsertCapture.getAllValues().get(0);
        assertTrue(resultFirstInsertTags.containsKey("tagKey"));
        assertTrue(resultFirstInsertTags.values().stream()
                .flatMap(l -> l.getList().stream())
                .collect(Collectors.toList())
                .contains("tagVal"));

    }

    @Test
    public void testGetAthenzDomainFromLcoalCache() {

        String domainName = "local-cache-domain";
        Map<String, AthenzDomain> cache = new HashMap<>();

        // unknown domains will return null and not exceptions

        assertNull(zms.dbService.getAthenzDomainFromLocalCache(cache, domainName));

        // now let's add the domain

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        // verify we get a valid domain object. it must also be in our cache now

        assertNotNull(zms.dbService.getAthenzDomainFromLocalCache(cache, domainName));
        assertNotNull(cache.get(domainName));

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testGetDelegatedMemberRole() {

        String domainName = "delegated-role-domain";
        Map<String, AthenzDomain> cache = new HashMap<>();
        MemberRole memberRole = new MemberRole().setDomainName(domainName).setRoleName("delegated-role");

        // unknown domains will return null and not exceptions

        assertNull(zms.dbService.getDelegatedMemberRole(cache, memberRole));

        // now let's add the domain

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        // create an empty policy with no assertions

        Policy policy1 = new Policy().setName(ResourceUtils.policyResourceName(domainName, "no-assertion"))
                .setActive(true).setVersion("0");
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, "no-assertion", policy1,
                auditRef, "unit-test", false);

        // create an inactive policy

        Policy policy2 = new Policy().setName(ResourceUtils.policyResourceName(domainName, "inactive"))
                .setActive(true).setVersion("0");
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, "inactive", policy2,
                auditRef, "unit-test", false);

        policy2.setActive(false).setVersion("1");
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, "inactive", policy2,
                auditRef, "unit-test", false);

        // create an assume role policy with a different role

        Policy policy3 = createPolicyObject(domainName, "assume-role-policy",
                "non-matching-role", true, "assume_role", "sports:role.test", AssertionEffect.ALLOW, null, true);
        zms.dbService.executePutPolicy(mockDomRsrcCtx, domainName, "assume-role-policy", policy3,
                auditRef, "unit-test", false);

        // with no assume role policies we get an empty set

        List<MemberRole> roleList = zms.dbService.getDelegatedMemberRole(cache, memberRole);
        assertTrue(roleList.isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testGetDelegatedRoleNamesNullCases() {

        // resource name does not contain :

        Map<String, AthenzDomain> cache = new HashMap<>();
        assertNull(zms.dbService.getDelegatedRoleNames(cache, "resource", "trust-domain"));

        // resource starts with * but not role object

        assertNull(zms.dbService.getDelegatedRoleNames(cache, "*:service", "trust-domain"));

        // unknown domain

        assertNull(zms.dbService.getDelegatedRoleNames(cache, "unknown-domain:role.trust-role", "trust-domain"));
    }

    @Test
    public void testMinReviewDays() {
        ReviewObject object = new ReviewObject().setServiceReviewDays(50);
        assertEquals(zms.dbService.minReviewDays(object), 50);

        object.setMemberReviewDays(60);
        assertEquals(zms.dbService.minReviewDays(object), 50);
        object.setMemberReviewDays(45);
        assertEquals(zms.dbService.minReviewDays(object), 45);

        object.setGroupReviewDays(46);
        assertEquals(zms.dbService.minReviewDays(object), 45);
        object.setGroupReviewDays(40);
        assertEquals(zms.dbService.minReviewDays(object), 40);

        object.setMemberExpiryDays(41);
        assertEquals(zms.dbService.minReviewDays(object), 40);
        object.setMemberExpiryDays(35);
        assertEquals(zms.dbService.minReviewDays(object), 35);

        object.setServiceExpiryDays(36);
        assertEquals(zms.dbService.minReviewDays(object), 35);
        object.setServiceExpiryDays(30);
        assertEquals(zms.dbService.minReviewDays(object), 30);

        object.setGroupExpiryDays(31);
        assertEquals(zms.dbService.minReviewDays(object), 30);
        object.setMemberReviewDays(25);
        assertEquals(zms.dbService.minReviewDays(object), 25);
    }

    @Test
    public void testFilterObjectsForReview() {

        // we're specifying an invalid value which will be ignored by the
        // service and set back to default 68%

        System.setProperty(ZMS_PROP_REVIEW_DAYS_PERCENTAGE, "120");

        ZMSConfig zmsConfig = new ZMSConfig();
        zmsConfig.setUserDomain("user");
        DBService dbService = new DBService(mockObjStore, null, zmsConfig, null, null);

        ReviewObjects reviewObjects = new ReviewObjects();
        assertEquals(dbService.filterObjectsForReview(reviewObjects), reviewObjects);

        reviewObjects.setList(Collections.emptyList());
        assertEquals(dbService.filterObjectsForReview(reviewObjects), reviewObjects);

        // we're going to create four objects in our list
        // object1 - no last reviewed date, but created year ago so it must be included
        // object2 - longer than min review days, so it must be excluded
        // object3 - shorter than min review days, so it must be included
        // object4 - no last reviewed date, but created today so it must be excluded

        List<ReviewObject> reviewObjectList = new ArrayList<>();
        reviewObjects.setList(reviewObjectList);

        Timestamp yearOldTimestamp = Timestamp.fromMillis(System.currentTimeMillis()
                - TimeUnit.MILLISECONDS.convert(365, TimeUnit.DAYS));
        ReviewObject object1 = new ReviewObject().setDomainName("domain1").setName("object1")
                .setMemberExpiryDays(90).setCreated(yearOldTimestamp);
        reviewObjectList.add(object1);

        ReviewObject object2 = new ReviewObject().setDomainName("domain2").setName("object2")
                .setMemberExpiryDays(90).setMemberReviewDays(120)
                .setServiceReviewDays(90).setGroupReviewDays(120)
                .setGroupReviewDays(110).setGroupReviewDays(150)
                .setCreated(yearOldTimestamp)
                // last review must be done less than 68% of 90 days (61.2 days) before today - e.g. 60. days
                .setLastReviewedDate(Timestamp.fromMillis(System.currentTimeMillis()
                        - TimeUnit.MILLISECONDS.convert(60, TimeUnit.DAYS)));
        reviewObjectList.add(object2);

        ReviewObject object3 = new ReviewObject().setDomainName("domain3").setName("object3")
                .setMemberExpiryDays(90).setMemberReviewDays(120)
                .setServiceReviewDays(90).setGroupReviewDays(120)
                .setGroupReviewDays(110).setGroupReviewDays(150)
                .setCreated(yearOldTimestamp)
                // last review must be done more than 68% of 90 days (61.2 days) before today - e.g. 65 days
                .setLastReviewedDate(Timestamp.fromMillis(System.currentTimeMillis() -
                        TimeUnit.MILLISECONDS.convert(65, TimeUnit.DAYS)));
        reviewObjectList.add(object3);

        ReviewObject object4 = new ReviewObject().setDomainName("domain1").setName("object4")
                .setMemberExpiryDays(90).setCreated(Timestamp.fromCurrentTime());
        reviewObjectList.add(object4);

        ReviewObjects filterObjects = dbService.filterObjectsForReview(reviewObjects);
        assertEquals(filterObjects.getList().size(), 2);
        assertEquals(filterObjects.getList().get(0), object1);
        assertEquals(filterObjects.getList().get(1), object3);

        System.clearProperty(ZMS_PROP_REVIEW_DAYS_PERCENTAGE);
    }

    @Test
    public void testAuditLogDeleteSolutionTemplate() {

        String domainName = "auditlog-solutiontemplate";
        String caller = "testAuditLogDeleteSolutionTemplate";
        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", adminUser);
        zms.postTopLevelDomain(mockDomRsrcCtx, auditRef, null, dom1);

        // apply the template

        List<String> templates = new ArrayList<>();
        templates.add("templateWithRoleMeta");
        DomainTemplate domainTemplate = new DomainTemplate().setTemplateNames(templates);
        zms.dbService.executePutDomainTemplate(mockDomRsrcCtx, domainName, domainTemplate, auditRef, caller);

        DomainTemplateList domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertEquals(1, domainTemplateList.getTemplateNames().size());

        StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        auditDetails.append("{\"templates\": ");

        Template template = zms.dbService.zmsConfig.getServerSolutionTemplates().get("templateWithRoleMeta");
        ObjectStoreConnection conn = zms.dbService.store.getConnection(true, false);

        // remove the templateWithRoleMeta template
        zms.dbService.deleteSolutionTemplate(mockDomRsrcCtx, conn, domainName, "templateWithRoleMeta", template,
                auditDetails);

        auditDetails.append("}");

        assertTrue(isValidJSON(auditDetails.toString()));
        domainTemplateList = zms.dbService.listDomainTemplates(domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zms.deleteTopLevelDomain(mockDomRsrcCtx, domainName, auditRef, null);
    }

    @Test
    public void testProcessDomainContactsFailureCases() {

        final String domainName = "process-domain-contacts";
        ObjectStoreConnection conn = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(conn.insertDomainContact(domainName, "security-contact", "user.joe"))
                .thenReturn(false); // test case 1 - original list empty
        Mockito.when(conn.deleteDomainContact(domainName, "security-contact"))
                .thenReturn(false); // test case 2 - update list is empty
        Mockito.when(conn.updateDomainContact(domainName, "security-contact", "user.jane"))
                .thenReturn(false); // test case 3 - updating security-contact
        Mockito.when(conn.insertDomainContact(domainName, "pe-contact", "user.jane"))
                .thenReturn(false); // test case 4 - adding an entry during update
        Mockito.when(conn.deleteDomainContact(domainName, "sre-contact"))
                .thenReturn(false); // test case 5 - deleting an entry during update

        // with null list we do not make any changes

        assertTrue(zms.dbService.processDomainContacts(conn, domainName, null, null));

        // test case 1 - we're adding one new contact

        Map<String, String> updatedContacts = new HashMap<>();
        updatedContacts.put("security-contact", "user.joe");
        assertFalse(zms.dbService.processDomainContacts(conn, domainName, updatedContacts, null));

        // test case 2 - we're deleting an existing contact

        Map<String, String> originalContacts = new HashMap<>();
        originalContacts.put("security-contact", "user.joe");
        assertFalse(zms.dbService.processDomainContacts(conn, domainName, Collections.emptyMap(), originalContacts));

        // test case 3 - add one new contact, update an existing contact and delete one.

        updatedContacts = new HashMap<>();
        updatedContacts.put("security-contact", "user.jack");
        updatedContacts.put("pe-contact", "user.jane");

        originalContacts = new HashMap<>();
        originalContacts.put("security-contact", "user.joe");
        originalContacts.put("sre-contact", "user.jack");
        assertFalse(zms.dbService.processDomainContacts(conn, domainName, updatedContacts, originalContacts));

        // test case 3 - update an existing contact

        updatedContacts = new HashMap<>();
        updatedContacts.put("security-contact", "user.jack");

        originalContacts = new HashMap<>();
        originalContacts.put("security-contact", "user.joe");
        assertFalse(zms.dbService.processDomainContacts(conn, domainName, updatedContacts, originalContacts));

        // test case 4 - insert a new contact during update

        updatedContacts = new HashMap<>();
        updatedContacts.put("security-contact", "user.joe");
        updatedContacts.put("pe-contact", "user.jane");

        originalContacts = new HashMap<>();
        originalContacts.put("security-contact", "user.joe");
        assertFalse(zms.dbService.processDomainContacts(conn, domainName, updatedContacts, originalContacts));

        // test case 5 - delete a contact during update

        updatedContacts = new HashMap<>();
        updatedContacts.put("security-contact", "user.joe");

        originalContacts = new HashMap<>();
        originalContacts.put("security-contact", "user.joe");
        originalContacts.put("sre-contact", "user.joe");
        assertFalse(zms.dbService.processDomainContacts(conn, domainName, updatedContacts, originalContacts));

        // test case 5 - delete a contact during update with empty string

        updatedContacts = new HashMap<>();
        updatedContacts.put("security-contact", "user.joe");
        updatedContacts.put("sre-contact", "");

        originalContacts = new HashMap<>();
        originalContacts.put("security-contact", "user.joe");
        originalContacts.put("sre-contact", "user.joe");
        assertFalse(zms.dbService.processDomainContacts(conn, domainName, updatedContacts, originalContacts));
    }
}
