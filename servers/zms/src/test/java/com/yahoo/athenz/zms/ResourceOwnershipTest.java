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

import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.impl.jdbc.JDBCConnection;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.testng.Assert.*;

public class ResourceOwnershipTest {

    @Mock
    private JDBCConnection mockJdbcConn;
    @Mock private ObjectStore mockObjStore;

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        MockitoAnnotations.openMocks(this);
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        zmsTestInitializer.setUp();
        Mockito.reset(mockJdbcConn, mockObjStore);
        Mockito.when(mockObjStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockJdbcConn);
    }

    @Test
    public void testValidateResourceDomainOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // valid cases
        zmsImpl.validateResourceOwnership(new ResourceDomainOwnership(), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceDomainOwnership().setObjectOwner("TF"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceDomainOwnership().setObjectOwner("TF"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceDomainOwnership().setObjectOwner("TF").setMetaOwner("UI"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceDomainOwnership().setMetaOwner("UI"), "unit-test");

        // invalid cases
        try {
            zmsImpl.validateResourceOwnership((ResourceDomainOwnership) null, "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
        try {
            zmsImpl.validateResourceOwnership(new ResourceDomainOwnership().setObjectOwner("TF Test"), "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
    }

    @Test
    public void testValidateResourceRoleOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // valid cases
        zmsImpl.validateResourceOwnership(new ResourceRoleOwnership(), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF").setMetaOwner("UI"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF").setMetaOwner("UI")
                .setMembersOwner("MDS"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceRoleOwnership().setMetaOwner("UI"), "unit-test");

        // invalid cases
        try {
            zmsImpl.validateResourceOwnership((ResourceDomainOwnership) null, "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
        try {
            zmsImpl.validateResourceOwnership(new ResourceDomainOwnership().setObjectOwner("TF Test"), "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
    }

    @Test
    public void testValidateResourceGroupOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // valid cases
        zmsImpl.validateResourceOwnership(new ResourceGroupOwnership(), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF").setMetaOwner("UI"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF").setMetaOwner("UI")
                .setMembersOwner("MDS"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceGroupOwnership().setMetaOwner("UI"), "unit-test");

        // invalid cases
        try {
            zmsImpl.validateResourceOwnership((ResourceGroupOwnership) null, "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
        try {
            zmsImpl.validateResourceOwnership(new ResourceGroupOwnership().setObjectOwner("TF Test"), "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
    }

    @Test
    public void testValidateResourcePolicyOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // valid cases
        zmsImpl.validateResourceOwnership(new ResourcePolicyOwnership(), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF").setAssertionsOwner("UI"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourcePolicyOwnership().setAssertionsOwner("UI"), "unit-test");

        // invalid cases
        try {
            zmsImpl.validateResourceOwnership((ResourcePolicyOwnership) null, "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
        try {
            zmsImpl.validateResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF Test"), "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
    }

    @Test
    public void testValidateResourceServiceOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // valid cases
        zmsImpl.validateResourceOwnership(new ResourceServiceIdentityOwnership(), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF")
                .setPublicKeysOwner("UI"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF")
                .setPublicKeysOwner("UI").setHostsOwner("MSD"), "unit-test");
        zmsImpl.validateResourceOwnership(new ResourceServiceIdentityOwnership().setPublicKeysOwner("UI"), "unit-test");

        // invalid cases
        try {
            zmsImpl.validateResourceOwnership((ResourcePolicyOwnership) null, "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
        try {
            zmsImpl.validateResourceOwnership(new ResourcePolicyOwnership().setObjectOwner("TF Test"), "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
    }

    @Test
    public void testPutResourceDomainOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "domain-ownership";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ResourceDomainOwnership resourceOwnership = new ResourceDomainOwnership().setObjectOwner("TF")
                .setMetaOwner("UI");
        zmsImpl.putResourceDomainOwnership(ctx, domainName, auditRef, resourceOwnership);
        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourceDomainOwnership().setObjectOwner("TF");
        zmsImpl.putResourceDomainOwnership(ctx, domainName, auditRef, resourceOwnership);
        domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourceDomainOwnership();
        zmsImpl.putResourceDomainOwnership(ctx, domainName, auditRef, resourceOwnership);
        domain = zmsImpl.getDomain(ctx, domainName);
        assertNull(domain.getResourceOwnership());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutResourceDomainOwnershipRetryException() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "domain-ownership";

        ResourceDomainOwnership resourceOwnership = new ResourceDomainOwnership().setObjectOwner("TF")
                .setMetaOwner("UI");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceDomainOwnership(domainName, resourceOwnership))
                .thenThrow(new ResourceException(410));

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceDomainOwnership(ctx, domainName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(410, ex.getCode());
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceDomainOwnershipFailure() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "domain-ownership";

        ResourceDomainOwnership resourceOwnership = new ResourceDomainOwnership().setObjectOwner("TF")
                .setMetaOwner("UI");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceDomainOwnership(domainName, resourceOwnership))
                .thenReturn(false);

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceDomainOwnership(ctx, domainName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceRoleOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-ownership";
        final String roleName = "role1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<RoleMember> roleMembers = new ArrayList<>();
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        ResourceRoleOwnership resourceOwnership = new ResourceRoleOwnership().setObjectOwner("TF")
                .setMetaOwner("UI").setMembersOwner("MDS");
        zmsImpl.putResourceRoleOwnership(ctx, domainName, roleName, auditRef, resourceOwnership);
        Role role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        assertEquals(role.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourceRoleOwnership().setObjectOwner("TF");
        zmsImpl.putResourceRoleOwnership(ctx, domainName, roleName, auditRef, resourceOwnership);
        role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        assertEquals(role.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourceRoleOwnership();
        zmsImpl.putResourceRoleOwnership(ctx, domainName, roleName, auditRef, resourceOwnership);
        role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        assertNull(role.getResourceOwnership());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutResourceRoleOwnershipRetryException() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-ownership";
        final String roleName = "role1";

        ResourceRoleOwnership resourceOwnership = new ResourceRoleOwnership().setObjectOwner("TF")
                .setMetaOwner("UI").setMembersOwner("MDS");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceRoleOwnership(domainName, roleName, resourceOwnership))
                .thenThrow(new ResourceException(410));

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceRoleOwnership(ctx, domainName, roleName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(410, ex.getCode());
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceRoleOwnershipFailure() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-ownership";
        final String roleName = "role1";

        ResourceRoleOwnership resourceOwnership = new ResourceRoleOwnership().setObjectOwner("TF")
                .setMetaOwner("UI").setMembersOwner("MDS");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceRoleOwnership(domainName, roleName, resourceOwnership))
                .thenReturn(false);

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceRoleOwnership(ctx, domainName, roleName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceGroupOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-ownership";
        final String groupName = "group1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<GroupMember> groupMembers = new ArrayList<>();
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group1);

        ResourceGroupOwnership resourceOwnership = new ResourceGroupOwnership().setObjectOwner("TF")
                .setMetaOwner("UI").setMembersOwner("MDS");
        zmsImpl.putResourceGroupOwnership(ctx, domainName, groupName, auditRef, resourceOwnership);
        Group group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        assertEquals(group.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourceGroupOwnership().setObjectOwner("TF");
        zmsImpl.putResourceGroupOwnership(ctx, domainName, groupName, auditRef, resourceOwnership);
        group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        assertEquals(group.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourceGroupOwnership();
        zmsImpl.putResourceGroupOwnership(ctx, domainName, groupName, auditRef, resourceOwnership);
        group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        assertNull(group.getResourceOwnership());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutResourceGroupOwnershipRetryException() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-ownership";
        final String groupName = "group1";

        ResourceGroupOwnership resourceOwnership = new ResourceGroupOwnership().setObjectOwner("TF")
                .setMetaOwner("UI").setMembersOwner("MDS");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceGroupOwnership(domainName, groupName, resourceOwnership))
                .thenThrow(new ResourceException(410));

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceGroupOwnership(ctx, domainName, groupName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(410, ex.getCode());
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceGroupOwnershipFailure() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-ownership";
        final String groupName = "group1";

        ResourceGroupOwnership resourceOwnership = new ResourceGroupOwnership().setObjectOwner("TF")
                .setMetaOwner("UI").setMembersOwner("MDS");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceGroupOwnership(domainName, groupName, resourceOwnership))
                .thenReturn(false);

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceGroupOwnership(ctx, domainName, groupName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourcePolicyOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "policy-ownership";
        final String policyName = "policy1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Policy policy1 = zmsTestInitializer.createPolicyObject(domainName, policyName);
        zmsImpl.putPolicy(ctx, domainName, policyName, auditRef, null, null, policy1);

        ResourcePolicyOwnership resourceOwnership = new ResourcePolicyOwnership().setObjectOwner("TF")
                .setAssertionsOwner("UI");
        zmsImpl.putResourcePolicyOwnership(ctx, domainName, policyName, auditRef, resourceOwnership);
        Policy policy = zmsImpl.getPolicy(ctx, domainName, policyName);
        assertEquals(policy.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourcePolicyOwnership().setObjectOwner("TF");
        zmsImpl.putResourcePolicyOwnership(ctx, domainName, policyName, auditRef, resourceOwnership);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName);
        assertEquals(policy.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourcePolicyOwnership();
        zmsImpl.putResourcePolicyOwnership(ctx, domainName, policyName, auditRef, resourceOwnership);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName);
        assertNull(policy.getResourceOwnership());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutResourcePolicyOwnershipRetryException() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "policy-ownership";
        final String policyName = "policy1";

        ResourcePolicyOwnership resourceOwnership = new ResourcePolicyOwnership().setObjectOwner("TF")
                .setAssertionsOwner("UI");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourcePolicyOwnership(domainName, policyName, resourceOwnership))
                .thenThrow(new ResourceException(410));

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourcePolicyOwnership(ctx, domainName, policyName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(410, ex.getCode());
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourcePolicyOwnershipFailure() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "policy-ownership";
        final String policyName = "policy1";

        ResourcePolicyOwnership resourceOwnership = new ResourcePolicyOwnership().setObjectOwner("TF")
                .setAssertionsOwner("UI");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourcePolicyOwnership(domainName, policyName, resourceOwnership))
                .thenReturn(false);

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourcePolicyOwnership(ctx, domainName, policyName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceServiceOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "service-ownership";
        final String serviceName = "service1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(domainName, serviceName,
                null, null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, null, null, service1);

        ResourceServiceIdentityOwnership resourceOwnership = new ResourceServiceIdentityOwnership()
                .setObjectOwner("TF").setPublicKeysOwner("UI").setHostsOwner("MSD");
        zmsImpl.putResourceServiceIdentityOwnership(ctx, domainName, serviceName, auditRef, resourceOwnership);
        ServiceIdentity service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(service.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourceServiceIdentityOwnership().setObjectOwner("TF");
        zmsImpl.putResourceServiceIdentityOwnership(ctx, domainName, serviceName, auditRef, resourceOwnership);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(service.getResourceOwnership(), resourceOwnership);

        resourceOwnership = new ResourceServiceIdentityOwnership();
        zmsImpl.putResourceServiceIdentityOwnership(ctx, domainName, serviceName, auditRef, resourceOwnership);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNull(service.getResourceOwnership());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutResourceServiceOwnershipFailure() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "service-ownership";
        final String serviceName = "service1";

        ResourceServiceIdentityOwnership resourceOwnership = new ResourceServiceIdentityOwnership()
                .setObjectOwner("TF").setPublicKeysOwner("UI");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceServiceOwnership(domainName, serviceName, resourceOwnership))
                .thenReturn(false);

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceServiceIdentityOwnership(ctx, domainName, serviceName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceServiceOwnershipRetryException() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "service-ownership";
        final String serviceName = "service1";

        ResourceServiceIdentityOwnership resourceOwnership = new ResourceServiceIdentityOwnership()
                .setObjectOwner("TF").setPublicKeysOwner("UI");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceServiceOwnership(domainName, serviceName, resourceOwnership))
                .thenThrow(new ResourceException(410));

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceServiceIdentityOwnership(ctx, domainName, serviceName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(410, ex.getCode());
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }
}
