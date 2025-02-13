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

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.common.server.store.impl.JDBCConnection;
import com.yahoo.athenz.common.server.util.ResourceOwnership;
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
            zmsImpl.validateResourceOwnership((ResourceRoleOwnership) null, "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
        try {
            zmsImpl.validateResourceOwnership(new ResourceRoleOwnership().setObjectOwner("TF Test"), "unit-test");
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
            zmsImpl.validateResourceOwnership((ResourceServiceIdentityOwnership) null, "unit-test");
        } catch (ResourceException ex) {
            assert(ex.getCode() == 400);
        }
        try {
            zmsImpl.validateResourceOwnership(new ResourceServiceIdentityOwnership().setObjectOwner("TF Test"), "unit-test");
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
    public void testPutResourceDomainOwnershipRetryException() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "domain-ownership";

        ResourceDomainOwnership resourceOwnership = new ResourceDomainOwnership().setObjectOwner("TF")
                .setMetaOwner("UI");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceDomainOwnership(domainName, resourceOwnership))
                .thenThrow(new ServerResourceException(410));

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceDomainOwnership(ctx, domainName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 410);
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceDomainOwnershipFailure() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "domain-ownership";

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
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        // calling the method within the domain object update method
        // should not fail the operation since the exception is ignored

        zmsImpl.updateResourceDomainOwnership(ctx, domainName, resourceOwnership, auditRef, "unit-test");

        // restore the state

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
    public void testPutResourceRoleOwnershipRetryException() throws ServerResourceException {

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
            assertEquals(ex.getCode(), 410);
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceRoleOwnershipFailure() throws ServerResourceException {

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
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        // calling the method within the role object update method
        // should not fail the operation since the exception is ignored

        zmsImpl.updateResourceRoleOwnership(ctx, domainName, roleName, resourceOwnership, auditRef, "unit-test");

        // restore the state

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
    public void testPutResourceGroupOwnershipRetryException() throws ServerResourceException {

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
            assertEquals(ex.getCode(), 410);
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceGroupOwnershipFailure() throws ServerResourceException {

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
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        // calling the method within the group object update method
        // should not fail the operation since the exception is ignored

        zmsImpl.updateResourceGroupOwnership(ctx, domainName, groupName, resourceOwnership, auditRef, "unit-test");

        // restore the state

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
    public void testPutResourcePolicyOwnershipRetryException() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "policy-ownership";
        final String policyName = "policy1";

        ResourcePolicyOwnership resourceOwnership = new ResourcePolicyOwnership().setObjectOwner("TF")
                .setAssertionsOwner("UI");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourcePolicyOwnership(domainName, policyName, resourceOwnership))
                .thenThrow(new ServerResourceException(410));

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourcePolicyOwnership(ctx, domainName, policyName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 410);
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourcePolicyOwnershipFailure() throws ServerResourceException {

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
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        // calling the method within the policy object update method
        // should not fail the operation since the exception is ignored

        zmsImpl.updateResourcePolicyOwnership(ctx, domainName, policyName, resourceOwnership, auditRef, "unit-test");

        // restore the state

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
    public void testPutResourceServiceOwnershipFailure() throws ServerResourceException {

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
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("unable to put resource"));
        }

        // calling the method within the service object update method
        // should not fail the operation since the exception is ignored

        zmsImpl.updateResourceServiceOwnership(ctx, domainName, serviceName, resourceOwnership, auditRef, "unit-test");

        // restore the state

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testPutResourceServiceOwnershipRetryException() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "service-ownership";
        final String serviceName = "service1";

        ResourceServiceIdentityOwnership resourceOwnership = new ResourceServiceIdentityOwnership()
                .setObjectOwner("TF").setPublicKeysOwner("UI");

        Mockito.when(mockJdbcConn.getDomain(domainName)).thenReturn(new Domain().setName(domainName));
        Mockito.when(mockJdbcConn.setResourceServiceOwnership(domainName, serviceName, resourceOwnership))
                .thenThrow(new ServerResourceException(410));

        ObjectStore saveStore = zmsImpl.dbService.store;
        zmsImpl.dbService.store = mockObjStore;
        int saveRetryCount = zmsImpl.dbService.defaultRetryCount;
        zmsImpl.dbService.defaultRetryCount = 3;

        try {
            zmsImpl.putResourceServiceIdentityOwnership(ctx, domainName, serviceName, auditRef, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 410);
        }

        zmsImpl.dbService.defaultRetryCount = saveRetryCount;
        zmsImpl.dbService.store = saveStore;
    }

    @Test
    public void testResourceRoleOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-ownership-object";
        final String roleName = "role1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user1").setActive(true));
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, "TF1", role1);

        Role role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        ResourceRoleOwnership resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF1");
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF1");

        // put the same role with another ownership which should be rejected

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user2").setActive(true));
        role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, roleMembers);
        try {
            zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, "TF2", role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // put the same role with the same ownership which should be processed

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, "TF1", role1);

        // now update the role with the ignore ownership flag and make sure it's processed

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user3").setActive(true));
        role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, true, "ignore", role1);

        // add a new role without any members and verify members owner is not set

        final String roleName2 = "role2";
        Role role2 = zmsTestInitializer.createRoleObject(domainName, roleName2, null, null);
        zmsImpl.putRole(ctx, domainName, roleName2, auditRef, false, "TF3", role2);
        role = zmsImpl.getRole(ctx, domainName, roleName2, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertEquals(resourceOwnership.getMetaOwner(), "TF3");
        assertNull(resourceOwnership.getMembersOwner());

        // add a new role without any ownership

        final String roleName3 = "role3";
        Role role3 = zmsTestInitializer.createRoleObject(domainName, roleName3, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName3, auditRef, false, null, role3);

        // now update the role with a new ownership value set and verify values

        zmsImpl.putRole(ctx, domainName, roleName3, auditRef, false, "TF4", role3);
        role = zmsImpl.getRole(ctx, domainName, roleName3, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF4");
        assertEquals(resourceOwnership.getMetaOwner(), "TF4");
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        // add another role without any ownership

        final String roleName4 = "role4";
        Role role4 = zmsTestInitializer.createRoleObject(domainName, roleName4, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName4, auditRef, false, null, role4);

        // this time set the resource association for object owner only

        zmsImpl.dbService.executePutResourceRoleOwnership(ctx, domainName, roleName4,
                new ResourceRoleOwnership().setObjectOwner("TF5"), auditRef, null);

        // now put the role again with a new member with same ownership

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user5").setActive(true));
        role4 = zmsTestInitializer.createRoleObject(domainName, roleName4, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName4, auditRef, false, "TF5", role4);

        role = zmsImpl.getRole(ctx, domainName, roleName4, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF5");
        assertEquals(resourceOwnership.getMetaOwner(), "TF5");
        assertEquals(resourceOwnership.getMembersOwner(), "TF5");

        // update a role with resource ownership force override
        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user5").setActive(true));
        role4 = zmsTestInitializer.createRoleObject(domainName, roleName4, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName4, auditRef, false, "TF6:force", role4);

        role = zmsImpl.getRole(ctx, domainName, roleName4, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF6");
        assertEquals(resourceOwnership.getMetaOwner(), "TF6");
        assertEquals(resourceOwnership.getMembersOwner(), "TF6");

        // deleting the object without any ownership should fail

        try {
            zmsImpl.deleteRole(ctx, domainName, roleName4, auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the object with a different ownership should fail

        try {
            zmsImpl.deleteRole(ctx, domainName, roleName4, auditRef, "TF7");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the object with the correct ownership should work

        zmsImpl.deleteRole(ctx, domainName, roleName4, auditRef, "TF6");

        // deleting the object with the ignore flag should work

        zmsImpl.deleteRole(ctx, domainName, roleName3, auditRef, "ignore");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testResourceRoleOwnershipMembers() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-ownership-members";
        final String roleName = "role1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user1").setActive(true));
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        Role role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        assertNull(role.getResourceOwnership());

        // now set the meta for role and verify the new ownership

        RoleMeta roleMeta = new RoleMeta().setDescription("test-role");
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, "TF1", roleMeta);

        role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        ResourceRoleOwnership resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertNull(resourceOwnership.getMembersOwner());

        // now try deleting the member to verify operation succeeds without owner
        zmsImpl.deleteMembership(ctx, domainName, roleName, "user.user1", auditRef, "TF-delete");

        role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertNull(resourceOwnership.getMembersOwner());

        // now add a member to the role and verify the new ownership

        Membership mbr = new Membership().setRoleName(roleName).setMemberName("user.user2");
        zmsImpl.putMembership(ctx, domainName, roleName, "user.user2", auditRef, false, "TF2", mbr);

        role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF2");

        // try to add a new member to the role with a different ownership

        Membership mbr2 = new Membership().setRoleName(roleName).setMemberName("user.user2a");
        try {
            zmsImpl.putMembership(ctx, domainName, roleName, "user.user2a", auditRef, false, "TF3", mbr2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to delete existing member with a different ownership
        try {
            zmsImpl.deleteMembership(ctx, domainName, roleName, "user.user2", auditRef, "TF3");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // now add a member with the same ownership and it should be ok

        zmsImpl.putMembership(ctx, domainName, roleName, "user.user2a", auditRef, false, "TF2", mbr2);

        // now delete a member with the same ownership and it should be ok

        zmsImpl.deleteMembership(ctx, domainName, roleName, "user.user2", auditRef, "TF2");

        // now add a member with the ignore flag, and it should be ok
        // verify that th member ownership hasn't changed

        zmsImpl.putMembership(ctx, domainName, roleName, "user.user2a", auditRef, true, "ignore", mbr2);
        role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF2");

        // add a new role without any member ownership

        final String roleName2 = "role2";
        Role role2 = zmsTestInitializer.createRoleObject(domainName, roleName2, null, null);
        zmsImpl.putRole(ctx, domainName, roleName2, auditRef, false, "TF3", role2);

        // add a new member without any ownership should be fine

        Membership mbr3 = new Membership().setRoleName(roleName2).setMemberName("user.user2b");
        zmsImpl.putMembership(ctx, domainName, roleName2, "user.user2b", auditRef, false, null, mbr3);

        // now add a member with the ownership set which should be set
        // the ownership for the role members

        Membership mbr4 = new Membership().setRoleName(roleName2).setMemberName("user.user3");
        zmsImpl.putMembership(ctx, domainName, roleName2, "user.user3", auditRef, false, "TF4", mbr4);
        role = zmsImpl.getRole(ctx, domainName, roleName2, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertEquals(resourceOwnership.getMetaOwner(), "TF3");
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        // try to add a member without any owner and it should be rejected

        try {
            zmsImpl.putMembership(ctx, domainName, roleName2, "user.user2b", auditRef, false, null, mbr3);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to delete a member without any owner and it should be rejected

        try {
            zmsImpl.deleteMembership(ctx, domainName, roleName2, "user.user2b", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to add a member with the same ownership and it should work fine

        zmsImpl.putMembership(ctx, domainName, roleName2, "user.user2b", auditRef, false, "TF4", mbr3);

        // now add a member with the ownership override

        Membership mbr5 = new Membership().setRoleName(roleName2).setMemberName("user.user3");
        zmsImpl.putMembership(ctx, domainName, roleName2, "user.user3", auditRef, false, "TF5:force", mbr5);
        role = zmsImpl.getRole(ctx, domainName, roleName2, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertEquals(resourceOwnership.getMetaOwner(), "TF3");
        assertEquals(resourceOwnership.getMembersOwner(), "TF5");

        // try to delete a member with the same ownership and it should work fine

        zmsImpl.deleteMembership(ctx, domainName, roleName2, "user.user2b", auditRef, "TF5");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testResourceRoleOwnershipMeta() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-ownership-members";
        final String roleName = "role1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user1").setActive(true));
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, roleMembers);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        Role role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        assertNull(role.getResourceOwnership());

        // now set the meta for role and verify the new ownership

        RoleMeta roleMeta = new RoleMeta().setDescription("test-role");
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, "TF1", roleMeta);

        role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        ResourceRoleOwnership resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertNull(resourceOwnership.getMembersOwner());

        // now add a member to the role and which would set the ownership for members

        Membership mbr = new Membership().setRoleName(roleName).setMemberName("user.user2");
        zmsImpl.putMembership(ctx, domainName, roleName, "user.user2", auditRef, false, "TF2", mbr);

        role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF2");

        // try to set meta with new ownership which should be rejected

        try {
            zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, "TF2", roleMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to set meta without any ownership which should be rejected

        try {
            zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, roleMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // setting the meta owner to the same value should be ok

        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, "TF1", roleMeta);

        // setting the meta owner with the ignore flag should be ok
        // verify that the ownership hasn't changed

        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, "ignore", roleMeta);
        role = zmsImpl.getRole(ctx, domainName, roleName, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF2");

        // put the same role with empty ownership

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user3").setActive(true));
        role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, roleMembers);
        try {
            zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, "", role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // put the same role with the meta owner's value which should be rejected

        try {
            zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, "TF1", role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // put the same role with the member owner's value which should be rejected as well

        try {
            zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, "TF2", role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // now update the role with the ignore ownership flag and make sure it's processed

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, "ignore", role1);

        // add a new role without any meta ownership

        final String roleName2 = "role2";
        Role role2 = zmsTestInitializer.createRoleObject(domainName, roleName2, null, null);
        zmsImpl.putRole(ctx, domainName, roleName2, auditRef, false, null, role2);

        // now add a member with the ownership set which should be set
        // the ownership for the role members

        Membership mbr4 = new Membership().setRoleName(roleName2).setMemberName("user.user3");
        zmsImpl.putMembership(ctx, domainName, roleName2, "user.user3", auditRef, false, "TF4", mbr4);
        role = zmsImpl.getRole(ctx, domainName, roleName2, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertNull(resourceOwnership.getMetaOwner());
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        // try to put meta without any ownership and it should work fine

        zmsImpl.putRoleMeta(ctx, domainName, roleName2, auditRef, null, roleMeta);

        // try to put meta with a new owner which should update the meta ownership

        zmsImpl.putRoleMeta(ctx, domainName, roleName2, auditRef, "TF5", roleMeta);
        role = zmsImpl.getRole(ctx, domainName, roleName2, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF5");
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        // try to put meta with force override and it should work fine
        zmsImpl.putRoleMeta(ctx, domainName, roleName2, auditRef, "TF6:force", roleMeta);
        role = zmsImpl.getRole(ctx, domainName, roleName2, null, null, null);
        resourceOwnership = role.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF6");
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testResourceGroupOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-ownership-object";
        final String groupName = "group1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user1").setActive(true));
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, "TF1", group1);

        Group group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        ResourceGroupOwnership resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF1");
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF1");

        // put the same group with another ownership which should be rejected

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user2").setActive(true));
        group1 = zmsTestInitializer.createGroupObject(domainName, groupName, groupMembers);
        try {
            zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, "TF2", group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // put the same group with the same ownership which should be processed

        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, "TF1", group1);

        // now update the group with the ignore ownership flag and make sure it's processed

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user3").setActive(true));
        group1 = zmsTestInitializer.createGroupObject(domainName, groupName, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, true, "ignore", group1);

        // add a new group without any members and verify members owner is not set

        final String groupName2 = "group2";
        Group group2 = zmsTestInitializer.createGroupObject(domainName, groupName2, null, null);
        zmsImpl.putGroup(ctx, domainName, groupName2, auditRef, false, "TF3", group2);
        group = zmsImpl.getGroup(ctx, domainName, groupName2, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertEquals(resourceOwnership.getMetaOwner(), "TF3");
        assertNull(resourceOwnership.getMembersOwner());

        // add a new group without any ownership

        final String groupName3 = "group3";
        Group group3 = zmsTestInitializer.createGroupObject(domainName, groupName3, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName3, auditRef, false, null, group3);

        // now update the group with a new ownership value set and verify values

        zmsImpl.putGroup(ctx, domainName, groupName3, auditRef, false, "TF4", group3);
        group = zmsImpl.getGroup(ctx, domainName, groupName3, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF4");
        assertEquals(resourceOwnership.getMetaOwner(), "TF4");
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        // add another group without any ownership

        final String groupName4 = "group4";
        Group group4 = zmsTestInitializer.createGroupObject(domainName, groupName4, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName4, auditRef, false, null, group4);

        // this time set the resource association for object owner only

        zmsImpl.dbService.executePutResourceGroupOwnership(ctx, domainName, groupName4,
                new ResourceGroupOwnership().setObjectOwner("TF5"), auditRef, null);

        // now put the group again with a new member with same ownership

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user5").setActive(true));
        group4 = zmsTestInitializer.createGroupObject(domainName, groupName4, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName4, auditRef, false, "TF5", group4);

        group = zmsImpl.getGroup(ctx, domainName, groupName4, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF5");
        assertEquals(resourceOwnership.getMetaOwner(), "TF5");
        assertEquals(resourceOwnership.getMembersOwner(), "TF5");

        // now put the group again with a force ownership override

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user5").setActive(true));
        group4 = zmsTestInitializer.createGroupObject(domainName, groupName4, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName4, auditRef, false, "TF6:force", group4);

        group = zmsImpl.getGroup(ctx, domainName, groupName4, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF6");
        assertEquals(resourceOwnership.getMetaOwner(), "TF6");
        assertEquals(resourceOwnership.getMembersOwner(), "TF6");

        // deleting the object without any ownership should fail

        try {
            zmsImpl.deleteGroup(ctx, domainName, groupName4, auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the object with a different ownership should fail

        try {
            zmsImpl.deleteGroup(ctx, domainName, groupName4, auditRef, "TF7");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the object with the correct ownership should work

        zmsImpl.deleteGroup(ctx, domainName, groupName4, auditRef, "TF6");

        // deleting the group with the ignore flag should work

        zmsImpl.deleteGroup(ctx, domainName, groupName3, auditRef, "ignore");
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testResourceGroupOwnershipMembers() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-ownership-members";
        final String groupName = "group1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user1").setActive(true));
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group1);

        Group group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        assertNull(group.getResourceOwnership());

        // now set the meta for group and verify the new ownership

        GroupMeta groupMeta = new GroupMeta().setMaxMembers(10);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, "TF1", groupMeta);

        group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        ResourceGroupOwnership resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertNull(resourceOwnership.getMembersOwner());

        // now try deleting the member to verify operation succeeds without owner
        zmsImpl.deleteGroupMembership(ctx, domainName, groupName, "user.user1", auditRef, "TF-delete");

        group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertNull(resourceOwnership.getMembersOwner());

        // now add a member to the group and verify the new ownership

        GroupMembership mbr = new GroupMembership().setGroupName(groupName).setMemberName("user.user2");
        zmsImpl.putGroupMembership(ctx, domainName, groupName, "user.user2", auditRef, false, "TF2", mbr);

        group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF2");

        // try to add a new member to the group with a different ownership

        GroupMembership mbr2 = new GroupMembership().setGroupName(groupName).setMemberName("user.user2a");
        try {
            zmsImpl.putGroupMembership(ctx, domainName, groupName, "user.user2a", auditRef, false, "TF3", mbr2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to delete existing member with a different ownership
        try {
            zmsImpl.deleteGroupMembership(ctx, domainName, groupName, "user.user2", auditRef, "TF3");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // now add a member with the same ownership and it should be ok

        zmsImpl.putGroupMembership(ctx, domainName, groupName, "user.user2a", auditRef, false, "TF2", mbr2);

        // now delete a member with the same ownership and it should be ok

        zmsImpl.deleteGroupMembership(ctx, domainName, groupName, "user.user2", auditRef, "TF2");

        // now add a member with the ignore flag, and it should be ok
        // verify that th member ownership hasn't changed

        zmsImpl.putGroupMembership(ctx, domainName, groupName, "user.user2a", auditRef, true, "ignore", mbr2);
        group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF2");

        // add a new group without any member ownership

        final String groupName2 = "group2";
        Group group2 = zmsTestInitializer.createGroupObject(domainName, groupName2, null, null);
        zmsImpl.putGroup(ctx, domainName, groupName2, auditRef, false, "TF3", group2);

        // add a new member without any ownership should be fine

        GroupMembership mbr3 = new GroupMembership().setGroupName(groupName2).setMemberName("user.user2b");
        zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.user2b", auditRef, false, null, mbr3);

        // now add a member with the ownership set which should be set
        // the ownership for the group members

        GroupMembership mbr4 = new GroupMembership().setGroupName(groupName2).setMemberName("user.user3");
        zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.user3", auditRef, false, "TF4", mbr4);
        group = zmsImpl.getGroup(ctx, domainName, groupName2, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertEquals(resourceOwnership.getMetaOwner(), "TF3");
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        // now add new membership with force override
        GroupMembership mbr5 = new GroupMembership().setGroupName(groupName2).setMemberName("user.user3");
        zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.user3", auditRef, false, "TF5:force", mbr5);
        group = zmsImpl.getGroup(ctx, domainName, groupName2, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertEquals(resourceOwnership.getMetaOwner(), "TF3");
        assertEquals(resourceOwnership.getMembersOwner(), "TF5");

        // try to add a member without any owner and it should be rejected

        try {
            zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.user2b", auditRef, false, null, mbr3);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to delete a member without any owner and it should be rejected

        try {
            zmsImpl.deleteGroupMembership(ctx, domainName, groupName2, "user.user3", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to add a member with the same ownership and it should work fine

        zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.user2b", auditRef, false, "TF5", mbr3);

        // try to delete a member with the same ownership and it should work fine

        zmsImpl.deleteGroupMembership(ctx, domainName, groupName2, "user.user2b", auditRef, "TF5");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testResourceGroupOwnershipMeta() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-ownership-members";
        final String groupName = "group1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user1").setActive(true));
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, groupMembers);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group1);

        Group group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        assertNull(group.getResourceOwnership());

        // now set the meta for group and verify the new ownership

        GroupMeta groupMeta = new GroupMeta().setMaxMembers(10);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, "TF1", groupMeta);

        group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        ResourceGroupOwnership resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertNull(resourceOwnership.getMembersOwner());

        // now add a member to the group and which would set the ownership for members

        GroupMembership mbr = new GroupMembership().setGroupName(groupName).setMemberName("user.user2");
        zmsImpl.putGroupMembership(ctx, domainName, groupName, "user.user2", auditRef, false, "TF2", mbr);

        group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF2");

        // try to set meta with new ownership which should be rejected

        try {
            zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, "TF2", groupMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to set meta without any ownership which should be rejected

        try {
            zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, groupMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // setting the meta owner to the same value should be ok

        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, "TF1", groupMeta);

        // setting the meta owner with the ignore flag should be ok
        // verify that the ownership hasn't changed

        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, "ignore", groupMeta);
        group = zmsImpl.getGroup(ctx, domainName, groupName, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");
        assertEquals(resourceOwnership.getMembersOwner(), "TF2");

        // put the same group with empty ownership

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user3").setActive(true));
        group1 = zmsTestInitializer.createGroupObject(domainName, groupName, groupMembers);
        try {
            zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, "", group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // put the same group with the meta owner's value which should be rejected

        try {
            zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, "TF1", group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // put the same group with the member owner's value which should be rejected as well

        try {
            zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, "TF2", group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // now update the group with the ignore ownership flag and make sure it's processed

        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, "ignore", group1);

        // add a new group without any meta ownership

        final String groupName2 = "group2";
        Group group2 = zmsTestInitializer.createGroupObject(domainName, groupName2, null, null);
        zmsImpl.putGroup(ctx, domainName, groupName2, auditRef, false, null, group2);

        // now add a member with the ownership set which should be set
        // the ownership for the group members

        GroupMembership mbr4 = new GroupMembership().setGroupName(groupName2).setMemberName("user.user3");
        zmsImpl.putGroupMembership(ctx, domainName, groupName2, "user.user3", auditRef, false, "TF4", mbr4);
        group = zmsImpl.getGroup(ctx, domainName, groupName2, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertNull(resourceOwnership.getMetaOwner());
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        // try to put meta without any ownership and it should work fine

        zmsImpl.putGroupMeta(ctx, domainName, groupName2, auditRef, null, groupMeta);

        // try to put meta with a new owner which should update the meta ownership

        zmsImpl.putGroupMeta(ctx, domainName, groupName2, auditRef, "TF5", groupMeta);
        group = zmsImpl.getGroup(ctx, domainName, groupName2, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF5");
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        // try to put meta with a new owner via force override

        zmsImpl.putGroupMeta(ctx, domainName, groupName2, auditRef, "TF6:force", groupMeta);
        group = zmsImpl.getGroup(ctx, domainName, groupName2, null, null);
        resourceOwnership = group.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF6");
        assertEquals(resourceOwnership.getMembersOwner(), "TF4");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testResourceDomainOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // create a top level domain without any ownership

        final String domainName1 = "domain-ownership-object1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName1);
        assertNull(domain.getResourceOwnership());

        final String domainName2 = "domain-ownership-object2";
        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, "TF1", dom2);

        domain = zmsImpl.getDomain(ctx, domainName2);
        ResourceDomainOwnership resourceOwnership = domain.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF1");
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");

        // create a subdomain without any ownership

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject("sub1", domainName2, null, null,
                zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postSubDomain(ctx, domainName2, auditRef, null, subDom1);

        domain = zmsImpl.getDomain(ctx, domainName2 + ".sub1");
        assertNull(domain.getResourceOwnership());

        // create a subdomain with ownership

        SubDomain subDom2 = zmsTestInitializer.createSubDomainObject("sub2", domainName2, null, null,
                zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postSubDomain(ctx, domainName2, auditRef, "TF2", subDom2);

        domain = zmsImpl.getDomain(ctx, domainName2 + ".sub2");
        resourceOwnership = domain.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getMetaOwner(), "TF2");

        // create a user domain without any ownership

        RsrcCtxWrapper ctx1 = zmsTestInitializer.contextWithMockPrincipal("postUserDomain");
        UserDomain userDom1 = zmsTestInitializer.createUserDomainObject("john-doe", "Test Domain1", "testOrg");
        zmsImpl.postUserDomain(ctx1, "john-doe", auditRef, null, userDom1);

        domain = zmsImpl.getDomain(ctx, "user.john-doe");
        assertNull(domain.getResourceOwnership());

        zmsImpl.deleteUserDomain(ctx1, "john-doe", auditRef, null);

        // create a user domain with ownership

        zmsImpl.postUserDomain(ctx1, "john-doe", auditRef, "TF3", userDom1);

        domain = zmsImpl.getDomain(ctx, "user.john-doe");
        resourceOwnership = domain.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertEquals(resourceOwnership.getMetaOwner(), "TF3");

        // deleting the domain without any ownership should fail

        try {
            zmsImpl.deleteUserDomain(ctx1, "john-doe", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the domain with the wrong ownership should fail

        try {
            zmsImpl.deleteUserDomain(ctx1, "john-doe", auditRef, "TF2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the domain with the correct ownership should work

        zmsImpl.deleteUserDomain(ctx1, "john-doe", auditRef, "TF3");

        zmsImpl.deleteSubDomain(ctx, domainName2, "sub1", auditRef, null);

        // deleting the subdomain without any ownership should fail

        try {
            zmsImpl.deleteSubDomain(ctx, domainName2, "sub2", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the subdomain with the wrong ownership should fail

        try {
            zmsImpl.deleteSubDomain(ctx, domainName2, "sub2", auditRef, "TF3");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the subdomain with the ignore ownership should work

        zmsImpl.deleteSubDomain(ctx, domainName2, "sub2", auditRef, "ignore");

        // deleting the top level domain without any ownership should fail

        try {
            zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the top level domain with the wrong ownership should fail

        try {
            zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, "TF2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the top level domain with the correct ownership should work

        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, "TF1");
        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
    }

    @Test
    public void testResourceDomainMetaOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // create domain without any ownership details

        final String domainName = "domain-ownership-meta";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // domain meta without any ownership should be fine

        DomainMeta domainMeta = new DomainMeta().setDescription("test-domain");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);

        // set the domain meta ownership

        zmsImpl.putDomainMeta(ctx, domainName, auditRef, "TF1", domainMeta);
        Domain domain = zmsImpl.getDomain(ctx, domainName);
        ResourceDomainOwnership resourceOwnership = domain.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");

        // now update the domain meta with the ignore ownership flag
        // and verify the ownership details haven't changed

        zmsImpl.putDomainMeta(ctx, domainName, auditRef, "ignore", domainMeta);
        domain = zmsImpl.getDomain(ctx, domainName);
        resourceOwnership = domain.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF1");

        zmsImpl.putDomainMeta(ctx, domainName, auditRef, "TF2:force", domainMeta);
        domain = zmsImpl.getDomain(ctx, domainName);
        resourceOwnership = domain.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getMetaOwner(), "TF2");

        // try to update meta without any ownership which should be rejected

        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, domainMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to update meta with a new ownership which should be rejected

        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, "TF3", domainMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // try to update with the same ownership value which should be oik

        zmsImpl.putDomainMeta(ctx, domainName, auditRef, "TF2", domainMeta);

        // create another domain and set the object ownership

        final String domainName2 = "domain-ownership-meta2";
        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ResourceDomainOwnership resourceOwnership2 = new ResourceDomainOwnership().setObjectOwner("TF2");
        zmsImpl.dbService.executePutResourceDomainOwnership(ctx, domainName2, resourceOwnership2, auditRef, null);

        // verify ownership of the domain

        domain = zmsImpl.getDomain(ctx, domainName2);
        resourceOwnership = domain.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertNull(resourceOwnership.getMetaOwner());

        // updating the domain meta without any value should be fine

        zmsImpl.putDomainMeta(ctx, domainName2, auditRef, null, domainMeta);

        // now update the domain meta with a new ownership value which should be set

        zmsImpl.putDomainMeta(ctx, domainName2, auditRef, "TF3", domainMeta);
        domain = zmsImpl.getDomain(ctx, domainName2);
        resourceOwnership = domain.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getMetaOwner(), "TF3");


        // now update the domain meta with a force override ownership value which should be set

        zmsImpl.putDomainMeta(ctx, domainName2, auditRef, "TF4:force", domainMeta);
        domain = zmsImpl.getDomain(ctx, domainName2);
        resourceOwnership = domain.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getMetaOwner(), "TF4");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, "TF2");
    }

    @Test
    public void testResourcePolicyOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "policy-ownership-object";
        final String roleName = "role1";
        final String policyName = "policy1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, null);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        // create a policy without any ownership details

        Policy policy1 = zmsTestInitializer.createPolicyObject(domainName, policyName, null, true);
        zmsImpl.putPolicy(ctx, domainName, policyName, auditRef, false, null, policy1);

        Policy policy = zmsImpl.getPolicy(ctx, domainName, policyName);
        assertNull(policy.getResourceOwnership());

        // create a policy with the object ownership set

        final String policyName2 = "policy2";
        Policy policy2 = zmsTestInitializer.createPolicyObject(domainName, policyName2, null, true);
        zmsImpl.putPolicy(ctx, domainName, policyName2, auditRef, false, "TF1", policy2);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName2);
        ResourcePolicyOwnership resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF1");
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF1");

        // update the policy with an empty ownership which should be rejected

        try {
            zmsImpl.putPolicy(ctx, domainName, policyName2, auditRef, false, null, policy2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // update the policy with a different ownership which should be rejected

        try {
            zmsImpl.putPolicy(ctx, domainName, policyName2, auditRef, false, "TF2", policy2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // update the policy with the same ownership which should be processed

        zmsImpl.putPolicy(ctx, domainName, policyName2, auditRef, false, "TF1", policy2);

        // update the policy with the ignore ownership flag which should be processed
        // and make sure the ownership details haven't changed

        zmsImpl.putPolicy(ctx, domainName, policyName2, auditRef, true, "ignore", policy2);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName2);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF1");
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF1");

        // create a policy without any assertions

        final String policyName3 = "policy3";
        Policy policy3 = zmsTestInitializer.createPolicyObject(domainName, policyName3);
        policy3.setAssertions(new ArrayList<>());
        zmsImpl.putPolicy(ctx, domainName, policyName3, auditRef, false, "TF2", policy3);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName3);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertNull(resourceOwnership.getAssertionsOwner());

        // update the policy ownership - set assertion and remove object owners

        resourceOwnership = new ResourcePolicyOwnership().setAssertionsOwner("TF2");
        zmsImpl.dbService.executePutResourcePolicyOwnership(ctx, domainName, policyName3,
                resourceOwnership, auditRef, null);

        // update the policy with the same ownership flag which should be processed
        // and the object ownership should be set again

        zmsImpl.putPolicy(ctx, domainName, policyName3, auditRef, false, "TF2", policy3);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName3);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF2");

        // create another policy without any assertions

        final String policyName4 = "policy4";
        Policy policy4 = zmsTestInitializer.createPolicyObject(domainName, policyName4);
        policy4.setAssertions(new ArrayList<>());
        zmsImpl.putPolicy(ctx, domainName, policyName4, auditRef, false, "TF3", policy4);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName4);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertNull(resourceOwnership.getAssertionsOwner());

        // update the policy with an assertion and the assertion ownership should be set

        policy4 = zmsTestInitializer.createPolicyObject(domainName, policyName4);
        zmsImpl.putPolicy(ctx, domainName, policyName4, auditRef, false, "TF3", policy4);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName4);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF3");

        // remove the object ownership and set the assertion ownership

        resourceOwnership = new ResourcePolicyOwnership().setAssertionsOwner("TF3");
        zmsImpl.dbService.executePutResourcePolicyOwnership(ctx, domainName, policyName4,
                resourceOwnership, auditRef, null);

        // add a force override flag and the assertion ownership should be set
        policy4 = zmsTestInitializer.createPolicyObject(domainName, policyName4);
        zmsImpl.putPolicy(ctx, domainName, policyName4, auditRef, false, "TF4:force", policy4);

        policy = zmsImpl.getPolicy(ctx, domainName, policyName4);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF4");

        // verify put policy with a different ownership is now rejected

        try {
            zmsImpl.putPolicy(ctx, domainName, policyName4, auditRef, false, "TF5", policy4);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the object without any ownership should fail

        try {
            zmsImpl.deletePolicy(ctx, domainName, policyName3, auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the object with a different ownership should fail

        try {
            zmsImpl.deletePolicy(ctx, domainName, policyName3, auditRef, "TF4");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the object with the correct ownership should work

        zmsImpl.deletePolicy(ctx, domainName, policyName3, auditRef, "TF2");

        // deleting the policy with the ignore flag should work

        zmsImpl.deletePolicy(ctx, domainName, policyName2, auditRef, "ignore");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testResourcePolicyOwnershipAssertions() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "policy-ownership-assertions";
        final String roleName = "role1";
        final String policyName = "policy1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, null);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        // create a policy without any ownership details

        Policy policy1 = zmsTestInitializer.createPolicyObject(domainName, policyName, null, true);
        zmsImpl.putPolicy(ctx, domainName, policyName, auditRef, false, null, policy1);

        // adding a new assertion without any ownership should be fine

        Assertion assertion = new Assertion().setAction("read").setResource(domainName + ":resource1")
                .setRole(role1.getName());
        zmsImpl.putAssertion(ctx, domainName, policyName, auditRef, null, assertion);

        // apply the assertion with ownership and verify it has been set

        zmsImpl.putAssertion(ctx, domainName, policyName, auditRef, "TF1", assertion);
        Policy policy = zmsImpl.getPolicy(ctx, domainName, policyName);
        ResourcePolicyOwnership resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF1");

        // apply the assertion with the same ownership which should be ok

        Assertion assertion1 = zmsImpl.putAssertion(ctx, domainName, policyName, auditRef, "TF1", assertion);
        // apply the assertion with a different value and verify it's rejected

        try {
            zmsImpl.putAssertion(ctx, domainName, policyName, auditRef, "TF2", assertion);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // delete the assertion with different ownership and it should be rejected

        try {
            zmsImpl.deleteAssertion(ctx, domainName, policyName, assertion1.getId(), auditRef, "TF2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // delete the assertion with null ownership and it should be rejected

        try {
            zmsImpl.deleteAssertion(ctx, domainName, policyName, assertion1.getId(), auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // delete the assertion with same ownership and it should be ok
        try {
            zmsImpl.deleteAssertion(ctx, domainName, policyName, assertion1.getId(), auditRef, "TF1");
        } catch (ResourceException ex) {
            fail();
        }

        // apply the assertion again with resource owner TF1
        assertion1 = zmsImpl.putAssertion(ctx, domainName, policyName, auditRef, "TF1", assertion);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF1");

        // apply the assertion again with resource owner TF2 with force override
        assertion1 = zmsImpl.putAssertion(ctx, domainName, policyName, auditRef, "TF2:force", assertion);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF2");

        // apply the assertion with a null value and verify it's rejected

        try {
            zmsImpl.putAssertion(ctx, domainName, policyName, auditRef, null, assertion);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // apply the assertion with the ignore ownership flag which should be ok
        // and verify the ownership details haven't changed

        zmsImpl.putAssertion(ctx, domainName, policyName, auditRef, "ignore", assertion);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF2");

        // delete the assertion with the ignore ownership flag which should be ok
        zmsImpl.deleteAssertion(ctx, domainName, policyName, assertion1.getId(), auditRef, "ignore");
        policy = zmsImpl.getPolicy(ctx, domainName, policyName);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF2");

        // create a new policy without any assertions

        final String policyName2 = "policy2";
        Policy policy3 = zmsTestInitializer.createPolicyObject(domainName, policyName2);
        policy3.setAssertions(new ArrayList<>());
        zmsImpl.putPolicy(ctx, domainName, policyName2, auditRef, false, "TF2", policy3);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName2);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertNull(resourceOwnership.getAssertionsOwner());

        // apply the assertion with empty assertion and it should be ok

        Assertion assertion2 = new Assertion().setAction("read").setResource(domainName + ":resource2")
                .setRole(role1.getName());
        zmsImpl.putAssertion(ctx, domainName, policyName2, auditRef, null, assertion2);

        // apply the assertion with ownership and verify it has been set

        zmsImpl.putAssertion(ctx, domainName, policyName2, auditRef, "TF3", assertion2);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName2);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF3");

        // apply the assertion with force override
        zmsImpl.putAssertion(ctx, domainName, policyName2, auditRef, "TF4:force", assertion2);
        policy = zmsImpl.getPolicy(ctx, domainName, policyName2);
        resourceOwnership = policy.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getAssertionsOwner(), "TF4");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testResourceServiceOwnership() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "service-ownership-object";
        final String serviceName = "service1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // create a service without any ownership details

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(domainName, serviceName,
                "http://localhost", "/usr/bin/athenz", "user1", "group1", null);
        service1.setPublicKeys(null);
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service1);

        ServiceIdentity service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNull(service.getResourceOwnership());

        // put the service with the object ownership set

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF1", service1);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        ResourceServiceIdentityOwnership resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF1");
        assertNull(resourceOwnership.getPublicKeysOwner());
        assertNull(resourceOwnership.getHostsOwner());

        // update the service with an empty ownership which should be rejected

        try {
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // update the service with a different ownership which should be rejected

        try {
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF2", service1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // update the service with the same ownership which should be processed

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF1", service1);

        // now update the service object with a host and public key

        List<PublicKeyEntry> pubKeys = new ArrayList<>();
        pubKeys.add(new PublicKeyEntry().setId("key1").setKey(zmsTestInitializer.getPubKeyK1()));
        service1.setPublicKeys(pubKeys);

        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        service1.setHosts(hosts);

        // update resource ownership
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF1", service1);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF1");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF1");
        assertEquals(resourceOwnership.getHostsOwner(), "TF1");


        // update resource ownership via force override
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF2:force", service1);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF2");
        assertEquals(resourceOwnership.getHostsOwner(), "TF2");

        // update the service with the same ownership value is successful

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF2", service1);

        // update the service with the ignore ownership flag which should be processed
        // but make sure the owner values are not changed

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "ignore", service1);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF2");
        assertEquals(resourceOwnership.getHostsOwner(), "TF2");

        // set the ownership for the public keys only and verify
        // update with a different value fails

        zmsImpl.putResourceServiceIdentityOwnership(ctx, domainName, serviceName, auditRef,
                new ResourceServiceIdentityOwnership().setPublicKeysOwner("TF3"));

        try {
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF4", service1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // update the object and make sure all ownership fields are set

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF3", service1);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF3");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF3");
        assertEquals(resourceOwnership.getHostsOwner(), "TF3");

        // set the ownership for the hosts only and verify
        // update with a different value fails

        zmsImpl.putResourceServiceIdentityOwnership(ctx, domainName, serviceName, auditRef,
                new ResourceServiceIdentityOwnership().setHostsOwner("TF4"));

        try {
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF5", service1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // update the object and make sure all ownership fields are set

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF4", service1);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF4");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF4");
        assertEquals(resourceOwnership.getHostsOwner(), "TF4");

        // set the ownership for the object only and verify
        // update with a different value fails

        zmsImpl.putResourceServiceIdentityOwnership(ctx, domainName, serviceName, auditRef,
                new ResourceServiceIdentityOwnership().setObjectOwner("TF6"));

        try {
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF7", service1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // update the object and make sure all ownership fields are set

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, "TF6", service1);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF6");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF6");
        assertEquals(resourceOwnership.getHostsOwner(), "TF6");

        // create a service without any ownership details

        final String serviceName2 = "service2";
        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(domainName, serviceName2,
                "http://localhost", "/usr/bin/athenz", "user1", "group1", null);
        service2.setPublicKeys(null);
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName2, auditRef, false, null, service2);

        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName2);
        assertNull(service.getResourceOwnership());

        // put the service with public keys and hosts and verify all values are set

        service2 = zmsTestInitializer.createServiceObject(domainName, serviceName2,
                "http://localhost", "/usr/bin/athenz", "user1", "group1", "host2");

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName2, auditRef, false, "TF2", service2);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName2);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF2");
        assertEquals(resourceOwnership.getHostsOwner(), "TF2");

        // deleting the object without any ownership should fail

        try {
            zmsImpl.deleteServiceIdentity(ctx, domainName, serviceName2, auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the object with a different ownership should fail

        try {
            zmsImpl.deleteServiceIdentity(ctx, domainName, serviceName2, auditRef, "TF6");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // deleting the object with the correct ownership should work

        zmsImpl.deleteServiceIdentity(ctx, domainName, serviceName2, auditRef, "TF2");

        // deleting the policy with the ignore flag should work

        zmsImpl.deleteServiceIdentity(ctx, domainName, serviceName, auditRef, "ignore");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testResourceServiceOwnershipPublicKeys() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "service-ownership-public-keys";
        final String serviceName = "service1";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // create a service without any ownership details

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(domainName, serviceName,
                "http://localhost", "/usr/bin/athenz", "user1", "group1", null);
        service1.setPublicKeys(null);
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service1);

        ServiceIdentity service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNull(service.getResourceOwnership());

        // add a public key without any ownership details which should be ok

        PublicKeyEntry publicKey = new PublicKeyEntry().setId("key1").setKey(zmsTestInitializer.getPubKeyK1());
        zmsImpl.putPublicKeyEntry(ctx, domainName, serviceName, "key1", auditRef, null, publicKey);

        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNull(service.getResourceOwnership());

        // add a public key with the object ownership set

        publicKey = new PublicKeyEntry().setId("key2").setKey(zmsTestInitializer.getPubKeyK1());
        zmsImpl.putPublicKeyEntry(ctx, domainName, serviceName, "key2", auditRef, "TF1", publicKey);

        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        ResourceServiceIdentityOwnership resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF1");
        assertNull(resourceOwnership.getHostsOwner());

        // add another public key with null ownership which should be rejected

        publicKey = new PublicKeyEntry().setId("key3").setKey(zmsTestInitializer.getPubKeyK1());
        try {
            zmsImpl.putPublicKeyEntry(ctx, domainName, serviceName, "key3", auditRef, null, publicKey);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // add the same public key with a different ownership value which should be rejected

        try {
            zmsImpl.putPublicKeyEntry(ctx, domainName, serviceName, "key3", auditRef, "TF2", publicKey);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.CONFLICT);
        }

        // add the same public key with the ignore option which should be ok
        // but verify that the ownership hasn't changed

        zmsImpl.putPublicKeyEntry(ctx, domainName, serviceName, "key3", auditRef, "ignore", publicKey);
        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertNull(resourceOwnership.getObjectOwner());
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF1");
        assertNull(resourceOwnership.getHostsOwner());

        // add a new public key with the same keys ownership set

        publicKey = new PublicKeyEntry().setId("key4").setKey(zmsTestInitializer.getPubKeyK1());
        zmsImpl.putPublicKeyEntry(ctx, domainName, serviceName, "key4", auditRef, "TF1", publicKey);

        // create a service with host and object ownership set but not public keys

        final String serviceName2 = "service2";
        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(domainName, serviceName2,
                "http://localhost", "/usr/bin/athenz", "user1", "group1", "host1");
        service2.setPublicKeys(null);
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName2, auditRef, false, "TF2", service2);

        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName2);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getHostsOwner(), "TF2");
        assertNull(resourceOwnership.getPublicKeysOwner());

        // adding public keys without any ownership is going to work fine

        publicKey = new PublicKeyEntry().setId("key1").setKey(zmsTestInitializer.getPubKeyK1());
        zmsImpl.putPublicKeyEntry(ctx, domainName, serviceName2, "key1", auditRef, null, publicKey);

        // adding a public key with an owner will set ownership for keys

        publicKey = new PublicKeyEntry().setId("key2").setKey(zmsTestInitializer.getPubKeyK1());
        zmsImpl.putPublicKeyEntry(ctx, domainName, serviceName2, "key2", auditRef, "TF3", publicKey);

        service = zmsImpl.getServiceIdentity(ctx, domainName, serviceName2);
        resourceOwnership = service.getResourceOwnership();
        assertNotNull(resourceOwnership);
        assertEquals(resourceOwnership.getObjectOwner(), "TF2");
        assertEquals(resourceOwnership.getHostsOwner(), "TF2");
        assertEquals(resourceOwnership.getPublicKeysOwner(), "TF3");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
