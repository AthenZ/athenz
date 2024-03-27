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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.provider.DomainDependencyProviderResponse;
import com.yahoo.athenz.zms.provider.ServiceProviderClient;
import com.yahoo.athenz.zms.provider.ServiceProviderManager;
import org.mockito.Mockito;
import org.testng.annotations.*;

import java.lang.reflect.Field;
import java.util.*;

import static com.yahoo.athenz.zms.ZMSConsts.*;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class ZMSDeleteDomainTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();
    private final long fetchDomainDependencyFrequency = 1L; // For the tests, fetch every second

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS,
                String.valueOf(fetchDomainDependencyFrequency));
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void clearConnections() throws Exception {
        zmsTestInitializer.clearConnections();
        System.clearProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS);
        // Reset ServiceProviderManager Singleton
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        ServiceProviderManager.getInstance(zmsImpl.dbService, zmsImpl).shutdown();
        Field instance = ServiceProviderManager.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    @Test
    public void testDeleteDomainWithGroupConsistency() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName1 = "delete-group1";
        final String domainName2 = "delete-group2";
        final String domainName3 = "delete-group3";
        final String groupName1 = "group1";
        final String groupName2 = "group2";
        final String groupName3 = "group3";
        final String roleName1 = "role1";
        final String roleName2 = "role2";
        final String roleName3 = "role3";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1, "Test Domain1",
                "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2, "Test Domain2",
                "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        TopLevelDomain dom3 = zmsTestInitializer.createTopLevelDomainObject(domainName3, "Test Domain3",
                "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom3);

        Group group1 = zmsTestInitializer.createGroupObject(domainName1, groupName1, "user.joe", "user.jane");
        zmsImpl.putGroup(ctx, domainName1, groupName1, auditRef, false, null, group1);

        Group group2 = zmsTestInitializer.createGroupObject(domainName1, groupName2, "user.joe", "user.jane");
        zmsImpl.putGroup(ctx, domainName1, groupName2, auditRef, false, null, group2);

        Group group3 = zmsTestInitializer.createGroupObject(domainName3, groupName3, "user.joe", "user.jane");
        zmsImpl.putGroup(ctx, domainName3, groupName3, auditRef, false, null, group3);

        // add group2 as a member to roles in 2 different domains

        Role role1 = zmsTestInitializer.createRoleObject(domainName1, roleName1, null, "user.john",
                ResourceUtils.groupResourceName(domainName1, groupName2));
        zmsImpl.putRole(ctx, domainName1, roleName1, auditRef, false, null, role1);

        Role role2 = zmsTestInitializer.createRoleObject(domainName2, roleName2, null, "user.john",
                ResourceUtils.groupResourceName(domainName1, groupName2));
        zmsImpl.putRole(ctx, domainName2, roleName2, auditRef, false, null, role2);

        Role role3 = zmsTestInitializer.createRoleObject(domainName3, roleName3, null, "user.john",
                ResourceUtils.groupResourceName(domainName3, groupName3));
        zmsImpl.putRole(ctx, domainName3, roleName3, auditRef, false, null, role3);

        // we should be able to delete domain3 without any issues since
        // group3 is included in the same domain only

        zmsImpl.deleteTopLevelDomain(ctx, domainName3, auditRef, null);

        // we should not able to delete domain1 since the group from domain1
        // is included in both domain1 and domain2. our error message should
        // only include reference from domain2

        try {
            zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertFalse(ex.getMessage().contains(ResourceUtils.roleResourceName(domainName1, roleName1)));
            assertTrue(ex.getMessage().contains(ResourceUtils.roleResourceName(domainName2, roleName2)));
        }

        // after we delete domain2 we can delete domain1 successfully

        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
    }

    @Test
    public void testDeleteDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // make sure we can't delete system domains

        try {
            zmsImpl.deleteDomain(ctx, auditRef, "sys.auth", "testDeleteDomain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("reserved system domain"));
        }

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                "TestDeleteDomain", null, null, zmsTestInitializer.getAdminUser());
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        zmsImpl.deleteDomain(ctx, auditRef, "testdeletedomain", "testDeleteDomain");

        try {
            zmsImpl.getDomain(ctx, "TestDeleteDomain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteDomainNonExistant() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        try {
            zmsImpl.deleteDomain(ctx, auditRef, "TestDeleteDomainNonExist", "testDeleteDomainNonExistant");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteDomainMissingAuditRef() {
        // create domain and require auditing
        String domain = "testdeletedomainmissingauditref";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                domain, null, null, zmsTestInitializer.getAdminUser());
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        // delete it without an auditRef and catch exception
        try {
            zmsImpl.deleteDomain(ctx, null, domain, "testDeleteDomainMissingAuditRef");
            fail("requesterror not thrown by testDeleteDomainMissingAuditRef.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domain, auditRef, null);
        }
    }

    @Test
    public void testDeleteTopLevelDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("DelTopDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain resDom1 = zmsImpl.getDomain(ctx, "DelTopDom1");
        assertNotNull(resDom1);

        zmsImpl.deleteTopLevelDomain(ctx, "DelTopDom1", auditRef, null);

        // we should get a forbidden exception since the domain
        // no longer exists

        try {
            zmsImpl.getDomain(ctx, "DelTopDom1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testVerifyServiceProvidersAuthorizeDelete() {
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        String domain = "test";
        String caller = "deleteDomain";

        // Mock service provider manager and service provider client

        zmsImpl.serviceProviderManager = Mockito.mock(ServiceProviderManager.class);
        zmsImpl.serviceProviderClient = Mockito.mock(ServiceProviderClient.class);
        Map<String, ServiceProviderManager.DomainDependencyProvider> serviceProvidersWithEndpoints = new HashMap<>();
        boolean isInstance = false;
        String status = PROVIDER_RESPONSE_DENY;
        int numberOfProviders = 20;
        for (int i = 1; i <= numberOfProviders; ++i) {
            ServiceProviderManager.DomainDependencyProvider domainDependencyProvider =
                    new ServiceProviderManager.DomainDependencyProvider("provider" + i, "https://provider" + i, isInstance);
            serviceProvidersWithEndpoints.put("provider" + i, domainDependencyProvider);
            DomainDependencyProviderResponse providerResponse = new DomainDependencyProviderResponse();
            providerResponse.setStatus(status);
            providerResponse.setMessage("message for provider number " + i + "isInstance? " + isInstance);
            Mockito.when(zmsImpl.serviceProviderClient.getDependencyStatus(domainDependencyProvider,
                    domain, ctx.principal().getFullName())).thenReturn(providerResponse);
            isInstance = !isInstance;
            status = status.equals(PROVIDER_RESPONSE_DENY) ? PROVIDER_RESPONSE_ALLOW : PROVIDER_RESPONSE_DENY;
        }
        Mockito.when(zmsImpl.serviceProviderManager.getServiceProvidersWithEndpoints())
                .thenReturn(serviceProvidersWithEndpoints);

        try {
            zmsImpl.verifyServiceProvidersAuthorizeDelete(ctx, domain, caller);
            fail();
        } catch (ResourceException ex) {
            status = PROVIDER_RESPONSE_DENY;
            isInstance = false;
            for (int i = 1; i <= numberOfProviders; ++i) {
                if (status.equals(PROVIDER_RESPONSE_DENY)) {
                    assertTrue(ex.getMessage().contains("message for provider number " + i + "isInstance? " + isInstance));
                } else {
                    assertFalse(ex.getMessage().contains("message for provider number " + i + "isInstance? " + isInstance));
                }
                isInstance = !isInstance;
                status = status.equals(PROVIDER_RESPONSE_DENY) ? PROVIDER_RESPONSE_ALLOW : PROVIDER_RESPONSE_DENY;
            }
        }
        Mockito.verify(zmsImpl.serviceProviderManager, Mockito.times(1)).getServiceProvidersWithEndpoints();
    }

    @Test
    public void testDeleteTopLevelDomainServiceProviderDeclines() {

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String topLevelDomainName = "deltopdomdependencyexist";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(topLevelDomainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain resDom1 = zmsImpl.getDomain(ctx, topLevelDomainName);
        assertNotNull(resDom1);

        // Create services

        ServiceIdentity service = zmsTestInitializer.createServiceObject(topLevelDomainName,
                "Service1", "http://localhost/ser", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, topLevelDomainName, "Service1", auditRef, false, null, service);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(topLevelDomainName,
                "Service2", "http://localhost/ser2", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, topLevelDomainName, "Service2", auditRef, false, null, service2);

        // Set endpoint for services

        RsrcCtxWrapper sysAdminCtx = zmsTestInitializer.contextWithMockPrincipal("deleteMembership");

        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta();
        meta.setProviderEndpoint("https://localhost/service-provider-test-delete");
        zmsImpl.putServiceIdentitySystemMeta(sysAdminCtx, topLevelDomainName, "Service1", "providerendpoint", auditRef, meta);

        ServiceIdentitySystemMeta meta2 = new ServiceIdentitySystemMeta();
        meta2.setProviderEndpoint("https://localhost/service-provider-test-delete2");
        zmsImpl.putServiceIdentitySystemMeta(sysAdminCtx, topLevelDomainName, "Service2", "providerendpoint", auditRef, meta2);

        // Make service2 an instance provider as well as service provider
        makeInstanceProvider(topLevelDomainName, sysAdminCtx, "service2");
        zmsTestInitializer.makeServiceProviders(zmsImpl, sysAdminCtx, Arrays.asList(topLevelDomainName + ".service1",
                topLevelDomainName + ".service2"), fetchDomainDependencyFrequency);

        // Make service1 provider deny deletion for regular user and allow it for admin for service1
        // Make service2 provider deny deletion for all users

        zmsImpl.serviceProviderClient = Mockito.mock(ServiceProviderClient.class);
        DomainDependencyProviderResponse providerResponseDeniesRegularUser = new DomainDependencyProviderResponse();
        providerResponseDeniesRegularUser.setStatus(PROVIDER_RESPONSE_DENY);
        providerResponseDeniesRegularUser.setMessage("provider denied deleting the domain for principal " + ctx.principal().getFullName());
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider = new ServiceProviderManager.DomainDependencyProvider(topLevelDomainName + ".service1", "https://localhost/service-provider-test-delete", false);
        when(zmsImpl.serviceProviderClient.getDependencyStatus(domainDependencyProvider, topLevelDomainName, ctx.principal().getFullName())).thenReturn(providerResponseDeniesRegularUser);
        DomainDependencyProviderResponse providerResponseAllows = new DomainDependencyProviderResponse();
        providerResponseAllows.setStatus(PROVIDER_RESPONSE_ALLOW);
        when(zmsImpl.serviceProviderClient.getDependencyStatus(domainDependencyProvider, topLevelDomainName, sysAdminCtx.principal().getFullName())).thenReturn(providerResponseAllows);
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider2 = new ServiceProviderManager.DomainDependencyProvider(topLevelDomainName + ".service2", "https://localhost/service-provider-test-delete2", true);
        when(zmsImpl.serviceProviderClient.getDependencyStatus(domainDependencyProvider2, topLevelDomainName, ctx.principal().getFullName())).thenReturn(providerResponseDeniesRegularUser);
        DomainDependencyProviderResponse providerResponseDeniesAdmin = new DomainDependencyProviderResponse();
        providerResponseDeniesAdmin.setStatus(PROVIDER_RESPONSE_DENY);
        providerResponseDeniesAdmin.setMessage("provider denied deleting the domain for principal " + sysAdminCtx.principal().getFullName());
        when(zmsImpl.serviceProviderClient.getDependencyStatus(domainDependencyProvider2, topLevelDomainName, sysAdminCtx.principal().getFullName()))
                .thenReturn(providerResponseDeniesAdmin) // Service2 provider will deny deletion in the first call by a sysadmin
                .thenReturn(providerResponseAllows);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchDomainDependencyFrequency) + 50);

        // Denies deletion for regular user by both service providers

        try {
            zmsImpl.deleteTopLevelDomain(ctx, topLevelDomainName, auditRef, null);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Service 'deltopdomdependencyexist.service2' is dependent on domain 'deltopdomdependencyexist'. Error: provider denied deleting the domain for principal user.user1, Service 'deltopdomdependencyexist.service1' is dependent on domain 'deltopdomdependencyexist'. Error: provider denied deleting the domain for principal user.user1\"}");
        }

        // Denies deletion for sys admin by service2 provider

        try {
            zmsImpl.deleteTopLevelDomain(sysAdminCtx, topLevelDomainName, auditRef, null);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Service 'deltopdomdependencyexist.service2' is dependent on domain 'deltopdomdependencyexist'. Error: provider denied deleting the domain for principal user.testadminuser\"}");
        }


        // Now the client will start to allow deletions for sysadmin

        zmsImpl.deleteTopLevelDomain(sysAdminCtx, topLevelDomainName, auditRef, null);
    }

    @Test
    public void testDeleteTopLevelDomainDependencyExist() {

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String topLevelDomainName = "deltopdomdependencyexist";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(topLevelDomainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain resDom1 = zmsImpl.getDomain(ctx, topLevelDomainName);
        assertNotNull(resDom1);

        registerDependency(ctx, topLevelDomainName, zmsImpl, topLevelDomainName, "service-provider1");

        // We can't delete a domain that has service dependency

        try {
            zmsImpl.deleteTopLevelDomain(ctx, topLevelDomainName, auditRef, null);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Remove domain" +
                    " 'deltopdomdependencyexist' dependency from the following" +
                    " service(s):deltopdomdependencyexist.service-provider1\"}");
        }

        // Register another dependency, verify it appears in the delete error list

        registerDependency(ctx, topLevelDomainName, zmsImpl, topLevelDomainName, "service-provider2");
        try {
            zmsImpl.deleteTopLevelDomain(ctx, topLevelDomainName, auditRef, null);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Remove domain" +
                    " 'deltopdomdependencyexist' dependency from the following service(s):" +
                    "deltopdomdependencyexist.service-provider1, deltopdomdependencyexist.service-provider2\"}");
        }

        // Remove one of the dependencies, verify the error message is updated

        deRegisterDependency(topLevelDomainName, zmsImpl, topLevelDomainName, "service-provider1");
        try {
            zmsImpl.deleteTopLevelDomain(ctx, topLevelDomainName, auditRef, null);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Remove domain" +
                    " 'deltopdomdependencyexist' dependency from the following" +
                    " service(s):deltopdomdependencyexist.service-provider2\"}");
        }

        // Now remove the dependency but set endpoint for the service - verify the error message change

        RsrcCtxWrapper sysAdminCtx = zmsTestInitializer.contextWithMockPrincipal("deleteMembership");
        zmsImpl.deleteDomainDependency(sysAdminCtx, topLevelDomainName,
                topLevelDomainName + ".service-provider2", auditRef);

        // Verify dependency was removed

        DomainList dependentDomainList = zmsImpl.getDependentDomainList(sysAdminCtx,
                topLevelDomainName + ".service-provider1");
        assertEquals(dependentDomainList.getNames().size(), 0);
        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta();
        meta.setProviderEndpoint("https://localhost/testendpoint");
        zmsImpl.putServiceIdentitySystemMeta(ctx, topLevelDomainName, "service-provider2",
                "providerendpoint", auditRef, meta);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchDomainDependencyFrequency) + 50);

        try {
            zmsImpl.deleteTopLevelDomain(ctx, topLevelDomainName, auditRef, null);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Service '" +
                    topLevelDomainName + ".service-provider2' is dependent on domain '" + topLevelDomainName +
                    "'. Error: Exception thrown during call to provider: Failed to get response from" +
                    " server: https://localhost/testendpoint\"}");
        }

        // Now make the provider approve the deletion

        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider =
                new ServiceProviderManager.DomainDependencyProvider(topLevelDomainName + ".service-provider2",
                        "https://localhost/testendpoint", false);
        DomainDependencyProviderResponse providerResponse = new DomainDependencyProviderResponse();
        providerResponse.setStatus("allow");
        ServiceProviderClient serviceProviderClientMock = Mockito.mock(ServiceProviderClient.class);
        when(serviceProviderClientMock.getDependencyStatus(domainDependencyProvider, topLevelDomainName,
                ctx.principal().getFullName())).thenReturn(providerResponse);
        zmsImpl.serviceProviderClient = serviceProviderClientMock;
        zmsImpl.deleteTopLevelDomain(ctx, topLevelDomainName, auditRef, null);
    }

    @Test
    public void testDeleteTopLevelDomainChildExist() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("DelTopChildDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        SubDomain dom2 = zmsTestInitializer.createSubDomainObject("DelSubDom2", "DelTopChildDom1",
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(ctx, "DelTopChildDom1", auditRef, null, dom2);

        // we can't delete Dom1 since Dom2 still exists

        try {
            zmsImpl.deleteTopLevelDomain(ctx, "DelTopChildDom1", auditRef, null);
            fail("requesterror not thrown.");
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        zmsImpl.deleteSubDomain(ctx, "DelTopChildDom1", "DelSubDom2", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "DelTopChildDom1", auditRef, null);
    }

    @Test
    public void testDeleteTopLevelDomainNonExistant() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        try {
            zmsImpl.deleteTopLevelDomain(ctx, "NonExistantDomain", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteTopLevelDomainNonExistantNoAuditRef() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        try {
            zmsImpl.deleteTopLevelDomain(ctx, "NonExistantDomain", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteTopLevelDomainMissingAuditRef() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // create domain and require auditing
        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                "TopDomainAuditRequired", null, null, zmsTestInitializer.getAdminUser());
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        // delete it without an auditRef and catch exception
        try {
            zmsImpl.deleteTopLevelDomain(ctx, "TopDomainAuditRequired", null, null);
            fail("requesterror not thrown by deleteTopLevelDomain.");
        } catch (ResourceException ex) {
            System.out.println("*** " + ex.getMessage());
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, "TopDomainAuditRequired", auditRef, null);
        }
    }

    @Test
    public void testDeleteSubDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("DelSubDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        SubDomain dom2 = zmsTestInitializer.createSubDomainObject("DelSubDom2", "DelSubDom1",
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(ctx, "DelSubDom1", auditRef, null, dom2);

        Domain resDom1 = zmsImpl.getDomain(ctx, "DelSubDom1.DelSubDom2");
        assertNotNull(resDom1);

        zmsImpl.deleteSubDomain(ctx, "DelSubDom1", "DelSubDom2", auditRef, null);

        // we should get a forbidden exception since the domain
        // no longer exists

        try {
            zmsImpl.getDomain(ctx, "DelSubDom1.DelSubDom2");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "DelSubDom1", auditRef, null);
    }

    @Test
    public void testDeleteSubDomainNotAuthorized() {

        final String domainName = "delsubdom1authz";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        SubDomain dom2 = zmsTestInitializer.createSubDomainObject("DelSubDom2", domainName,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(ctx, "DelSubDom1Authz", auditRef, null, dom2);

        Domain resDom1 = zmsImpl.getDomain(ctx, domainName + ".DelSubDom2");
        assertNotNull(resDom1);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal2 = principalAuthority.authenticate("v=U1;d=user;n=user2;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext ctx2 = zmsTestInitializer.createResourceContext(principal2);

        // using a different principal, this operation should get rejected

        try {
            zmsImpl.deleteSubDomain(ctx2, domainName, "DelSubDom2", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Principal is not authorized to delete domain: delsubdom1authz.delsubdom2"));
        }

        // with our standard principal we should be able to delete the subdomain

        zmsImpl.deleteSubDomain(ctx, domainName, "DelSubDom2", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testDeleteSubDomainChildExist() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("DelSubChildDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        SubDomain dom2 = zmsTestInitializer.createSubDomainObject("DelSubDom2", "DelSubChildDom1",
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postSubDomain(ctx, "DelSubChildDom1", auditRef, null, dom2);

        SubDomain dom3 = zmsTestInitializer.createSubDomainObject("DelSubDom3", "DelSubChildDom1.DelSubDom2",
                "Test Domain3", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(ctx, "DelSubChildDom1.DelSubDom2", auditRef, null, dom3);

        // we can't delete Dom2 since Dom3 still exists

        try {
            zmsImpl.deleteSubDomain(ctx, "DelSubChildDom1", "DelSubDom2", auditRef, null);
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        zmsImpl.deleteSubDomain(ctx, "DelSubChildDom1.DelSubDom2", "DelSubDom3", auditRef, null);
        zmsImpl.deleteSubDomain(ctx, "DelSubChildDom1", "DelSubDom2", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "DelSubChildDom1", auditRef, null);
    }

    @Test
    public void testDeleteSubDomainNonExistant() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                "ExistantTopDomain", null, null, zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);
        try {
            zmsImpl.deleteSubDomain(ctx, "ExistantTopDomain", "NonExistantSubDomain", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        zmsImpl.deleteTopLevelDomain(ctx, "ExistantTopDomain", auditRef, null);
    }

    @Test
    public void testDeleteSubDomainSubAndTopNonExistant() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        try {
            zmsImpl.deleteSubDomain(ctx, "NonExistantTopDomain", "NonExistantSubDomain", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testDeleteSubDomainMissingAuditRef() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                "ExistantTopDomain2", null, null, zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        SubDomain subDom = zmsTestInitializer.createSubDomainObject(
                "ExistantSubDom2", "ExistantTopDomain2",
                null, null, zmsTestInitializer.getAdminUser());
        subDom.setAuditEnabled(true);
        zmsImpl.postSubDomain(ctx, "ExistantTopDomain2", auditRef, null, subDom);

        try {
            zmsImpl.deleteSubDomain(ctx, "ExistantTopDomain2", "ExistantSubDom2", null, null);
            fail("requesterror not thrown by deleteSubDomain.");
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteSubDomain(ctx, "ExistantTopDomain2", "ExistantSubDom2", auditRef, null);
            zmsImpl.deleteTopLevelDomain(ctx, "ExistantTopDomain2", auditRef, null);
        }
    }

    @Test
    public void testDeleteDomainTemplateNull() {
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        String userId = "user1";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password", 0, userAuthority);
        assertNotNull(principal);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        try {
            zmsImpl.deleteDomainTemplate(rsrcCtx1, "dom1", null, "zms");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteDomainTemplate() {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal1 = principalAuthority.authenticate("v=U1;d=user;n=user1;s=signature",
                "10.11.12.13", "GET", null);
        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal1);
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        try{
            zmsImpl.deleteDomainTemplate(rsrcCtx1, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testDeleteDomainRoleMemberInvalidDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        try {
            zmsImpl.deleteDomainRoleMember(ctx, "invalid-domain", "user.joe", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
    }

    @Test
    public void testDeleteDomainRoleMember() {

        String domainName = "deletedomainrolemember2";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.jack", "user.janie");
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        Role role2 = zmsTestInitializer.createRoleObject(domainName, "role2", null,
                "user.janie", "user.jane");
        zmsImpl.putRole(ctx, domainName, "role2", auditRef, false, null, role2);

        Role role3 = zmsTestInitializer.createRoleObject(domainName, "role3", null,
                "user.jack", "user.jane");
        zmsImpl.putRole(ctx, domainName, "role3", auditRef, false, null, role3);

        Role role4 = zmsTestInitializer.createRoleObject(domainName, "role4", null,
                "user.jack", null);
        zmsImpl.putRole(ctx, domainName, "role4", auditRef, false, null, role4);

        Role role5 = zmsTestInitializer.createRoleObject(domainName, "role5", null,
                "user.jack-service", "user.jane");
        zmsImpl.putRole(ctx, domainName, "role5", auditRef, false, null, role5);

        DomainRoleMembers domainRoleMembers = zmsImpl.getDomainRoleMembers(ctx, domainName);
        assertEquals(domainName, domainRoleMembers.getDomainName());

        List<DomainRoleMember> members = domainRoleMembers.getMembers();
        assertNotNull(members);
        assertEquals(5, members.size());
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack", "role1", "role3", "role4");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.janie", "role1", "role2");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jane", "role2", "role3", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack-service", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, zmsTestInitializer.getAdminUser(), "admin");

        // with unknown user we get back 404

        try {
            zmsImpl.deleteDomainRoleMember(ctx, domainName, "user.unknown", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        members = domainRoleMembers.getMembers();
        assertNotNull(members);
        assertEquals(5, members.size());
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack", "role1", "role3", "role4");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.janie", "role1", "role2");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jane", "role2", "role3", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack-service", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, zmsTestInitializer.getAdminUser(), "admin");

        // now remove a known user

        zmsImpl.deleteDomainRoleMember(ctx, domainName, "user.jack", auditRef);

        domainRoleMembers = zmsImpl.getDomainRoleMembers(ctx, domainName);
        assertEquals(domainName, domainRoleMembers.getDomainName());

        members = domainRoleMembers.getMembers();
        assertNotNull(members);
        assertEquals(4, members.size());
        ZMSTestUtils.verifyDomainRoleMember(members, "user.janie", "role1", "role2");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jane", "role2", "role3", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, "user.jack-service", "role5");
        ZMSTestUtils.verifyDomainRoleMember(members, zmsTestInitializer.getAdminUser(), "admin");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testDeleteUserDomainNull() {
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        String userId = "user1";
        Principal principal = SimplePrincipal.create("user", userId, userId + ":password", 0, userAuthority);
        assertNotNull(principal);
        ((SimplePrincipal) principal).setUnsignedCreds(userId);
        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        try {
            zmsImpl.deleteUserDomain(rsrcCtx1, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteUserDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        UserDomain dom1 = zmsTestInitializer.createUserDomainObject("john-doe",
                "Test Domain Delete User Domain", "testDeleteOrg");
        zmsImpl.postUserDomain(ctx, "john-doe", auditRef, null, dom1);

        zmsImpl.deleteUserDomain(ctx, "john-doe", auditRef, null);

        try {
            zmsImpl.getDomain(ctx, "john-doe");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteServiceIdentityDependencyExist() {

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceDelDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject("ServiceDelDom2",
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject("ServiceDelDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceDelDom1", "Service1", auditRef, false, null, service1);

        ServiceIdentity serviceRes1 = zmsImpl.getServiceIdentity(ctx, "ServiceDelDom1",
                "Service1");
        assertNotNull(serviceRes1);

        // add a domain dependency on the service and verify it prevents service deletion

        RsrcCtxWrapper providerCtx = registerDependency(ctx, "ServiceDelDom1".toLowerCase(), zmsImpl,
                "ServiceDelDom1".toLowerCase(), "Service1".toLowerCase());
        try {
            zmsImpl.deleteServiceIdentity(providerCtx, "ServiceDelDom1", "Service1", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Remove service" +
                    " 'servicedeldom1.service1' dependency from the following domain(s):servicedeldom1\"}");
        }

        // Register another dependency, verify it appears in the delete error list

        providerCtx = registerDependency(ctx, "ServiceDelDom2".toLowerCase(), zmsImpl,
                "ServiceDelDom1".toLowerCase(), "Service1".toLowerCase());
        try {
            zmsImpl.deleteServiceIdentity(providerCtx, "ServiceDelDom1", "Service1", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message:" +
                    " \"Remove service 'servicedeldom1.service1' dependency from the following" +
                    " domain(s):servicedeldom1, servicedeldom2\"}");
        }

        // Remove one of the dependencies, verify the error message is updated

        deRegisterDependency("ServiceDelDom1".toLowerCase(), zmsImpl, "ServiceDelDom1".toLowerCase(),
                "Service1".toLowerCase());
        try {
            zmsImpl.deleteServiceIdentity(providerCtx, "ServiceDelDom1", "Service1", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message:" +
                    " \"Remove service 'servicedeldom1.service1' dependency from the following" +
                    " domain(s):servicedeldom2\"}");
        }
        deRegisterDependency("ServiceDelDom2".toLowerCase(), zmsImpl, "ServiceDelDom1".toLowerCase(),
                "Service1".toLowerCase());
        zmsImpl.deleteServiceIdentity(ctx, "ServiceDelDom1", "Service1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "ServiceDelDom1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "ServiceDelDom2", auditRef, null);
    }

    private void makeInstanceProvider(String topLevelDomainName, RsrcCtxWrapper sysAdminCtx,
            String serviceInstanceProvider) {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String instanceProvidersRoleName = "instance-providers";
        Role role = new Role();
        role.setName(instanceProvidersRoleName);
        RoleMember roleMember = new RoleMember();
        roleMember.setMemberName(topLevelDomainName + "." + serviceInstanceProvider);
        List<RoleMember> roleMembers = Arrays.asList(roleMember);
        role.setRoleMembers(roleMembers);
        zmsImpl.putRole(sysAdminCtx, "sys.auth", instanceProvidersRoleName, auditRef, false, null, role);

        String instanceProviderPolicyName = "instanceProviderPolicy";
        Policy policy = new Policy();
        policy.setName(instanceProviderPolicyName);
        Assertion assertion = new Assertion();
        assertion.setAction("launch");
        assertion.setResource("sys.auth:instance");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setRole("sys.auth:role." + instanceProvidersRoleName);
        List<Assertion> assertions = List.of(assertion);
        policy.setAssertions(assertions);
        zmsImpl.putPolicy(sysAdminCtx, "sys.auth", instanceProviderPolicyName, auditRef, false, null, policy);
    }

    private RsrcCtxWrapper registerDependency(RsrcCtxWrapper mockDomRsrcCtx, String domainName,
            ZMSImpl zmsImpl, String serviceProviderDomain, String serviceProviderName) {

        final String auditRef = zmsTestInitializer.getAuditRef();

        // Check if service provider exists. If not create it

        try {
            zmsImpl.getServiceIdentity(mockDomRsrcCtx, serviceProviderDomain, serviceProviderName);
        } catch (ResourceException ex) {
            ServiceIdentity serviceProvider = zmsTestInitializer.createServiceObject(serviceProviderDomain,
                    serviceProviderName, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");

            zmsImpl.putServiceIdentity(mockDomRsrcCtx, serviceProviderDomain, serviceProviderName,
                    auditRef, false, null, serviceProvider);
        }

        String fullServiceProviderName = serviceProviderDomain + "." + serviceProviderName;

        // Create service provider role if it it doesn't exist

        String sysAdminDomainName = "sys.auth";
        String serviceProvidersRoleName = "service_providers";
        try {
            zmsImpl.getRole(mockDomRsrcCtx, sysAdminDomainName, serviceProvidersRoleName, false, false, false);
        } catch (ResourceException ex) {
            Role role = new Role();
            role.setName(serviceProvidersRoleName);
            role.setRoleMembers(new ArrayList<>());
            zmsImpl.putRole(mockDomRsrcCtx, sysAdminDomainName, serviceProvidersRoleName, auditRef, false, null, role);
        }

        // Add service to authorized service providers list

        Membership membership = new Membership();
        membership.setMemberName(fullServiceProviderName);

        RsrcCtxWrapper sysAdminContext = zmsTestInitializer.contextWithMockPrincipal("putMembership");
        zmsImpl.putMembership(sysAdminContext, sysAdminDomainName, serviceProvidersRoleName,
                fullServiceProviderName, auditRef, false, null, membership);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchDomainDependencyFrequency) + 50);

        // Now make the service provider put a dependency on the  domain

        RsrcCtxWrapper serviceProviderCtx = zmsTestInitializer.contextWithMockPrincipal(
                "putDomainDependency", serviceProviderDomain, serviceProviderName);
        DependentService dependentService = new DependentService().setService(fullServiceProviderName);
        zmsImpl.putDomainDependency(serviceProviderCtx, domainName, auditRef, dependentService);
        return serviceProviderCtx;
    }

    private void deRegisterDependency(final String domainName, ZMSImpl zmsImpl, final String serviceProviderDomain,
            final String serviceProviderName) {

        final String auditRef = zmsTestInitializer.getAuditRef();

        String fullServiceProviderName = serviceProviderDomain + "." + serviceProviderName;
        RsrcCtxWrapper serviceProviderCtx = zmsTestInitializer.contextWithMockPrincipal("putDomainDependency",
                serviceProviderDomain, serviceProviderName);
        zmsImpl.deleteDomainDependency(serviceProviderCtx, domainName, fullServiceProviderName, auditRef);
    }

    @Test
    public void testDeleteWithMetaAttributes() {

        System.setProperty(ZMS_PROP_DOMAIN_DELETE_META_ATTRIBUTES, "account,gcpproject,azuresubscription");

        final String domainName = "del-with-meta-attrs";
        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        zmsTestInitializer.setupPrincipalSystemMetaDelete(zmsImpl, ctx.principal().getFullName(),
                domainName, "domain", "account", "gcpproject", "azuresubscription", "public-cloud");

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        DomainMeta meta = new DomainMeta();

        meta.setAccount("acct-1234");
        meta.setGcpProject("gcp-project");
        meta.setGcpProjectNumber("1234");
        meta.setAzureSubscription("azure-subscription");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_ACCOUNT, auditRef, meta);
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_GCP_PROJECT, auditRef, meta);
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);

        try {
            zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
            fail("request-error not thrown.");
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Domain has non-empty account attribute"));
        }

        // remove the aws account and try again

        meta.setAccount(null);
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_ACCOUNT, auditRef, meta);

        try {
            zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
            fail("request-error not thrown.");
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Domain has non-empty gcp-project attribute"));
        }

        // remove the gcp project and try again

        meta.setGcpProject(null);
        meta.setGcpProjectNumber(null);
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_GCP_PROJECT, auditRef, meta);

        try {
            zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
            fail("request-error not thrown.");
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Domain has non-empty azure-subscription attribute"));
        }

        meta.setAzureSubscription(null);
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsTestInitializer.cleanupPrincipalSystemMetaDelete(zmsImpl, "domain");

        System.clearProperty(ZMS_PROP_DOMAIN_DELETE_META_ATTRIBUTES);
    }
}
