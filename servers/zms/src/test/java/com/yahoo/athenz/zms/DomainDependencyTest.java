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

import com.yahoo.athenz.zms.provider.DomainDependencyProviderResponse;
import com.yahoo.athenz.zms.provider.ServiceProviderClient;
import com.yahoo.athenz.zms.provider.ServiceProviderManager;
import org.mockito.Mockito;
import org.testng.annotations.*;

import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.yahoo.athenz.zms.ZMSConsts.*;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class DomainDependencyTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();
    private final long fetchFrequency = 1L; // For the test, fetch every second

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
        System.setProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS, String.valueOf(fetchFrequency));

        // Reset ServiceProviderManager Singleton
        resetServiceProviderManager();
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void clearConnections() throws Exception {

        zmsTestInitializer.clearConnections();

        // Reset ServiceProviderManager Singleton
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        ServiceProviderManager.getInstance(zmsImpl.dbService, zmsImpl).shutdown();
        resetServiceProviderManager();

        System.clearProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS);
    }

    void resetServiceProviderManager() throws Exception {
        Field instance = ServiceProviderManager.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    @Test
    public void testDomainDependency() {

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        final String auditRef = zmsTestInitializer.getAuditRef();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        // Create top level domain and subdomain.
        // Then create a service in the subdomain and make it a service provider.

        final String topLevelDomainName = "test-domain1-dependency";
        final String subDomainName = "sub-test-domain1";
        final String fullSubDomainName = topLevelDomainName + "." + subDomainName;
        final String serviceProviderName = "service-provider";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(topLevelDomainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject(subDomainName,
                topLevelDomainName, "Sub Test Domain 1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(ctx, topLevelDomainName, auditRef, null, subDom1);

        ServiceIdentity serviceProvider = zmsTestInitializer.createServiceObject(fullSubDomainName,
                serviceProviderName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, fullSubDomainName, serviceProviderName, auditRef, false, null, serviceProvider);

        final String sysAdminDomainName = "sys.auth";
        final String serviceProvidersRoleName = "service_providers";
        final String fullServiceProviderName = fullSubDomainName + "." + serviceProviderName;

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember authorizedServiceRoleMember = new RoleMember();
        authorizedServiceRoleMember.setMemberName(fullServiceProviderName);
        roleMembers.add(authorizedServiceRoleMember);
        Role role = new Role();
        role.setName(serviceProvidersRoleName);
        role.setRoleMembers(roleMembers);

        zmsImpl.putRole(ctx, sysAdminDomainName, serviceProvidersRoleName, auditRef, false, null, role);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

        // Now switch to the service provider context and put a dependency on the top level domain

        RsrcCtxWrapper serviceProviderCtx = zmsTestInitializer.contextWithMockPrincipal("putDomainDependency",
                fullSubDomainName, serviceProviderName);

        DependentService dependentService = new DependentService().setService(fullServiceProviderName);
        zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, auditRef, dependentService);

        ServiceIdentityList dependentServiceList = zmsImpl.getDependentServiceList(ctx, topLevelDomainName);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullServiceProviderName);

        DomainList domainList = zmsImpl.getDependentDomainList(ctx, fullServiceProviderName);
        assertEquals(domainList.getNames().size(), 1);
        assertEquals(domainList.getNames().get(0), topLevelDomainName);

        // Create a new top level domain and add a dependency to it as well

        String secondTopLevelDomain = "test-domain2-dependency";
        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(secondTopLevelDomain,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        zmsImpl.putDomainDependency(serviceProviderCtx, secondTopLevelDomain, auditRef, dependentService);
        dependentServiceList = zmsImpl.getDependentServiceList(ctx, secondTopLevelDomain);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullServiceProviderName);

        domainList = zmsImpl.getDependentDomainList(ctx, fullServiceProviderName);
        assertEquals(domainList.getNames().size(), 2);
        assertTrue(domainList.getNames().contains(topLevelDomainName));
        assertTrue(domainList.getNames().contains(secondTopLevelDomain));

        // Now delete the original dependency and verify it was removed

        zmsImpl.deleteDomainDependency(serviceProviderCtx, topLevelDomainName,
                fullSubDomainName + "." + serviceProviderName, auditRef);

        dependentServiceList = zmsImpl.getDependentServiceList(ctx, topLevelDomainName);
        assertEquals(dependentServiceList.getNames().size(), 0);

        // Verify it didn't affect the other domain

        dependentServiceList = zmsImpl.getDependentServiceList(ctx, secondTopLevelDomain);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullServiceProviderName);

        domainList = zmsImpl.getDependentDomainList(ctx, fullServiceProviderName);
        assertEquals(domainList.getNames().size(), 1);
        assertTrue(domainList.getNames().contains(secondTopLevelDomain));

        zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, auditRef, dependentService);
        dependentServiceList = zmsImpl.getDependentServiceList(ctx, secondTopLevelDomain);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullServiceProviderName);

        domainList = zmsImpl.getDependentDomainList(ctx, fullServiceProviderName);
        assertEquals(domainList.getNames().size(), 2);
        assertTrue(domainList.getNames().contains(topLevelDomainName));
        assertTrue(domainList.getNames().contains(secondTopLevelDomain));

        // Finally delete again but this time as a system administrator

        RsrcCtxWrapper sysAdminCtx = zmsTestInitializer.contextWithMockPrincipal("deleteDomainDependency");
        zmsImpl.deleteDomainDependency(sysAdminCtx, topLevelDomainName, fullServiceProviderName, auditRef);

        dependentServiceList = zmsImpl.getDependentServiceList(ctx, topLevelDomainName);
        assertEquals(dependentServiceList.getNames().size(), 0);

        // Verify it didn't affect the other domain

        dependentServiceList = zmsImpl.getDependentServiceList(ctx, secondTopLevelDomain);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullServiceProviderName);

        domainList = zmsImpl.getDependentDomainList(ctx, fullServiceProviderName);
        assertEquals(domainList.getNames().size(), 1);
        assertTrue(domainList.getNames().contains(secondTopLevelDomain));

        // Trying to delete test-domain2-dependency will fail as the service
        // test-domain1-dependency.sub-test-domain1.service-provider is still dependent on it

        try {
            zmsImpl.deleteTopLevelDomain(ctx, secondTopLevelDomain, auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Remove domain " +
                    "'test-domain2-dependency' dependency from the following service(s):" +
                    "test-domain1-dependency.sub-test-domain1.service-provider\"}");
        }

        // Now remove the dependency but set endpoint for the service.
        // It will not be responsive so exception will be thrown

        zmsImpl.deleteDomainDependency(sysAdminCtx, secondTopLevelDomain, fullServiceProviderName, auditRef);
        // Verify dependency was removed
        DomainList dependentDomainList = zmsImpl.getDependentDomainList(ctx, fullServiceProviderName);
        assertEquals(dependentDomainList.getNames().size(), 0);
        // Setting endpoint
        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta();
        meta.setProviderEndpoint("https://localhost/service-provider");
        zmsImpl.putServiceIdentitySystemMeta(sysAdminCtx, fullSubDomainName, serviceProviderName,
                "providerendpoint", auditRef, meta);

        // Wait for ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

        try {
            zmsImpl.deleteTopLevelDomain(ctx, secondTopLevelDomain, auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Service " +
                    "'test-domain1-dependency.sub-test-domain1.service-provider' is dependent on domain " +
                    "'test-domain2-dependency'. Error: Exception thrown during call to provider: Failed " +
                    "to get response from server: https://localhost/service-provider\"}");
        }

        // Now make the service provider client approve deletion of the domains

        ServiceProviderClient serviceProviderClient = Mockito.mock(ServiceProviderClient.class);
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider =
                new ServiceProviderManager.DomainDependencyProvider(fullServiceProviderName, "https://localhost/service-provider", false);
        DomainDependencyProviderResponse response = new DomainDependencyProviderResponse();
        response.setStatus(PROVIDER_RESPONSE_ALLOW);
        when(serviceProviderClient.getDependencyStatus(domainDependencyProvider, secondTopLevelDomain,
                ctx.principal().getFullName())).thenReturn(response);
        when(serviceProviderClient.getDependencyStatus(domainDependencyProvider, fullSubDomainName,
                ctx.principal().getFullName())).thenReturn(response);
        when(serviceProviderClient.getDependencyStatus(domainDependencyProvider, topLevelDomainName,
                ctx.principal().getFullName())).thenReturn(response);
        zmsImpl.serviceProviderClient = serviceProviderClient;

        zmsImpl.deleteTopLevelDomain(ctx, secondTopLevelDomain, auditRef, null);
        zmsImpl.deleteSubDomain(ctx, topLevelDomainName, subDomainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, topLevelDomainName, auditRef, null);
    }

    @Test
    public void testDomainDependencyAuth() {
        long fetchFrequency = 1L; // For the test, fetch every second
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        final String auditRef = zmsTestInitializer.getAuditRef();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        // Clear ZMS_PROP_AUDIT_REF_CHECK_OBJECTS as we usually use the default settings role and group

        System.clearProperty(ZMS_PROP_AUDIT_REF_CHECK_OBJECTS);
        zmsImpl.dbService.setAuditRefObjectBits();

        // Create top level domain and subdomain.
        // Then create a service in the subdomain and make it a service provider.

        final String topLevelDomainName = "test-domain1-auth";
        final String subDomainName = "sub-test-domain1";
        final String fullSubDomainName = topLevelDomainName + "." + subDomainName;
        final String serviceProviderName = "service-provider";
        final String fullServiceProviderName = fullSubDomainName + "." + serviceProviderName;

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(topLevelDomainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject(subDomainName,
                topLevelDomainName, "Sub Test Domain 1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(ctx, topLevelDomainName, auditRef, null, subDom1);

        ServiceIdentity serviceProvider = zmsTestInitializer.createServiceObject(fullSubDomainName,
                serviceProviderName, "http://localhost/service", "/usr/bin/java", "root",
                "users", "host1");

        ServiceIdentity someOtherServiceProvider = zmsTestInitializer.createServiceObject(fullSubDomainName,
                "some-other-service", "http://localhost/other-service", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, fullSubDomainName, serviceProviderName, auditRef, false, null, serviceProvider);
        zmsImpl.putServiceIdentity(ctx, fullSubDomainName, "some-other-service", auditRef, false, null, someOtherServiceProvider);

        DependentService dependentService = new DependentService().setService(fullServiceProviderName);
        try {
            zmsImpl.putDomainDependency(ctx, topLevelDomainName, auditRef, dependentService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"user.user1 is not " +
                    "an authorized service provider\"}");
        }

        try {
            zmsImpl.deleteDomainDependency(ctx, topLevelDomainName, fullServiceProviderName, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"user.user1 is not " +
                    "an authorized service provider\"}");
        }

        // Now make the service a service provider

        String sysAdminDomainName = "sys.auth";
        String serviceProvidersRoleName = "service_providers";

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember authorizedServiceRoleMember = new RoleMember();
        authorizedServiceRoleMember.setMemberName(fullServiceProviderName);
        RoleMember authorizedServiceRoleMemberOther = new RoleMember();
        authorizedServiceRoleMemberOther.setMemberName(fullSubDomainName + "." + "some-other-service");
        roleMembers.add(authorizedServiceRoleMember);
        roleMembers.add(authorizedServiceRoleMemberOther);
        Role role = new Role();
        role.setName(serviceProvidersRoleName);
        role.setRoleMembers(roleMembers);
        zmsImpl.putRole(ctx, sysAdminDomainName, serviceProvidersRoleName, auditRef, false, null, role);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

        // Switch to service provider context

        RsrcCtxWrapper serviceProviderCtx = zmsTestInitializer.contextWithMockPrincipal("putDomainDependency",
                fullSubDomainName, serviceProviderName);

        // Specify invalid domain

        try {
            zmsImpl.putDomainDependency(serviceProviderCtx, "some.unknown.domain", auditRef, dependentService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (404): {code: 404, message: \"putdomaindependency: " +
                    "Unknown domain: some.unknown.domain\"}");
        }

        try {
            zmsImpl.deleteDomainDependency(serviceProviderCtx, "some.unknown.domain", fullServiceProviderName, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (404): {code: 404, message: \"putdomaindependency: " +
                    "Unknown domain: some.unknown.domain\"}");
        }

        // Try to register a different service provider. Specified service will be ignored and the principal will be used as the service

        DependentService dependentServiceOther = new DependentService().setService(fullSubDomainName + "." + "some-other-service");
        zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, auditRef, dependentServiceOther);
        DomainList dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx,
                fullSubDomainName + "." + "some-other-service");
        assertTrue(dependentDomainList.getNames().isEmpty());
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullServiceProviderName);
        assertEquals(dependentDomainList.getNames().size(), 1);
        assertEquals(dependentDomainList.getNames().get(0), topLevelDomainName);

        zmsImpl.deleteDomainDependency(serviceProviderCtx, topLevelDomainName, fullServiceProviderName, auditRef);
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullServiceProviderName);
        assertTrue(dependentDomainList.getNames().isEmpty());

        // Now test api with system admin

        RsrcCtxWrapper sysAdminCtx = zmsTestInitializer.contextWithMockPrincipal("putDomainDependency");

        // Try and register to a service which is not a listed service provider

        try {
            DependentService dependentServiceNone = new DependentService().setService(fullSubDomainName + "." + "none-service-provider");
            zmsImpl.putDomainDependency(sysAdminCtx, topLevelDomainName, auditRef, dependentServiceNone);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: " +
                    "\"test-domain1-auth.sub-test-domain1.none-service-provider is not an authorized service provider\"}");
        }

        // Register and de-register a service provider using system admin

        zmsImpl.putDomainDependency(sysAdminCtx, topLevelDomainName, auditRef, dependentService);
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullServiceProviderName);
        assertEquals(dependentDomainList.getNames().size(), 1);
        assertEquals(dependentDomainList.getNames().get(0), topLevelDomainName);
        zmsImpl.deleteDomainDependency(sysAdminCtx, topLevelDomainName, fullServiceProviderName, auditRef);
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullServiceProviderName);
        assertTrue(dependentDomainList.getNames().isEmpty());

        // Register dependency using system admin but this time remove from service_providers role

        zmsImpl.putDomainDependency(sysAdminCtx, topLevelDomainName, auditRef, dependentService);
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullServiceProviderName);
        assertEquals(dependentDomainList.getNames().size(), 1);
        assertEquals(dependentDomainList.getNames().get(0), topLevelDomainName);
        zmsImpl.deleteMembership(sysAdminCtx, sysAdminDomainName, serviceProvidersRoleName, fullServiceProviderName, auditRef, null);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

        //  Now try and delete the dependency. It won't be possible as the service provider is no longer part of the role.

        try {
            zmsImpl.deleteDomainDependency(sysAdminCtx, topLevelDomainName, fullServiceProviderName, auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: " +
                    "\"test-domain1-auth.sub-test-domain1.service-provider is not an authorized service provider\"}");
        }

        // Re-add it to the service provider's role. After it is added we can delete it.

        Membership membership = new Membership();
        membership.setMemberName(fullServiceProviderName);
        zmsImpl.putMembership(sysAdminCtx, sysAdminDomainName, serviceProvidersRoleName, fullServiceProviderName,
                auditRef, false, null, membership);
        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);
        zmsImpl.deleteDomainDependency(sysAdminCtx, topLevelDomainName, fullServiceProviderName, auditRef);
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullServiceProviderName);
        assertTrue(dependentDomainList.getNames().isEmpty());

        zmsImpl.deleteSubDomain(ctx, topLevelDomainName, subDomainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, topLevelDomainName, auditRef, null);
    }

    @Test
    public void testServiceNotFound() {
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        try {
            zmsImpl.getDependentDomainList(ctx, "some.unknown.service");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): {code: 400, message: \"some.unknown.service " +
                    "is not a registered service provider\"}");
        }
    }

    @Test
    public void testDomainNotFound() {
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        ServiceIdentityList dependentServiceList = zmsImpl.getDependentServiceList(ctx, "some.unknown.domain");
        assertTrue(dependentServiceList.getNames().isEmpty());
    }

    @Test
    public void testAuditEnabled() {
        long fetchFrequency = 1L; // For the test, fetch every second
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        final String auditRef = zmsTestInitializer.getAuditRef();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        // Create top level domain and subdomain. Top level domain is audit enabled.
        // Then create a service in the subdomain and make it a service provider.

        final String topLevelDomainName = "test-domain1-audit";
        final String subDomainName = "sub-test-domain1";
        final String fullSubDomainName = topLevelDomainName + "." + subDomainName;
        final String serviceProviderName = "service-provider";
        final String fullServiceProviderName = fullSubDomainName + "." + serviceProviderName;

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(topLevelDomainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject(subDomainName,
                topLevelDomainName, "Sub Test Domain 1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(ctx, topLevelDomainName, auditRef, null, subDom1);

        ServiceIdentity serviceProvider = zmsTestInitializer.createServiceObject(fullSubDomainName,
                serviceProviderName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, fullSubDomainName, serviceProviderName, auditRef, false, null, serviceProvider);

        // Now make the service a service provider

        String sysAdminDomainName = "sys.auth";
        String serviceProvidersRoleName = "service_providers";

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember authorizedServiceRoleMember = new RoleMember();
        authorizedServiceRoleMember.setMemberName(fullServiceProviderName);
        roleMembers.add(authorizedServiceRoleMember);
        Role role = new Role();
        role.setName(serviceProvidersRoleName);
        role.setRoleMembers(roleMembers);
        zmsImpl.putRole(ctx, sysAdminDomainName, serviceProvidersRoleName, auditRef, false, null, role);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

        // Switch to service provider context

        RsrcCtxWrapper serviceProviderCtx = zmsTestInitializer.contextWithMockPrincipal("putDomainDependency",
                fullSubDomainName, serviceProviderName);

        // Trying to put domain dependency without audit will fail

        DependentService dependentService = new DependentService().setService(fullServiceProviderName);
        try {
            zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, null, dependentService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): {code: 400, message: \"putdomaindependency: " +
                    "Audit reference required for domain: test-domain1-audit\"}");
        }
        zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, auditRef, dependentService);

        // Trying to put domain dependency without audit will fail

        try {
            zmsImpl.deleteDomainDependency(serviceProviderCtx, topLevelDomainName, fullServiceProviderName, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): {code: 400, message: \"putdomaindependency: " +
                    "Audit reference required for domain: test-domain1-audit\"}");
        }
        zmsImpl.deleteDomainDependency(serviceProviderCtx, topLevelDomainName, fullServiceProviderName, auditRef);

        zmsImpl.deleteSubDomain(ctx, topLevelDomainName, subDomainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, topLevelDomainName, auditRef, null);
    }

    @Test
    public void testGetAuthorizedProviderService() {

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        String caller = "putDomainDependency";

        // Throw failure for service which is not a service provider

        try {
            zmsImpl.getAuthorizedProviderService(ctx, null, caller);
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"user.user1 is not an authorized service provider\"}");
        }

        // Throw failure for system administrator that didn't specify service

        RsrcCtxWrapper sysAdminCtx = zmsTestInitializer.contextWithMockPrincipal(caller);
        try {
            zmsImpl.getAuthorizedProviderService(sysAdminCtx, null, caller);
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): {code: 400, message: \"service is mandatory\"}");
        }

        // Throw failure for system administrator that specified a non service-provider service

        try {
            zmsImpl.getAuthorizedProviderService(sysAdminCtx, "not.service.provider", caller);
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"not.service.provider is not an authorized service provider\"}");
        }

        // Mock a service provider

        Map<String, ServiceProviderManager.DomainDependencyProvider> serviceProviders = Stream.of(new Object[][]{
                {"service.provider", new ServiceProviderManager.DomainDependencyProvider(
                        "service.provider", "https://localhost:1234/service", false)},
        }).collect(Collectors.toMap(data -> (String) data[0], data -> (ServiceProviderManager.DomainDependencyProvider) data[1]));
        zmsImpl.serviceProviderManager.setServiceProviders(serviceProviders);

        // For non system administrators - trying to specify the service provider isn't
        // enough, principal must be the service provider

        try {
            zmsImpl.getAuthorizedProviderService(ctx, "service.provider", caller);
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"user.user1 is " +
                    "not an authorized service provider\"}");
        }

        // Successful for system administrator or the service provider itself

        String authorizedProviderService = zmsImpl.getAuthorizedProviderService(sysAdminCtx, "service.provider", caller);
        assertEquals(authorizedProviderService, "service.provider");
        RsrcCtxWrapper serviceProviderCtx = zmsTestInitializer.contextWithMockPrincipal(caller, "service", "provider");
        authorizedProviderService = zmsImpl.getAuthorizedProviderService(serviceProviderCtx, "service.provider", caller);
        assertEquals(authorizedProviderService, "service.provider");

        // Successful for system administrator that isn't human

        RsrcCtxWrapper serviceSysAdminCtx = zmsTestInitializer.generateServiceSysAdmin(caller, "admindomain", "serviceprincipal");
        authorizedProviderService = zmsImpl.getAuthorizedProviderService(serviceSysAdminCtx, "service.provider", caller);
        assertEquals(authorizedProviderService, "service.provider");
    }
}
