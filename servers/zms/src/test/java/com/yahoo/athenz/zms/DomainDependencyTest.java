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

import org.testng.annotations.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import static com.yahoo.athenz.zms.ZMSConsts.ZMS_PROP_AUDIT_REF_CHECK_OBJECTS;
import static com.yahoo.athenz.zms.ZMSConsts.ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS;
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
        zmsTestInitializer.setUp();
        System.setProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS, String.valueOf(fetchFrequency));
    }

    @AfterMethod
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
        System.clearProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS);
    }

    @Test
    public void testDomainDependency() {

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper regularUserCtx = zmsTestInitializer.getMockDomRsrcCtx();

        // Create top level domain and sub level domain.
        // Then create a service in the sub domain and make it a service provider.

        final String topLevelDomainName = "test-domain1";
        final String subDomainName = "sub-test-domain1";
        final String fullSubDomainName = topLevelDomainName + "." + subDomainName;
        final String serviceProviderName = "service-provider";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(topLevelDomainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(regularUserCtx, zmsTestInitializer.getAuditRef(), dom1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject(subDomainName,
                topLevelDomainName, "Sub Test Domain 1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(regularUserCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), subDom1);

        ServiceIdentity serviceProvider = zmsTestInitializer.createServiceObject(fullSubDomainName,
                serviceProviderName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(regularUserCtx, fullSubDomainName, serviceProviderName, zmsTestInitializer.getAuditRef(), serviceProvider);

        final String sysAdminDomainName = "sys.auth";
        final String serviceProvidersRoleName = "service_providers";

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember authorizedServiceRoleMember = new RoleMember();
        authorizedServiceRoleMember.setMemberName(fullSubDomainName + "." + serviceProviderName);
        roleMembers.add(authorizedServiceRoleMember);
        Role role = new Role();
        role.setName(serviceProvidersRoleName);
        role.setRoleMembers(roleMembers);

        zmsImpl.putRole(regularUserCtx, sysAdminDomainName, serviceProvidersRoleName, zmsTestInitializer.getAuditRef(), role);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

        // Now switch to the service provider context and put a dependency on the top level domain

        RsrcCtxWrapper serviceProviderCtx = zmsTestInitializer.contextWithMockPrincipal("putDomainDependency", fullSubDomainName, serviceProviderName);

        DependentService dependentService = new DependentService().setService(fullSubDomainName + "." + serviceProviderName);
        zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), dependentService);

        ServiceIdentityList dependentServiceList = zmsImpl.getDependentServiceList(regularUserCtx, topLevelDomainName);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullSubDomainName + "." + serviceProviderName);

        DomainList domainList = zmsImpl.getDependentDomainList(regularUserCtx, fullSubDomainName + "." + serviceProviderName);
        assertEquals(domainList.getNames().size(), 1);
        assertEquals(domainList.getNames().get(0), topLevelDomainName);

        // Create a new top level domain and add a dependency to it as well

        String secondTopLevelDomain = "test-domain2";
        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(secondTopLevelDomain,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(regularUserCtx, zmsTestInitializer.getAuditRef(), dom2);

        zmsImpl.putDomainDependency(serviceProviderCtx, secondTopLevelDomain, zmsTestInitializer.getAuditRef(), dependentService);
        dependentServiceList = zmsImpl.getDependentServiceList(regularUserCtx, secondTopLevelDomain);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullSubDomainName + "." + serviceProviderName);

        domainList = zmsImpl.getDependentDomainList(regularUserCtx, fullSubDomainName + "." + serviceProviderName);
        assertEquals(domainList.getNames().size(), 2);
        assertTrue(domainList.getNames().contains(topLevelDomainName));
        assertTrue(domainList.getNames().contains(secondTopLevelDomain));

        // Now delete the original dependency and verify it was removed

        zmsImpl.deleteDomainDependency(serviceProviderCtx, topLevelDomainName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());

        dependentServiceList = zmsImpl.getDependentServiceList(regularUserCtx, topLevelDomainName);
        assertEquals(dependentServiceList.getNames().size(), 0);

        // Verify it didn't affect the other domain

        dependentServiceList = zmsImpl.getDependentServiceList(regularUserCtx, secondTopLevelDomain);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullSubDomainName + "." + serviceProviderName);

        domainList = zmsImpl.getDependentDomainList(regularUserCtx, fullSubDomainName + "." + serviceProviderName);
        assertEquals(domainList.getNames().size(), 1);
        assertTrue(domainList.getNames().contains(secondTopLevelDomain));

        zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), dependentService);
        dependentServiceList = zmsImpl.getDependentServiceList(regularUserCtx, secondTopLevelDomain);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullSubDomainName + "." + serviceProviderName);

        domainList = zmsImpl.getDependentDomainList(regularUserCtx, fullSubDomainName + "." + serviceProviderName);
        assertEquals(domainList.getNames().size(), 2);
        assertTrue(domainList.getNames().contains(topLevelDomainName));
        assertTrue(domainList.getNames().contains(secondTopLevelDomain));

        // Finally delete again but this time as a system administrator

        RsrcCtxWrapper sysAdminCtx = zmsTestInitializer.contextWithMockPrincipal("deleteDomainDependency");
        zmsImpl.deleteDomainDependency(sysAdminCtx, topLevelDomainName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());

        dependentServiceList = zmsImpl.getDependentServiceList(regularUserCtx, topLevelDomainName);
        assertEquals(dependentServiceList.getNames().size(), 0);

        // Verify it didn't affect the other domain

        dependentServiceList = zmsImpl.getDependentServiceList(regularUserCtx, secondTopLevelDomain);
        assertEquals(dependentServiceList.getNames().size(), 1);
        assertEquals(dependentServiceList.getNames().get(0), fullSubDomainName + "." + serviceProviderName);

        domainList = zmsImpl.getDependentDomainList(regularUserCtx, fullSubDomainName + "." + serviceProviderName);
        assertEquals(domainList.getNames().size(), 1);
        assertTrue(domainList.getNames().contains(secondTopLevelDomain));

        zmsTestInitializer.getZms().deleteSubDomain(regularUserCtx, topLevelDomainName, subDomainName, zmsTestInitializer.getAuditRef());
        zmsTestInitializer.getZms().deleteTopLevelDomain(regularUserCtx, topLevelDomainName, zmsTestInitializer.getAuditRef());

        // Trying to delete test-domain2 will fail as the service test-domain1.sub-test-domain1.service-provider is still dependent on it

        try {
            zmsTestInitializer.getZms().deleteTopLevelDomain(regularUserCtx, secondTopLevelDomain, zmsTestInitializer.getAuditRef());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"Remove domain 'test-domain2' dependency from the following service(s):test-domain1.sub-test-domain1.service-provider\"}");
        }

        // Remove the dependency registration and delete

        zmsTestInitializer.getZms().deleteDomainDependency(sysAdminCtx, secondTopLevelDomain, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());
        zmsTestInitializer.getZms().deleteTopLevelDomain(regularUserCtx, secondTopLevelDomain, zmsTestInitializer.getAuditRef());
    }

    @Test
    public void testDomainDependencyAuth() {
        long fetchFrequency = 1L; // For the test, fetch every second
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper regularUserCtx = zmsTestInitializer.getMockDomRsrcCtx();

        // Clear ZMS_PROP_AUDIT_REF_CHECK_OBJECTS as we usually use the default settings role and group

        System.clearProperty(ZMS_PROP_AUDIT_REF_CHECK_OBJECTS);
        zmsImpl.dbService.setAuditRefObjectBits();

        // Create top level domain and sub level domain.
        // Then create a service in the sub domain and make it a service provider.

        final String topLevelDomainName = "test-domain1";
        final String subDomainName = "sub-test-domain1";
        final String fullSubDomainName = topLevelDomainName + "." + subDomainName;
        final String serviceProviderName = "service-provider";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(topLevelDomainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(regularUserCtx, zmsTestInitializer.getAuditRef(), dom1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject(subDomainName,
                topLevelDomainName, "Sub Test Domain 1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(regularUserCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), subDom1);

        ServiceIdentity serviceProvider = zmsTestInitializer.createServiceObject(fullSubDomainName,
                serviceProviderName, "http://localhost/service", "/usr/bin/java", "root",
                "users", "host1");

        ServiceIdentity someOtherServiceProvider = zmsTestInitializer.createServiceObject(fullSubDomainName,
                "some-other-service", "http://localhost/other-service", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(regularUserCtx, fullSubDomainName, serviceProviderName, zmsTestInitializer.getAuditRef(), serviceProvider);
        zmsImpl.putServiceIdentity(regularUserCtx, fullSubDomainName, "some-other-service", zmsTestInitializer.getAuditRef(), someOtherServiceProvider);

        DependentService dependentService = new DependentService().setService(fullSubDomainName + "." + serviceProviderName);
        try {
            zmsImpl.putDomainDependency(regularUserCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), dependentService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"user.user1 is not an authorized service provider\"}");
        }

        try {
            zmsImpl.deleteDomainDependency(regularUserCtx, topLevelDomainName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"user.user1 is not an authorized service provider\"}");
        }

        // Now make the service a service provider

        String sysAdminDomainName = "sys.auth";
        String serviceProvidersRoleName = "service_providers";

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember authorizedServiceRoleMember = new RoleMember();
        authorizedServiceRoleMember.setMemberName(fullSubDomainName + "." + serviceProviderName);
        RoleMember authorizedServiceRoleMemberOther = new RoleMember();
        authorizedServiceRoleMemberOther.setMemberName(fullSubDomainName + "." + "some-other-service");
        roleMembers.add(authorizedServiceRoleMember);
        roleMembers.add(authorizedServiceRoleMemberOther);
        Role role = new Role();
        role.setName(serviceProvidersRoleName);
        role.setRoleMembers(roleMembers);
        zmsImpl.putRole(zmsTestInitializer.getMockDomRsrcCtx(), sysAdminDomainName, serviceProvidersRoleName, zmsTestInitializer.getAuditRef(), role);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

        // Switch to service provider context

        RsrcCtxWrapper serviceProviderCtx = zmsTestInitializer.contextWithMockPrincipal("putDomainDependency", fullSubDomainName, serviceProviderName);

        // Specify invalid domain

        try {
            zmsImpl.putDomainDependency(serviceProviderCtx, "some.unknown.domain", zmsTestInitializer.getAuditRef(), dependentService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (404): {code: 404, message: \"putdomaindependency: Unknown domain: some.unknown.domain\"}");
        }

        try {
            zmsImpl.deleteDomainDependency(serviceProviderCtx, "some.unknown.domain", fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (404): {code: 404, message: \"putdomaindependency: Unknown domain: some.unknown.domain\"}");
        }

        // Try to register a different service provider. Specified service will be ignored and the principal will be used as the service

        DependentService dependentServiceOther = new DependentService().setService(fullSubDomainName + "." + "some-other-service");
        zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), dependentServiceOther);
        DomainList dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullSubDomainName + "." + "some-other-service");
        assertTrue(dependentDomainList.getNames().isEmpty());
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullSubDomainName + "." + serviceProviderName);
        assertEquals(dependentDomainList.getNames().size(), 1);
        assertEquals(dependentDomainList.getNames().get(0), topLevelDomainName);

        zmsImpl.deleteDomainDependency(serviceProviderCtx, topLevelDomainName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullSubDomainName + "." + serviceProviderName);
        assertTrue(dependentDomainList.getNames().isEmpty());

        // Now test api with system admin

        RsrcCtxWrapper sysAdminCtx = zmsTestInitializer.contextWithMockPrincipal("putDomainDependency");

        // Try and register to a service which is not a listed service provider

        try {
            DependentService dependentServiceNone = new DependentService().setService(fullSubDomainName + "." + "none-service-provider");
            zmsImpl.putDomainDependency(sysAdminCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), dependentServiceNone);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"test-domain1.sub-test-domain1.none-service-provider is not an authorized service provider\"}");
        }

        // Register and de-register a service provider using system admin

        zmsImpl.putDomainDependency(sysAdminCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), dependentService);
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullSubDomainName + "." + serviceProviderName);
        assertEquals(dependentDomainList.getNames().size(), 1);
        assertEquals(dependentDomainList.getNames().get(0), topLevelDomainName);
        zmsImpl.deleteDomainDependency(sysAdminCtx, topLevelDomainName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullSubDomainName + "." + serviceProviderName);
        assertTrue(dependentDomainList.getNames().isEmpty());

        // Register dependency using system admin but this time remove from service_providers role

        zmsImpl.putDomainDependency(sysAdminCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), dependentService);
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullSubDomainName + "." + serviceProviderName);
        assertEquals(dependentDomainList.getNames().size(), 1);
        assertEquals(dependentDomainList.getNames().get(0), topLevelDomainName);
        zmsImpl.deleteMembership(sysAdminCtx, sysAdminDomainName, serviceProvidersRoleName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

        //  Now try and delete the dependency. It won't be possible as the service provider is not longer part of the role.

        try {
            zmsImpl.deleteDomainDependency(sysAdminCtx, topLevelDomainName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"test-domain1.sub-test-domain1.service-provider is not an authorized service provider\"}");
        }

        // Re-add it to the service providers role. After it is added we can delete it.

        Membership membership = new Membership();
        membership.setMemberName(fullSubDomainName + "." + serviceProviderName);
        zmsImpl.putMembership(sysAdminCtx, sysAdminDomainName, serviceProvidersRoleName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef(), membership);
        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);
        zmsImpl.deleteDomainDependency(sysAdminCtx, topLevelDomainName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());
        dependentDomainList = zmsImpl.getDependentDomainList(serviceProviderCtx, fullSubDomainName + "." + serviceProviderName);
        assertTrue(dependentDomainList.getNames().isEmpty());

        zmsTestInitializer.getZms().deleteSubDomain(regularUserCtx, topLevelDomainName, subDomainName, zmsTestInitializer.getAuditRef());
        zmsTestInitializer.getZms().deleteTopLevelDomain(regularUserCtx, topLevelDomainName, zmsTestInitializer.getAuditRef());
    }

    @Test
    public void testServiceNotFound() {
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        try {
            zmsImpl.getDependentDomainList(zmsTestInitializer.getMockDomRsrcCtx(), "some.unknown.service");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): {code: 400, message: \"some.unknown.service is not a registered service provider\"}");
        }
    }

    @Test
    public void testDomainNotFound() {
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        ServiceIdentityList dependentServiceList = zmsImpl.getDependentServiceList(zmsTestInitializer.getMockDomRsrcCtx(), "some.unknown.domain");
        assertTrue(dependentServiceList.getNames().isEmpty());
    }

    @Test
    public void testAuditEnabled() {
        long fetchFrequency = 1L; // For the test, fetch every second
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper regularUserCtx = zmsTestInitializer.getMockDomRsrcCtx();

        // Create top level domain and sub level domain. Top level domain is audit enabled.
        // Then create a service in the sub domain and make it a service provider.

        final String topLevelDomainName = "test-domain1";
        final String subDomainName = "sub-test-domain1";
        final String fullSubDomainName = topLevelDomainName + "." + subDomainName;
        final String serviceProviderName = "service-provider";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(topLevelDomainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(regularUserCtx, zmsTestInitializer.getAuditRef(), dom1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject(subDomainName,
                topLevelDomainName, "Sub Test Domain 1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(regularUserCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), subDom1);

        ServiceIdentity serviceProvider = zmsTestInitializer.createServiceObject(fullSubDomainName,
                serviceProviderName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(regularUserCtx, fullSubDomainName, serviceProviderName, zmsTestInitializer.getAuditRef(), serviceProvider);

        // Now make the service a service provider

        String sysAdminDomainName = "sys.auth";
        String serviceProvidersRoleName = "service_providers";

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember authorizedServiceRoleMember = new RoleMember();
        authorizedServiceRoleMember.setMemberName(fullSubDomainName + "." + serviceProviderName);
        roleMembers.add(authorizedServiceRoleMember);
        Role role = new Role();
        role.setName(serviceProvidersRoleName);
        role.setRoleMembers(roleMembers);
        zmsImpl.putRole(zmsTestInitializer.getMockDomRsrcCtx(), sysAdminDomainName, serviceProvidersRoleName, zmsTestInitializer.getAuditRef(), role);

        // Wait for cache to be ServiceProviderManager cache to refresh

        ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

        // Switch to service provider context

        RsrcCtxWrapper serviceProviderCtx = zmsTestInitializer.contextWithMockPrincipal("putDomainDependency", fullSubDomainName, serviceProviderName);

        // Trying to put domain dependency without audit will fail

        DependentService dependentService = new DependentService().setService(fullSubDomainName + "." + serviceProviderName);
        try {
            zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, null, dependentService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): {code: 400, message: \"putdomaindependency: Audit reference required for domain: test-domain1\"}");
        }
        zmsImpl.putDomainDependency(serviceProviderCtx, topLevelDomainName, zmsTestInitializer.getAuditRef(), dependentService);

        // Trying to put domain dependency without audit will fail

        try {
            zmsImpl.deleteDomainDependency(serviceProviderCtx, topLevelDomainName, fullSubDomainName + "." + serviceProviderName, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): {code: 400, message: \"putdomaindependency: Audit reference required for domain: test-domain1\"}");
        }
        zmsImpl.deleteDomainDependency(serviceProviderCtx, topLevelDomainName, fullSubDomainName + "." + serviceProviderName, zmsTestInitializer.getAuditRef());

        zmsTestInitializer.getZms().deleteSubDomain(regularUserCtx, topLevelDomainName, subDomainName, zmsTestInitializer.getAuditRef());
        zmsTestInitializer.getZms().deleteTopLevelDomain(regularUserCtx, topLevelDomainName, zmsTestInitializer.getAuditRef());
    }

    @Test
    public void testGetAuthorizedProviderService() {
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper regularUserCtx = zmsTestInitializer.getMockDomRsrcCtx();
        String caller = "putDomainDependency";

        // Throw failure for service which is not a service provider

        try {
            zmsImpl.getAuthorizedProviderService(regularUserCtx, null, caller);
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

        zmsImpl.serviceProviderManager.setServiceProviders(new HashSet<>(Arrays.asList("service.provider")));

        // For non system administrators - trying to specify the service provider isn't enough, principal must be the service provider

        try {
            zmsImpl.getAuthorizedProviderService(regularUserCtx, "service.provider", caller);
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"user.user1 is not an authorized service provider\"}");
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
