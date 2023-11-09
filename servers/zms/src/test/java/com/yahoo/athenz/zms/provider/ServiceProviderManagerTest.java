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

package com.yahoo.athenz.zms.provider;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.zms.*;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import static com.yahoo.athenz.zms.ZMSConsts.*;
import static java.util.stream.Collectors.toList;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class ServiceProviderManagerTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceProviderManagerTest.class);

    @BeforeMethod
    public void setup() throws NoSuchFieldException, IllegalAccessException {
        // Reset ServiceProviderManager Singleton
        Field instance = ServiceProviderManager.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    @AfterMethod
    public void clean() {
    }

    @Test
    public void testIsServiceProvider() throws InterruptedException, ExecutionException {
        String testDomainName = "test.domain";
        String testRoleName = "test_role";
        long fetchFrequency = 5L; // For the test, fetch every 5 seconds
        int numberOfThreads = 10;
        System.setProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_DOMAIN, testDomainName);
        System.setProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_ROLE, testRoleName);
        System.setProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS, String.valueOf(fetchFrequency));
        DBService dbService = Mockito.mock(DBService.class);

        // First db will return the role with a single member
        Role testRole1 = generateRoleWithMembers(Arrays.asList(
                "service.provider.test1"), testRoleName);
        // Then a couple of new members will join before the second call
        Role testRole2 = generateRoleWithMembers(Arrays.asList(
                "service.provider.test1",
                "service.provider.test2",
                "service.provider.test3"), testRoleName);
        //Before the third call, we will remove one of the service providers
        Role testRole3 = generateRoleWithMembers(Arrays.asList(
                "service.provider.test2",
                "service.provider.test3"), testRoleName);

        when(dbService.getRole(testDomainName, testRoleName, false, true, false))
                .thenReturn(testRole1)
                .thenReturn(testRole2)
                .thenReturn(testRole3);

        for (int i = 1; i <=3; ++i) {
            ServiceIdentity serviceIdentity = new ServiceIdentity();
            serviceIdentity.setName("service.provider.test" + i);
            serviceIdentity.setProviderEndpoint("https://localhost:4443/test" + i);
            when(dbService.getServiceIdentity("service.provider", "test" + i, true)).thenReturn(serviceIdentity);
        }

        Principal providerServicePrincipal = SimplePrincipal.create("service.provider", "test1", (String) null);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        when(authorizer.access(ServerCommonConsts.ACTION_LAUNCH, ServerCommonConsts.RESOURCE_INSTANCE,
                providerServicePrincipal, null)).thenReturn(true);
        ServiceProviderManager serviceProviderManager = ServiceProviderManager.getInstance(dbService, authorizer);

        // Simulate calls from different threads to check service provider
        ExecutorService executor = Executors.newFixedThreadPool(numberOfThreads);
        List<AssertServiceProviderTask> assertServiceProviderTasks = new ArrayList<>();
        for (int i = 0; i < numberOfThreads; ++i) {
            assertServiceProviderTasks.add(new AssertServiceProviderTask(serviceProviderManager, fetchFrequency, i));
        }
        List<Future<Boolean>> futures = executor.invokeAll(assertServiceProviderTasks);
        executor.shutdown();
        for (Future<Boolean> future : futures) {
            if (!future.get()) {
                fail();
            }
        }

        serviceProviderManager.shutdown();
        System.clearProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS);
        System.clearProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_DOMAIN);
        System.clearProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_ROLE);
    }

    private Role generateRoleWithMembers(List<String> memberNames, String roleName) {
        List<RoleMember> roleMembers = memberNames.stream().map(memberName -> {
            RoleMember roleMember = new RoleMember();
            roleMember.setMemberName(memberName);
            return roleMember;
        }).collect(toList());

        Role testRole = new Role();
        testRole.setName(roleName);
        testRole.setRoleMembers(roleMembers);
        return testRole;
    }

    public static class AssertServiceProviderTask implements Callable<Boolean> {
        final int threadNumber;
        final ServiceProviderManager serviceProviderManager;
        final long fetchFrequency;
        public AssertServiceProviderTask(ServiceProviderManager serviceProviderManager, long fetchFrequency, int threadNumber) {
            this.serviceProviderManager = serviceProviderManager;
            this.fetchFrequency = fetchFrequency;
            this.threadNumber = threadNumber;
        }

        @Override
        public Boolean call() {
            LOGGER.info("Starting thread {}", threadNumber);
            try {
                // Assert initial fetch from DB is correct
                assertFalse(serviceProviderManager.isServiceProvider(null));
                assertFalse(serviceProviderManager.isServiceProvider(""));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test1"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test2"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test3"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test4"));
                Map<String, ServiceProviderManager.DomainDependencyProvider> serviceProvidersWithEndpoints = serviceProviderManager.getServiceProvidersWithEndpoints();
                assertEquals(serviceProvidersWithEndpoints.size(), 1);

                // Now sleep until the second fetch from DB (fetchFrequency + add a small delta)
                LOGGER.info("sleeping until the second refresh happens...");
                ZMSTestUtils.sleep((1000 * fetchFrequency) + 1000);

                // Assert service.provider.test2 and service.provider.test3 added
                assertFalse(serviceProviderManager.isServiceProvider(null));
                assertFalse(serviceProviderManager.isServiceProvider(""));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test1"));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test2"));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test3"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test4"));
                serviceProvidersWithEndpoints = serviceProviderManager.getServiceProvidersWithEndpoints();
                assertEquals(serviceProvidersWithEndpoints.size(), 3);
                assertTrue(serviceProvidersWithEndpoints.get("service.provider.test1").isInstanceProvider());
                assertFalse(serviceProvidersWithEndpoints.get("service.provider.test2").isInstanceProvider());
                assertFalse(serviceProvidersWithEndpoints.get("service.provider.test3").isInstanceProvider());
                assertEquals(serviceProvidersWithEndpoints.get("service.provider.test1").getProviderEndpoint(), "https://localhost:4443/test1");
                assertEquals(serviceProvidersWithEndpoints.get("service.provider.test2").getProviderEndpoint(), "https://localhost:4443/test2");
                assertEquals(serviceProvidersWithEndpoints.get("service.provider.test3").getProviderEndpoint(), "https://localhost:4443/test3");

                // Now check final fetch from DB
                LOGGER.info("sleeping until final refresh happens...");
                ZMSTestUtils.sleep(1000 * fetchFrequency + 1000);

                // Assert service.provider.test1 was removed
                assertFalse(serviceProviderManager.isServiceProvider(null));
                assertFalse(serviceProviderManager.isServiceProvider(""));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test1"));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test2"));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test3"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test4"));
                serviceProvidersWithEndpoints = serviceProviderManager.getServiceProvidersWithEndpoints();
                assertEquals(serviceProvidersWithEndpoints.size(), 2);

                LOGGER.info("Finished successfully - thread {}", threadNumber);
                return true;
            } catch (AssertionError error) {
                LOGGER.info("Failed - thread {}", threadNumber);
                return false;
            }
        }
    }
}
