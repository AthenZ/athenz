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

import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ZMSTestUtils;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;

import static com.yahoo.athenz.zms.ZMSConsts.*;
import static java.util.stream.Collectors.toList;
import static org.testng.Assert.*;

public class ServiceProviderManagerTest {

    @Test
    public void testIsServiceProvider() throws InterruptedException, ExecutionException {
        String testDomainName = "test.domain";
        String testRoleName = "test_role";
        long fetchFrequency = 1L; // For the test, fetch every second
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

        Mockito.when(dbService.getRole(Mockito.eq(testDomainName), Mockito.eq(testRoleName), Mockito.eq(false), Mockito.eq(true), Mockito.eq(false)))
                .thenReturn(testRole1)
                .thenReturn(testRole2)
                .thenReturn(testRole3);

        ServiceProviderManager serviceProviderManager = new ServiceProviderManager(dbService);

        // Simulate calls from different threads to check service provider
        ExecutorService executor = Executors.newFixedThreadPool(numberOfThreads);
        List<AssertServiceProviderTask> assertServiceProviderTasks = new ArrayList<>();
        for (int i = 0; i < numberOfThreads; ++i) {
            assertServiceProviderTasks.add(new AssertServiceProviderTask(serviceProviderManager, fetchFrequency, i));
        }
        List<Future<Boolean>> futures = executor.invokeAll(assertServiceProviderTasks);
        executor.shutdown();
        for (int i = 0; i < futures.size(); ++i) {
            if (!futures.get(i).get()) {
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

    public class AssertServiceProviderTask implements Callable<Boolean> {
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
            System.out.println("Starting thread " + threadNumber);
            try {
                // Assert initial fetch from DB is correct
                assertFalse(serviceProviderManager.isServiceProvider(null));
                assertFalse(serviceProviderManager.isServiceProvider(""));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test1"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test2"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test3"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test4"));

                // Now sleep until the second fetch from DB (fetchFrequency + add a small delta)
                ZMSTestUtils.sleep((1000 * fetchFrequency) + 50);

                // Assert service.provider.test2 and service.provider.test3 added
                assertFalse(serviceProviderManager.isServiceProvider(null));
                assertFalse(serviceProviderManager.isServiceProvider(""));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test1"));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test2"));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test3"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test4"));

                // Now check final fetch from DB
                ZMSTestUtils.sleep(1000 * fetchFrequency);

                // Assert service.provider.test1 was removed
                assertFalse(serviceProviderManager.isServiceProvider(null));
                assertFalse(serviceProviderManager.isServiceProvider(""));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test1"));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test2"));
                assertTrue(serviceProviderManager.isServiceProvider("service.provider.test3"));
                assertFalse(serviceProviderManager.isServiceProvider("service.provider.test4"));
                System.out.println("Finished successfully - thread " + threadNumber);
                return true;
            } catch (AssertionError error) {
                System.out.println("Failed - thread " + threadNumber);
                return false;
            }
        }
    }
}