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
package com.yahoo.athenz.zms.assertion;

import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.ResourceAccess;
import com.yahoo.athenz.zms.ResourceAccessList;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class AwsAssumeRoleResourceUpdaterTest {

    @Test
    public void testEmptyNullCloudMap() {
        testEmptyCloudMap(null);
        testEmptyCloudMap(Collections.emptyMap());
    }

    void testEmptyCloudMap(Map<String, String> cloudMap) {
        AwsAssumeRoleResourceUpdater updater = new AwsAssumeRoleResourceUpdater();
        ResourceAccessList resourceAccessList = new ResourceAccessList();
        List<ResourceAccess> resourceList = new ArrayList<>();
        resourceList.add(new ResourceAccess());
        resourceAccessList.setResources(resourceList);
        updater.updateResourceValue(resourceAccessList, cloudMap, null);
        assertTrue(resourceAccessList.getResources().isEmpty());
    }

    private ResourceAccessList singleAssertionAccessList(final String role, final String resource) {

        Assertion assertion = new Assertion().setRole(role).setResource(resource)
                .setAction("assume_aws_role").setEffect(AssertionEffect.ALLOW);

        ResourceAccess resourceAccess = new ResourceAccess();
        resourceAccess.setAssertions(new ArrayList<>(List.of(assertion)));

        ResourceAccessList resourceAccessList = new ResourceAccessList();
        resourceAccessList.setResources(new ArrayList<>(List.of(resourceAccess)));
        return resourceAccessList;
    }

    @Test
    public void testUpdateResourceValueMultipleAccounts() {

        AwsAssumeRoleResourceUpdater updater = new AwsAssumeRoleResourceUpdater();

        ResourceAccessList resourceAccessList = singleAssertionAccessList(
                "athenz:role.admin", "athenz:role-resource");

        Map<String, String> cloudProviderMap = new HashMap<>();
        cloudProviderMap.put("athenz", "1234,5678");

        updater.updateResourceValue(resourceAccessList, cloudProviderMap, null);

        List<Assertion> assertions = resourceAccessList.getResources().get(0).getAssertions();
        assertEquals(assertions.size(), 2);

        Set<String> resources = new HashSet<>();
        for (Assertion assertion : assertions) {
            resources.add(assertion.getResource());
        }
        assertTrue(resources.contains("arn:aws:iam::1234:role/role-resource"));
        assertTrue(resources.contains("arn:aws:iam::5678:role/role-resource"));
    }

    @Test
    public void testUpdateResourceValueMultipleAccountsWithFilter() {

        AwsAssumeRoleResourceUpdater updater = new AwsAssumeRoleResourceUpdater();

        ResourceAccessList resourceAccessList = singleAssertionAccessList(
                "athenz:role.admin", "athenz:role-resource");

        Map<String, String> cloudProviderMap = new HashMap<>();
        cloudProviderMap.put("athenz", "1234,5678");

        updater.updateResourceValue(resourceAccessList, cloudProviderMap, "5678");

        List<Assertion> assertions = resourceAccessList.getResources().get(0).getAssertions();
        assertEquals(assertions.size(), 1);
        assertEquals(assertions.get(0).getResource(), "arn:aws:iam::5678:role/role-resource");
    }
}
