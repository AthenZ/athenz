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
package com.yahoo.athenz.common.server.util;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class ResourceUtilsTest {

    @Test
    public void testRoleResourceName() {
        assertEquals(ResourceUtils.roleResourceName("athenz", "role1"), "athenz:role.role1");
        assertEquals(ResourceUtils.roleResourceName("athenz.api", "role1"), "athenz.api:role.role1");
    }

    @Test
    public void testServiceResourceName() {
        assertEquals(ResourceUtils.serviceResourceName("athenz", "service1"), "athenz.service1");
        assertEquals(ResourceUtils.serviceResourceName("athenz.api", "service1"), "athenz.api.service1");
    }

    @Test
    public void testEntityResourceName() {
        assertEquals(ResourceUtils.entityResourceName("athenz", "entity1"), "athenz:entity.entity1");
        assertEquals(ResourceUtils.entityResourceName("athenz.api", "entity1"), "athenz.api:entity.entity1");
    }

    @Test
    public void testGroupResourceName() {
        assertEquals(ResourceUtils.groupResourceName("athenz", "group1"), "athenz:group.group1");
        assertEquals(ResourceUtils.groupResourceName("athenz.api", "group1"), "athenz.api:group.group1");
    }

    @Test
    public void testPolicyResourceName() {
        assertEquals(ResourceUtils.policyResourceName("athenz", "policy1"), "athenz:policy.policy1");
        assertEquals(ResourceUtils.policyResourceName("athenz.api", "policy1"), "athenz.api:policy.policy1");
    }
}
