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
package com.yahoo.athenz.zms.store;

import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Struct;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.*;

public class AthenzDomainTest {

    @Test
    public void testAthenzDomain() {

        AthenzDomain athenzDomain = new AthenzDomain("coretech");
        assertEquals(athenzDomain.getName(), "coretech");
        assertTrue(athenzDomain.getRoles().isEmpty());
        assertTrue(athenzDomain.getGroups().isEmpty());
        assertTrue(athenzDomain.getPolicies().isEmpty());
        assertTrue(athenzDomain.getServices().isEmpty());
        assertTrue(athenzDomain.getEntities().isEmpty());

        List<Role> roles = new ArrayList<>();
        roles.add(new Role().setName("role1"));
        athenzDomain.setRoles(roles);

        List<Group> groups = new ArrayList<>();
        groups.add(new Group().setName("dev-team"));
        athenzDomain.setGroups(groups);

        List<Policy> policies = new ArrayList<>();
        policies.add(new Policy().setName("policy1"));
        athenzDomain.setPolicies(policies);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(new ServiceIdentity().setName("service1"));
        athenzDomain.setServices(services);

        List<Entity> entities = new ArrayList<>();
        entities.add(new Entity().setName("entity1").setValue(new Struct().with("value", "data1")));
        athenzDomain.setEntities(entities);

        assertEquals(athenzDomain.getRoles().size(), 1);
        assertEquals(athenzDomain.getGroups().size(), 1);
        assertEquals(athenzDomain.getPolicies().size(), 1);
        assertEquals(athenzDomain.getServices().size(), 1);
        assertEquals(athenzDomain.getEntities().size(), 1);
    }
}
