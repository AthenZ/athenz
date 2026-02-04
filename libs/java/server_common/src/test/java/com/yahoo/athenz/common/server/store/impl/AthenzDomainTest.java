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
package com.yahoo.athenz.common.server.store.impl;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.store.AthenzDomain;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Struct;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
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

    @Test
    public void testSetRoleMemberPrincipalTypesWithNullRoles() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        athenzDomain.setRoles(null);
        
        // Should not throw exception when roles is null
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        assertNull(athenzDomain.getRoles());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesWithEmptyRoles() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        athenzDomain.setRoles(new ArrayList<>());
        
        // Should not throw exception when roles is empty
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        assertTrue(athenzDomain.getRoles().isEmpty());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesWithNullRoleMembers() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        role.setRoleMembers(null);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        // Should not throw exception when roleMembers is null
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        assertNull(athenzDomain.getRoles().get(0).getRoleMembers());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesWithEmptyRoleMembers() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        role.setRoleMembers(new ArrayList<>());
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        // Should not throw exception when roleMembers is empty
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        assertTrue(athenzDomain.getRoles().get(0).getRoleMembers().isEmpty());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesUserType() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        role.setRoleMembers(roleMembers);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        
        assertEquals(athenzDomain.getRoles().get(0).getRoleMembers().get(0).getPrincipalType(), 
                Principal.Type.USER.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesUserHeadlessType() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("headless.jane"));
        role.setRoleMembers(roleMembers);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        
        assertEquals(athenzDomain.getRoles().get(0).getRoleMembers().get(0).getPrincipalType(), 
                Principal.Type.USER_HEADLESS.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesGroupType() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("athenz:group.test-group"));
        role.setRoleMembers(roleMembers);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        
        assertEquals(athenzDomain.getRoles().get(0).getRoleMembers().get(0).getPrincipalType(), 
                Principal.Type.GROUP.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesServiceType() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("athenz.test-service"));
        role.setRoleMembers(roleMembers);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        
        assertEquals(athenzDomain.getRoles().get(0).getRoleMembers().get(0).getPrincipalType(), 
                Principal.Type.SERVICE.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesWithAdditionalUserDomainPrefix() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user2.bob"));
        role.setRoleMembers(roleMembers);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        List<String> addlUserCheckDomainPrefixList = List.of("user2");
        athenzDomain.setRoleMemberPrincipalTypes("user", addlUserCheckDomainPrefixList, "headless");
        
        assertEquals(athenzDomain.getRoles().get(0).getRoleMembers().get(0).getPrincipalType(), 
                Principal.Type.USER.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesMultipleMembers() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("headless.jane"));
        roleMembers.add(new RoleMember().setMemberName("athenz:group.test-group"));
        roleMembers.add(new RoleMember().setMemberName("athenz.test-service"));
        role.setRoleMembers(roleMembers);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        
        List<RoleMember> members = athenzDomain.getRoles().get(0).getRoleMembers();
        assertEquals(members.get(0).getPrincipalType(), Principal.Type.USER.getValue());
        assertEquals(members.get(1).getPrincipalType(), Principal.Type.USER_HEADLESS.getValue());
        assertEquals(members.get(2).getPrincipalType(), Principal.Type.GROUP.getValue());
        assertEquals(members.get(3).getPrincipalType(), Principal.Type.SERVICE.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesMultipleRoles() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        
        Role role1 = new Role().setName("role1");
        List<RoleMember> roleMembers1 = new ArrayList<>();
        roleMembers1.add(new RoleMember().setMemberName("user.joe"));
        roleMembers1.add(new RoleMember().setMemberName("athenz.test-service"));
        role1.setRoleMembers(roleMembers1);
        roles.add(role1);
        
        Role role2 = new Role().setName("role2");
        List<RoleMember> roleMembers2 = new ArrayList<>();
        roleMembers2.add(new RoleMember().setMemberName("headless.jane"));
        roleMembers2.add(new RoleMember().setMemberName("athenz:group.test-group"));
        role2.setRoleMembers(roleMembers2);
        roles.add(role2);
        
        athenzDomain.setRoles(roles);
        
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        
        // Verify role1 members
        List<RoleMember> members1 = athenzDomain.getRoles().get(0).getRoleMembers();
        assertEquals(members1.get(0).getPrincipalType(), Principal.Type.USER.getValue());
        assertEquals(members1.get(1).getPrincipalType(), Principal.Type.SERVICE.getValue());
        
        // Verify role2 members
        List<RoleMember> members2 = athenzDomain.getRoles().get(1).getRoleMembers();
        assertEquals(members2.get(0).getPrincipalType(), Principal.Type.USER_HEADLESS.getValue());
        assertEquals(members2.get(1).getPrincipalType(), Principal.Type.GROUP.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesMixedRolesWithNullAndEmptyMembers() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        
        Role role1 = new Role().setName("role1");
        role1.setRoleMembers(null);
        roles.add(role1);
        
        Role role2 = new Role().setName("role2");
        role2.setRoleMembers(new ArrayList<>());
        roles.add(role2);
        
        Role role3 = new Role().setName("role3");
        List<RoleMember> roleMembers3 = new ArrayList<>();
        roleMembers3.add(new RoleMember().setMemberName("user.joe"));
        role3.setRoleMembers(roleMembers3);
        roles.add(role3);
        
        athenzDomain.setRoles(roles);
        
        // Should not throw exception
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        
        assertNull(athenzDomain.getRoles().get(0).getRoleMembers());
        assertTrue(athenzDomain.getRoles().get(1).getRoleMembers().isEmpty());
        assertEquals(athenzDomain.getRoles().get(2).getRoleMembers().get(0).getPrincipalType(), 
                Principal.Type.USER.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesWithMultipleAdditionalUserPrefixes() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("user2.bob"));
        roleMembers.add(new RoleMember().setMemberName("user3.alice"));
        role.setRoleMembers(roleMembers);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        List<String> addlUserCheckDomainPrefixList = Arrays.asList("user2", "user3");
        athenzDomain.setRoleMemberPrincipalTypes("user", addlUserCheckDomainPrefixList, "headless");
        
        List<RoleMember> members = athenzDomain.getRoles().get(0).getRoleMembers();
        assertEquals(members.get(0).getPrincipalType(), Principal.Type.USER.getValue());
        assertEquals(members.get(1).getPrincipalType(), Principal.Type.USER.getValue());
        assertEquals(members.get(2).getPrincipalType(), Principal.Type.USER.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesServiceWithMultipleDots() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        // Service with multiple dots should still be SERVICE type
        roleMembers.add(new RoleMember().setMemberName("athenz.subdomain.test-service"));
        role.setRoleMembers(roleMembers);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        
        assertEquals(athenzDomain.getRoles().get(0).getRoleMembers().get(0).getPrincipalType(), 
                Principal.Type.SERVICE.getValue());
    }

    @Test
    public void testSetRoleMemberPrincipalTypesGroupWithMultipleDots() {
        AthenzDomain athenzDomain = new AthenzDomain("test-domain");
        List<Role> roles = new ArrayList<>();
        Role role = new Role().setName("role1");
        List<RoleMember> roleMembers = new ArrayList<>();
        // Group with multiple dots should still be GROUP type
        roleMembers.add(new RoleMember().setMemberName("athenz:group.subdomain.test-group"));
        role.setRoleMembers(roleMembers);
        roles.add(role);
        athenzDomain.setRoles(roles);
        
        athenzDomain.setRoleMemberPrincipalTypes("user", null, "headless");
        
        assertEquals(athenzDomain.getRoles().get(0).getRoleMembers().get(0).getPrincipalType(), 
                Principal.Type.GROUP.getValue());
    }
}
