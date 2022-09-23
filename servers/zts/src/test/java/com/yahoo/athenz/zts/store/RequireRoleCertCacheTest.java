/*
 *
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package com.yahoo.athenz.zts.store;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class RequireRoleCertCacheTest {

    @Test
    public void testRequireRoleCert() {
        RequireRoleCertCache requireRoleCertCache = new RequireRoleCertCache();

        // we have no role

        assertNull(requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user1"));
        assertNull(requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.dev-team"));
        assertEquals(requireRoleCertCache.requireRoleCertPrefixTrie.findMatchingValues("user.user1"), new HashSet<>());
        assertEquals(requireRoleCertCache.requireRoleCertWildcard, new HashSet<>());

        generateRolesForTest(requireRoleCertCache);

        // verify our roles now

        List<RequireRoleCertCache.RoleMemberCache> cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.dev-team");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 3);
        assertEquals(cacheMembers.get(0).getRoleMember().getMemberName(), "user.user1");
        assertEquals(cacheMembers.get(1).getRoleMember().getMemberName(), "user.user2");
        assertEquals(cacheMembers.get(2).getRoleMember().getMemberName(), "coretech.subdomain.test");

        cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.pe-team");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 2);
        assertEquals(cacheMembers.get(0).getRoleMember().getMemberName(), "user.user1");
        assertEquals(cacheMembers.get(1).getRoleMember().getMemberName(), "coretech.api");

        cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.everyone-team");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 1);
        assertEquals(cacheMembers.get(0).getRoleMember().getMemberName(), "*");

        cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.everyone-team");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 1);
        assertEquals(cacheMembers.get(0).getRoleMember().getMemberName(), "*");

        cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.no-members");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 0);

        cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.non-existent-role");
        assertNull(cacheMembers);

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user1");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 2);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.dev-team");
        assertEquals(cacheMembers.get(1).getRole(), "coretech:role.pe-team");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user2");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 1);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.dev-team");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("coretech.api");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 1);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.pe-team");

        // verify that fetching roles requring cert will include wildcard members
        List<String> rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("user.user1");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 3);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.dev-team");
        assertEquals(rolesRequireRoleCert.get(1), "coretech:role.pe-team");
        assertEquals(rolesRequireRoleCert.get(2), "coretech:role.everyone-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("user.user2");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 2);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.dev-team");
        assertEquals(rolesRequireRoleCert.get(1), "coretech:role.everyone-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("coretech.api");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 3);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.pe-team");
        assertEquals(rolesRequireRoleCert.get(1), "coretech:role.everyone-team");
        assertEquals(rolesRequireRoleCert.get(2), "coretech:role.prefix-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("coretech.subdomain.test");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 3);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.dev-team");
        assertEquals(rolesRequireRoleCert.get(1), "coretech:role.everyone-team");
        assertEquals(rolesRequireRoleCert.get(2), "coretech:role.prefix-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("coretech.some.other.service");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 2);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.everyone-team");
        assertEquals(rolesRequireRoleCert.get(1), "coretech:role.prefix-team");

        // Remove wildcard member and add only user.user1 as member
        Role role = new Role().setName("coretech:role.everyone-team");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1"));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("user.user1");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 3);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.dev-team");
        assertEquals(rolesRequireRoleCert.get(1), "coretech:role.pe-team");
        assertEquals(rolesRequireRoleCert.get(2), "coretech:role.everyone-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("user.user2");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 1);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.dev-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("coretech.api");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 2);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.pe-team");
        assertEquals(rolesRequireRoleCert.get(1), "coretech:role.prefix-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("coretech.subdomain.test");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 2);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.dev-team");
        assertEquals(rolesRequireRoleCert.get(1), "coretech:role.prefix-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("coretech.some.other.service");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 1);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.prefix-team");

        // Remove prefix

        role = new Role().setName("coretech:role.prefix-team");
        requireRoleCertCache.processRoleCache(role);

        // Remove user.user2 and add user.user3

        role = new Role().setName("coretech:role.dev-team");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue()));
        members.add(new RoleMember().setMemberName("user.user3")
                .setPrincipalType(Principal.Type.USER.getValue()));
        members.add(new RoleMember().setMemberName("coretech.subdomain.test")
                .setPrincipalType(Principal.Type.SERVICE.getValue()));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        // Verify removal of prefix member and user changes were updated in cache

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("user.user1");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 3);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.dev-team");
        assertEquals(rolesRequireRoleCert.get(1), "coretech:role.pe-team");
        assertEquals(rolesRequireRoleCert.get(2), "coretech:role.everyone-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("user.user2");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 0);

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("user.user3");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 1);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.dev-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("coretech.api");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 1);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.pe-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("coretech.subdomain.test");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 1);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.dev-team");

        rolesRequireRoleCert = requireRoleCertCache.getRolesRequireRoleCert("coretech.some.other.service");
        assertNotNull(rolesRequireRoleCert);
        assertEquals(rolesRequireRoleCert.size(), 0);

        // add new members that are disabled and expired

        role = new Role().setName("coretech:role.dev-team");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));
        members.add(new RoleMember().setMemberName("user.user3")
                .setPrincipalType(Principal.Type.USER.getValue()));
        members.add(new RoleMember().setMemberName("user.user4")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setSystemDisabled(1));
        members.add(new RoleMember().setMemberName("user.user5")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setExpiration(Timestamp.fromMillis(1000)));
        members.add(new RoleMember().setMemberName("user.user6")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setExpiration(Timestamp.fromMillis(1000)));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.dev-team");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 5);
        assertEquals(cacheMembers.get(0).getRoleMember().getMemberName(), "user.user1");
        assertEquals(cacheMembers.get(1).getRoleMember().getMemberName(), "user.user3");
        assertEquals(cacheMembers.get(2).getRoleMember().getMemberName(), "user.user4");
        assertEquals(cacheMembers.get(3).getRoleMember().getMemberName(), "user.user5");
        assertEquals(cacheMembers.get(4).getRoleMember().getMemberName(), "user.user6");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user1");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 3);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.dev-team");
        assertEquals(cacheMembers.get(1).getRole(), "coretech:role.pe-team");
        assertEquals(cacheMembers.get(2).getRole(), "coretech:role.everyone-team");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user3");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 1);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.dev-team");

        // expired and disabled users are not present

        assertNull(requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user4"));
        assertNull(requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user5"));
        assertNull(requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user6"));

        // now make user4 as enabled, expire user 3 and delete user6

        role = new Role().setName("coretech:role.dev-team");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));
        members.add(new RoleMember().setMemberName("user.user3")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setExpiration(Timestamp.fromMillis(1000)));
        members.add(new RoleMember().setMemberName("user.user4")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setSystemDisabled(0));
        members.add(new RoleMember().setMemberName("user.user5")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setExpiration(Timestamp.fromMillis(1000)));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.dev-team");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 4);
        assertEquals(cacheMembers.get(0).getRoleMember().getMemberName(), "user.user1");
        assertEquals(cacheMembers.get(1).getRoleMember().getMemberName(), "user.user3");
        assertEquals(cacheMembers.get(2).getRoleMember().getMemberName(), "user.user4");
        assertEquals(cacheMembers.get(3).getRoleMember().getMemberName(), "user.user5");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user1");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 3);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.dev-team");
        assertEquals(cacheMembers.get(1).getRole(), "coretech:role.pe-team");
        assertEquals(cacheMembers.get(2).getRole(), "coretech:role.everyone-team");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user3");
        assertNotNull(cacheMembers);
        assertTrue(cacheMembers.isEmpty());

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user4");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 1);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.dev-team");

        assertNull(requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user5"));
        assertNull(requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user6"));

        // now make user5 as valid as well

        role = new Role().setName("coretech:role.dev-team");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));
        members.add(new RoleMember().setMemberName("user.user3")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setExpiration(Timestamp.fromMillis(1000)));
        members.add(new RoleMember().setMemberName("user.user4")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setSystemDisabled(0));
        members.add(new RoleMember().setMemberName("user.user5")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.dev-team");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 4);
        assertEquals(cacheMembers.get(0).getRoleMember().getMemberName(), "user.user1");
        assertEquals(cacheMembers.get(1).getRoleMember().getMemberName(), "user.user3");
        assertEquals(cacheMembers.get(2).getRoleMember().getMemberName(), "user.user4");
        assertEquals(cacheMembers.get(3).getRoleMember().getMemberName(), "user.user5");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user1");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 3);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.dev-team");
        assertEquals(cacheMembers.get(1).getRole(), "coretech:role.pe-team");
        assertEquals(cacheMembers.get(2).getRole(), "coretech:role.everyone-team");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user3");
        assertNotNull(cacheMembers);
        assertTrue(cacheMembers.isEmpty());

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user4");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 1);
        assertEquals(cacheMembers.get(0).getRole(),"coretech:role.dev-team");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user5");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 1);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.dev-team");

        // update the pe-team with no changes

        role = new Role().setName("coretech:role.pe-team");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue()));
        members.add(new RoleMember().setMemberName("coretech.api")
                .setPrincipalType(Principal.Type.SERVICE.getValue()));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        cacheMembers = requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.pe-team");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 2);
        assertEquals(cacheMembers.get(0).getRoleMember().getMemberName(), "user.user1");
        assertEquals(cacheMembers.get(1).getRoleMember().getMemberName(), "coretech.api");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user1");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 3);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.dev-team");
        assertEquals(cacheMembers.get(1).getRole(), "coretech:role.pe-team");
        assertEquals(cacheMembers.get(2).getRole(), "coretech:role.everyone-team");

        cacheMembers = requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("coretech.api");
        assertNotNull(cacheMembers);
        assertEquals(cacheMembers.size(), 1);
        assertEquals(cacheMembers.get(0).getRole(), "coretech:role.pe-team");
    }

    private void generateRolesForTest(RequireRoleCertCache requireRoleCertCache) {
        // process a role with no members

        Role role = new Role().setName("coretech:role.dev-team");
        requireRoleCertCache.processRoleCache(role);

        assertTrue(requireRoleCertCache.roleMemberRequireCertCache.getIfPresent("coretech:role.dev-team").isEmpty());
        assertNull(requireRoleCertCache.principalRoleRequireCertCache.getIfPresent("user.user1"));

        // update the role and add four new members

        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue()));
        members.add(new RoleMember().setMemberName("user.user2")
                .setPrincipalType(Principal.Type.USER.getValue()));
        members.add(new RoleMember().setMemberName("coretech.subdomain.test")
                .setPrincipalType(Principal.Type.SERVICE.getValue()));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        // create and process another role

        role = new Role().setName("coretech:role.pe-team");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue()));
        members.add(new RoleMember().setMemberName("coretech.api")
                .setPrincipalType(Principal.Type.SERVICE.getValue()));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        // create a role with wildcard (everyone is a member)

        role = new Role().setName("coretech:role.everyone-team");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("*"));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        // create a role with prefix

        role = new Role().setName("coretech:role.prefix-team");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("coretech.*"));
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);

        // create a role with no members
        role = new Role().setName("coretech:role.no-members");
        members = new ArrayList<>();
        role.setRoleMembers(members);
        requireRoleCertCache.processRoleCache(role);
    }

    @Test
    public void testProcessCollectionDeletedMembers() {

        RequireRoleCertCache requireRoleCertCache = new RequireRoleCertCache();

        // verify we correctly handle null deleted members

        requireRoleCertCache.processCollectionDeletedMembers("collection-name", null);
    }
}
