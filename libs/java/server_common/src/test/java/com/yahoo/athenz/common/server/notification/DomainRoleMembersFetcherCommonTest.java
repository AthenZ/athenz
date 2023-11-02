/*
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
 */

package com.yahoo.athenz.common.server.notification;

import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

public class DomainRoleMembersFetcherCommonTest {

    @Test
    public void testGetDomainRoleMembers() {
        DomainRoleMembersFetcherCommon fetcherCommon = new DomainRoleMembersFetcherCommon(USER_DOMAIN_PREFIX);

        long currentTimeInMillis = System.currentTimeMillis();
        Timestamp futureTimeStamp =  Timestamp.fromMillis(currentTimeInMillis + 100000);
        Timestamp pastTimeStamp =  Timestamp.fromMillis(currentTimeInMillis - 100000);

        Role role1 = new Role();
        role1.setName("role1");
        RoleMember roleMember1 = new RoleMember().setMemberName("user.unexpiredUser").setExpiration(futureTimeStamp);
        RoleMember roleMember2 = new RoleMember().setMemberName("user.expiredUser").setExpiration(pastTimeStamp);
        RoleMember roleMember3 = new RoleMember().setMemberName("user.noExpiration");
        RoleMember roleMember4 = new RoleMember().setMemberName("notProperUsername");
        List<RoleMember> role1MemberList = new ArrayList<>(Arrays.asList(roleMember1, roleMember2, roleMember3, roleMember4));
        role1.setRoleMembers(role1MemberList);

        Role role2 = new Role();
        role2.setName("role2");

        Role role3 = new Role();

        List<Role> rolesList = new ArrayList<>();
        rolesList.add(role1);
        rolesList.add(role2);
        rolesList.add(role3);

        Set<String> receivedMembers = fetcherCommon.getDomainRoleMembers("role1", rolesList);
        assertEquals(2, receivedMembers.size());
        assertTrue(receivedMembers.contains("user.unexpiredUser"));
        assertTrue(receivedMembers.contains("user.noExpiration"));

        receivedMembers = fetcherCommon.getDomainRoleMembers("role2", rolesList);
        assertEquals(new HashSet<>(), receivedMembers);

        receivedMembers = fetcherCommon.getDomainRoleMembers("roleDoesntExist", rolesList);
        assertEquals(new HashSet<>(), receivedMembers);

        // if the role list is empty we get an empty set

        assertEquals(new HashSet<>(), fetcherCommon.getDomainRoleMembers("role1", null));
    }

    @Test
    public void testGetDomainRoleMembersFromRole() {
        DomainRoleMembersFetcherCommon fetcherCommon = new DomainRoleMembersFetcherCommon(USER_DOMAIN_PREFIX);

        long currentTimeInMillis = System.currentTimeMillis();
        Timestamp futureTimeStamp =  Timestamp.fromMillis(currentTimeInMillis + 100000);
        Timestamp pastTimeStamp =  Timestamp.fromMillis(currentTimeInMillis - 100000);

        Role role1 = new Role();
        role1.setName("role1");
        RoleMember roleMember1 = new RoleMember().setMemberName("user.unexpiredUser").setExpiration(futureTimeStamp);
        RoleMember roleMember2 = new RoleMember().setMemberName("user.expiredUser").setExpiration(pastTimeStamp);
        RoleMember roleMember3 = new RoleMember().setMemberName("user.noExpiration");
        RoleMember roleMember4 = new RoleMember().setMemberName("notProperUsername");
        List<RoleMember> role1MemberList = new ArrayList<>(Arrays.asList(roleMember1, roleMember2, roleMember3, roleMember4));
        role1.setRoleMembers(role1MemberList);

        Set<String> receivedMembers = fetcherCommon.getDomainRoleMembers(role1);
        assertEquals(2, receivedMembers.size());
        assertTrue(receivedMembers.contains("user.unexpiredUser"));
        assertTrue(receivedMembers.contains("user.noExpiration"));
    }

    @Test
    public void testDomainRoleMembersFetcherNullProvider() {
        DomainRoleMembersFetcher fetcher = new DomainRoleMembersFetcher(null, USER_DOMAIN_PREFIX);
        assertEquals(new HashSet<>(), fetcher.getDomainRoleMembers("domain", "role"));
    }

    @Test
    public void testDomainRoleMembersFetcherRole() {

        Role role1 = new Role();
        role1.setName("role1");
        List<RoleMember> role1MemberList = Collections.singletonList(new RoleMember().setMemberName("user.user1"));
        role1.setRoleMembers(role1MemberList);

        RolesProvider provider = new RolesProvider() {
            @Override
            public List<Role> getRolesByDomain(String domainName) {
                return null;
            }
            @Override
            public Role getRole(String domainName, String roleName, Boolean auditLog, Boolean expand, Boolean pending) {
                return role1;
            }
        };

        DomainRoleMembersFetcher fetcher = new DomainRoleMembersFetcher(provider, USER_DOMAIN_PREFIX);
        Set<String> users = fetcher.getDomainRoleMembers("domain1", "role1");
        assertEquals(1, users.size());
        assertTrue(users.contains("user.user1"));
    }

    @Test
    public void testDomainRoleMembersFetcherNotImpl() {

        Role role1 = new Role();
        role1.setName("role1");
        List<RoleMember> role1MemberList = Collections.singletonList(new RoleMember().setMemberName("user.user1"));
        role1.setRoleMembers(role1MemberList);

        List<Role> rolesList = new ArrayList<>();
        rolesList.add(role1);

        RolesProvider provider = new RolesProvider() {
            @Override
            public List<Role> getRolesByDomain(String domainName) {
                return rolesList;
            }
        };

        DomainRoleMembersFetcher fetcher = new DomainRoleMembersFetcher(provider, USER_DOMAIN_PREFIX);
        Set<String> users = fetcher.getDomainRoleMembers("domain1", "role1");
        assertEquals(1, users.size());
        assertTrue(users.contains("user.user1"));
    }

    @Test
    public void testDomainRoleMembersFetcherExc() {

        Role role1 = new Role();
        role1.setName("role1");
        List<RoleMember> role1MemberList = Collections.singletonList(new RoleMember().setMemberName("user.user1"));
        role1.setRoleMembers(role1MemberList);

        List<Role> rolesList = new ArrayList<>();
        rolesList.add(role1);

        RolesProvider provider = new RolesProvider() {
            @Override
            public List<Role> getRolesByDomain(String domainName) {
                return rolesList;
            }
            @Override
            public Role getRole(String domainName, String roleName, Boolean auditLog, Boolean expand, Boolean pending) {
                throw new ResourceException(400, "Invalid request");
            }
        };

        DomainRoleMembersFetcher fetcher = new DomainRoleMembersFetcher(provider, USER_DOMAIN_PREFIX);
        assertEquals(new HashSet<>(), fetcher.getDomainRoleMembers("domain1", "role1"));
    }
}
