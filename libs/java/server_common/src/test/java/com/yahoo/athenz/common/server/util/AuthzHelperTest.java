/*
 * Copyright 2020 Verizon Media
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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Timestamp;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class AuthzHelperTest {

    AuthzHelper.GroupMembersFetcher nullFetcher = groupName -> null;
    AuthzHelper.GroupMembersFetcher devTeamFetcher = new AuthzHelper.GroupMembersFetcher() {
        List<GroupMember> groupMembers;

        {
            groupMembers = new ArrayList<>();
            groupMembers.add(new GroupMember().setMemberName("user.valid"));
            groupMembers.add(new GroupMember().setMemberName("user.disabled").setSystemDisabled(1));
            groupMembers.add(new GroupMember().setMemberName("user.expired").setExpiration(Timestamp.fromMillis(100)));
        }

        @Override
        public List<GroupMember> getGroupMembers(String groupName) {
            return groupMembers;
        }
    };

    @DataProvider(name = "members")
    public static Object[][] getMembers() {
        return new Object[][]{
                {Collections.singletonList("member1"), null, 1},
                {Collections.singletonList("member1"), Collections.singletonList("member1"), 0},
                {Collections.singletonList("member1"), Collections.singletonList("member2"), 1},
                {Collections.singletonList("member1"), Arrays.asList("member2", "member1"), 0},
                {Arrays.asList("member1", "member2"), Arrays.asList("member2", "member1"), 0},
                {Arrays.asList("member1", "member2"), Collections.singletonList("member3"), 2}
        };
    }

    @Test(dataProvider = "members")
    public void testRemoveRoleMembers(List<String> originalRoleMembersList,
                                      List<String> removeRoleMembersList, int expectedSize) {

        List<RoleMember> originalRoleMembers = convertMembersToRoleMembers(originalRoleMembersList);
        List<RoleMember> removeRoleMembers = convertMembersToRoleMembers(removeRoleMembersList);

        AuthzHelper.removeRoleMembers(originalRoleMembers, removeRoleMembers);

        //remove case
        for (RoleMember orgMember : originalRoleMembers) {
            for (RoleMember removeMember : removeRoleMembers) {
                if (orgMember.getMemberName().equalsIgnoreCase(removeMember.getMemberName())) {
                    fail("Should have removed " + removeMember.getMemberName());
                }
            }
        }

        assertEquals(originalRoleMembers.size(), expectedSize);
    }

    @Test
    public void testRemoveRoleMembersInvalidInput() {
        List<RoleMember> list = Collections.singletonList(new RoleMember().setMemberName("member1"));
        AuthzHelper.removeRoleMembers(list, null);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getMemberName(), "member1");

        AuthzHelper.removeRoleMembers(null, list);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getMemberName(), "member1");
    }

    @DataProvider(name = "group-members")
    public static Object[][] getGroupMembers() {
        return new Object[][]{
                {Collections.singletonList("member1"), null, 1},
                {Collections.singletonList("member1"), Collections.singletonList("member1"), 0},
                {Collections.singletonList("member1"), Collections.singletonList("member2"), 1},
                {Collections.singletonList("member1"), Arrays.asList("member2", "member1"), 0},
                {Arrays.asList("member1", "member2"), Arrays.asList("member2", "member1"), 0},
                {Arrays.asList("member1", "member2"), Collections.singletonList("member3"), 2}
        };
    }

    private List<GroupMember> convertListToGroupMembers(List<String> members) {
        List<GroupMember> groupMembers = new ArrayList<>();
        if (members == null) {
            return groupMembers;
        }
        for (String member : members) {
            groupMembers.add(new GroupMember().setMemberName(member));
        }
        return groupMembers;
    }

    @Test(dataProvider = "group-members")
    public void testRemoveGroupMembers(List<String> originalGroupMembersList,
                                       List<String> removeGroupMembersList, int expectedSize) {

        List<GroupMember> originalGroupMembers = convertListToGroupMembers(originalGroupMembersList);
        List<GroupMember> removeGroupMembers = convertListToGroupMembers(removeGroupMembersList);

        AuthzHelper.removeGroupMembers(originalGroupMembers, removeGroupMembers);

        //remove case
        for (GroupMember orgMember : originalGroupMembers) {
            for (GroupMember removeMember : removeGroupMembers) {
                if (orgMember.getMemberName().equalsIgnoreCase(removeMember.getMemberName())) {
                    fail("Should have removed " + removeMember.getMemberName());
                }
            }
        }

        assertEquals(originalGroupMembers.size(), expectedSize);
    }

    @Test
    public void testRemoveGroupMembersInvalidInput() {
        List<GroupMember> list = Collections.singletonList(new GroupMember().setMemberName("member1"));
        AuthzHelper.removeGroupMembers(list, null);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getMemberName(), "member1");

        AuthzHelper.removeGroupMembers(null, list);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getMemberName(), "member1");
    }

    private List<RoleMember> convertMembersToRoleMembers(List<String> members) {
        List<RoleMember> roleMemberList = new ArrayList<>();
        if (members == null) {
            return roleMemberList;
        }
        for (String member: members) {
            roleMemberList.add(new RoleMember().setMemberName(member));
        }
        return roleMemberList;
    }

    @Test
    public void testIsDisabledMember() {
        assertFalse(AuthzHelper.isMemberDisabled(null));
        assertFalse(AuthzHelper.isMemberDisabled(0));
        assertTrue(AuthzHelper.isMemberDisabled(1));
        assertTrue(AuthzHelper.isMemberDisabled(2));
    }

    @Test
    public void testIsExpiredMember() {
        assertFalse(AuthzHelper.isMemberExpired(null, 0));
        assertFalse(AuthzHelper.isMemberExpired(Timestamp.fromCurrentTime(), System.currentTimeMillis() - 10000));
        assertTrue(AuthzHelper.isMemberExpired(Timestamp.fromCurrentTime(), System.currentTimeMillis() + 10000));
    }

    @Test
    public void testShouldSkipGroupMember() {
        long currentTime = System.currentTimeMillis();
        GroupMember member = new GroupMember();
        assertFalse(AuthzHelper.shouldSkipGroupMember(member, currentTime));

        member.setSystemDisabled(0);
        assertFalse(AuthzHelper.shouldSkipGroupMember(member, currentTime));

        member.setExpiration(Timestamp.fromMillis(currentTime + 10000));
        assertFalse(AuthzHelper.shouldSkipGroupMember(member, currentTime));

        member.setSystemDisabled(null);
        member.setExpiration(Timestamp.fromMillis(currentTime + 10000));
        assertFalse(AuthzHelper.shouldSkipGroupMember(member, currentTime));

        member.setSystemDisabled(1);
        member.setExpiration(null);
        assertTrue(AuthzHelper.shouldSkipGroupMember(member, currentTime));

        member.setSystemDisabled(1);
        member.setExpiration(Timestamp.fromMillis(currentTime - 10000));
        assertTrue(AuthzHelper.shouldSkipGroupMember(member, currentTime));

        member.setSystemDisabled(0);
        member.setExpiration(Timestamp.fromMillis(currentTime - 10000));
        assertTrue(AuthzHelper.shouldSkipGroupMember(member, currentTime));

        member.setSystemDisabled(null);
        member.setExpiration(Timestamp.fromMillis(currentTime - 10000));
        assertTrue(AuthzHelper.shouldSkipGroupMember(member, currentTime));
    }

    @Test
    public void testMemberNameMatch() {
        assertTrue(AuthzHelper.memberNameMatch("*", "user.joe"));
        assertTrue(AuthzHelper.memberNameMatch("*", "athenz.service.storage"));
        assertTrue(AuthzHelper.memberNameMatch("user.*", "user.joe"));
        assertTrue(AuthzHelper.memberNameMatch("athenz.*", "athenz.service.storage"));
        assertTrue(AuthzHelper.memberNameMatch("athenz.service*", "athenz.service.storage"));
        assertTrue(AuthzHelper.memberNameMatch("athenz.service*", "athenz.service-storage"));
        assertTrue(AuthzHelper.memberNameMatch("athenz.service*", "athenz.service"));
        assertTrue(AuthzHelper.memberNameMatch("user.joe", "user.joe"));

        assertFalse(AuthzHelper.memberNameMatch("user.*", "athenz.joe"));
        assertFalse(AuthzHelper.memberNameMatch("athenz.*", "athenztest.joe"));
        assertFalse(AuthzHelper.memberNameMatch("athenz.service*", "athenz.servic"));
        assertFalse(AuthzHelper.memberNameMatch("athenz.service*", "athenz.servictag"));
        assertFalse(AuthzHelper.memberNameMatch("user.joe", "user.joel"));
    }

    @Test
    public void testShouldRunDelegatedTrustCheck() {
        assertFalse(AuthzHelper.shouldRunDelegatedTrustCheck(null, "TrustDomain"));
        assertTrue(AuthzHelper.shouldRunDelegatedTrustCheck("TrustDomain", null));
        assertTrue(AuthzHelper.shouldRunDelegatedTrustCheck("TrustDomain", "TrustDomain"));
        assertFalse(AuthzHelper.shouldRunDelegatedTrustCheck("TrustDomain1", "TrustDomain"));
    }

    @Test
    public void testRetrieveResourceDomainA() {
        assertEquals("trustdomain", AuthzHelper.retrieveResourceDomain("resource", "assume_role", "trustdomain"));
        assertEquals("domain1", AuthzHelper.retrieveResourceDomain("domain1:resource", "assume_role", null));
        assertEquals("domain1", AuthzHelper.retrieveResourceDomain("domain1:resource", "read", null));
        assertEquals("domain1", AuthzHelper.retrieveResourceDomain("domain1:resource", "read", "trustdomain"));
        assertEquals("domain1", AuthzHelper.retrieveResourceDomain("domain1:a:b:c:d:e", "read", "trustdomain"));
        assertNull(AuthzHelper.retrieveResourceDomain("domain1-invalid", "read", null));
    }

    @Test
    public void testExtractResourceDomainName() {
        assertEquals(AuthzHelper.extractResourceDomainName("domain:entity"), "domain");
        assertEquals(AuthzHelper.extractResourceDomainName("domain:entity:value2"), "domain");
        assertEquals(AuthzHelper.extractResourceDomainName("domain:https://web.athenz.com/data"), "domain");
    }

    @Test
    public void testCheckKerberosAuthorityAuthorization() {
        Authority authority = new com.yahoo.athenz.auth.impl.KerberosAuthority();
        Principal principal = SimplePrincipal.create("krb", "user1", "v=U1;d=user;n=user1;s=signature",
                0, authority);
        assertNotNull(principal);
        assertTrue(AuthzHelper.authorityAuthorizationAllowed(principal));
    }

    @Test
    public void testCheckNullAuthorityAuthorization() {
        Principal principal = SimplePrincipal.create("user", "joe", "v=U1;d=user;n=user1;s=signature",
                0, null);
        assertNotNull(principal);
        assertTrue(AuthzHelper.authorityAuthorizationAllowed(principal));
    }

    @Test
    public void testIsMemberOfGroup() {
        Group group = new Group();
        assertFalse(AuthzHelper.isMemberOfGroup(group.getGroupMembers(), "user.user1"));

        List<GroupMember> members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1"));
        members.add(new GroupMember().setMemberName("coretech.api"));
        group.setGroupMembers(members);

        assertTrue(AuthzHelper.isMemberOfGroup(group.getGroupMembers(), "user.user1"));
        assertTrue(AuthzHelper.isMemberOfGroup(group.getGroupMembers(), "coretech.api"));
        assertFalse(AuthzHelper.isMemberOfGroup(group.getGroupMembers(), "user.user2"));
        assertFalse(AuthzHelper.isMemberOfGroup(group.getGroupMembers(), "coretech.dev.api"));
    }

    @Test
    public void testAssumeRoleResourceMatchActionNoMatch() {
        Assertion assertion = new Assertion()
                .setAction("test")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:*");
        assertFalse(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));

        assertion = new Assertion()
                .setAction("assume_role1")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:*");
        assertFalse(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));

        assertion = new Assertion()
                .setAction("assume_rol")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:*");
        assertFalse(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));
    }

    @Test
    public void testAssumeRoleResourceMatchRoleNoMatch() {
        Assertion assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:role.role2");
        assertFalse(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));

        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain2:role.role1");
        assertFalse(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));

        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:role.reader*");
        assertFalse(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));

        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("*:role.role2");
        assertFalse(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));
    }

    @Test
    public void testAssumeRoleResourceMatch() {
        Assertion assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain2:role.role1")
                .setResource("domain1:role.role1");
        assertTrue(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));

        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain2:role.role1")
                .setResource("domain1:role.*");
        assertTrue(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));

        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain2:role.role1")
                .setResource("domain1:*");
        assertTrue(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));

        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain2:role.role1")
                .setResource("*:role.role1");
        assertTrue(AuthzHelper.assumeRoleResourceMatch("domain1:role.role1", assertion));
    }

    @Test
    public void testMatchDelegatedTrustPolicyNullAssertions() {
        Policy policy = new Policy();
        assertFalse(AuthzHelper.matchDelegatedTrustPolicy(policy, "testRole", "testMember", null, nullFetcher));
    }

    @Test
    public void testMatchDelegatedTrustPolicyMatch() {

        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.*");

        List<Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        Policy policy = new Policy();
        policy.setAssertions(assertions);

        List<Role> roles = new ArrayList<>();

        Role role = createRoleObject("weather",  "Role1", "user.user1");
        roles.add(role);

        role = createRoleObject("weather",  "Role", "user.user2");
        roles.add(role);

        assertTrue(AuthzHelper.matchDelegatedTrustPolicy(policy, "weather:role.Role", "user.user2", roles, devTeamFetcher));
        assertFalse(AuthzHelper.matchDelegatedTrustPolicy(policy, "weather:role.Role", "user.unknown", roles, devTeamFetcher));
    }

    @Test
    public void testMatchDelegatedTrustAssertionInvalidAction() {

        Assertion assertion = new Assertion();
        assertion.setAction("READ");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain:*");
        assertion.setRole("domain:role.Role");

        assertFalse(AuthzHelper.matchDelegatedTrustAssertion(assertion, null, null, null, nullFetcher));
    }

    @Test
    public void testMatchDelegatedTrustAssertionNoResPatternMatchWithOutPattern() {

        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain:role.Role");
        assertion.setRole("domain:role.Role");

        assertFalse(AuthzHelper.matchDelegatedTrustAssertion(assertion, "domain:role.Role2", null, null, nullFetcher));
        assertFalse(AuthzHelper.matchDelegatedTrustAssertion(assertion, "coretech:role.Role", null, null, nullFetcher));
    }

    @Test
    public void testMatchDelegatedTrustAssertionNoResPatternMatchWithPattern() {

        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("domain:role.Role");

        assertFalse(AuthzHelper.matchDelegatedTrustAssertion(assertion, "domain:role.Role2", null, null, nullFetcher));
        assertFalse(AuthzHelper.matchDelegatedTrustAssertion(assertion, "coretech:role.Role2", null, null, nullFetcher));
    }

    @Test
    public void testMatchDelegatedTrustAssertionNoRoleMatchWithPattern() {

        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.*");

        List<Role> roles = new ArrayList<>();

        Role role = createRoleObject("coretech", "readers", null);
        roles.add(role);

        role = createRoleObject("coretech", "writers", null);
        roles.add(role);

        role = createRoleObject("coretech", "updaters", null);
        roles.add(role);

        assertFalse(AuthzHelper.matchDelegatedTrustAssertion(assertion, "coretech:role.Role", null, roles, nullFetcher));
    }

    @Test
    public void testMatchDelegatedTrustAssertionNoRoleMatchWithOutPattern() {

        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.Role");

        List<Role> roles = new ArrayList<>();

        Role role = createRoleObject("coretech",  "Role1", null);
        roles.add(role);

        role = createRoleObject("coretech",  "Role2", null);
        roles.add(role);

        assertFalse(AuthzHelper.matchDelegatedTrustAssertion(assertion, "weather:role.Role1", null, roles, nullFetcher));
        assertFalse(AuthzHelper.matchDelegatedTrustAssertion(assertion, "coretech:role.Role", null, roles, nullFetcher));
    }

    @Test
    public void testMatchDelegatedTrustAssertionNoMemberMatch() {

        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.Role");

        List<Role> roles = new ArrayList<>();

        Role role = createRoleObject("weather",  "Role1", "user.user1");
        roles.add(role);

        role = createRoleObject("weather",  "Role", "user.user2");
        roles.add(role);

        assertFalse(AuthzHelper.matchDelegatedTrustAssertion(assertion, "weather:role.Role", "user.user1", roles, nullFetcher));
    }

    @Test
    public void testMatchDelegatedTrustAssertionValidWithPattern() {

        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.*");

        List<Role> roles = new ArrayList<>();

        Role role = createRoleObject("weather",  "Role1", "user.user1");
        roles.add(role);

        role = createRoleObject("weather",  "Role", "user.user2");
        roles.add(role);

        assertTrue(AuthzHelper.matchDelegatedTrustAssertion(assertion, "weather:role.Role", "user.user2", roles, nullFetcher));
    }

    @Test
    public void testMatchDelegatedTrustAssertionValidWithOutPattern() {

        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.Role");

        List<Role> roles = new ArrayList<>();

        Role role = createRoleObject("weather",  "Role1", "user.user1");
        roles.add(role);

        role = createRoleObject("weather",  "Role", "user.user2");
        roles.add(role);

        assertTrue(AuthzHelper.matchDelegatedTrustAssertion(assertion, "weather:role.Role", "user.user2", roles, nullFetcher));
    }

    private Role createRoleObject(final String domainName, final String roleName, final String member) {

        List<RoleMember> members = new ArrayList<>();
        if (member != null) {
            members.add(new RoleMember().setMemberName(member));
        }

        Role role = new Role();
        role.setName(domainName + ":role." + roleName);
        role.setRoleMembers(members);

        return role;
    }

    @Test
    public void testIsMemberOfRole() {

        List<RoleMember> roleMembers = new ArrayList<>();

        // valid members

        RoleMember roleMemberJoe = new RoleMember()
                .setMemberName("user.joe")
                .setPrincipalType(Principal.Type.USER.getValue());
        RoleMember roleMemberJane = new RoleMember()
                .setMemberName("user.jane")
                .setPrincipalType(Principal.Type.USER.getValue());
        RoleMember roleGroup1  = new RoleMember()
                .setMemberName("coretech:group.dev-team")
                .setPrincipalType(Principal.Type.GROUP.getValue());

        roleMembers.add(roleMemberJoe);
        roleMembers.add(roleMemberJane);
        roleMembers.add(roleGroup1);

        Role role = new Role().setName("coretech:role.role1").setRoleMembers(roleMembers);

        // carry out the checks

        assertTrue(AuthzHelper.isMemberOfRole(role, "user.joe", devTeamFetcher));
        assertTrue(AuthzHelper.isMemberOfRole(role, "user.jane", devTeamFetcher));
        assertFalse(AuthzHelper.isMemberOfRole(role, "user.john", devTeamFetcher));

        assertTrue(AuthzHelper.isMemberOfRole(role, "user.valid", devTeamFetcher));
        assertFalse(AuthzHelper.isMemberOfRole(role, "user.disabled", devTeamFetcher));
        assertFalse(AuthzHelper.isMemberOfRole(role, "user.expired", devTeamFetcher));

        assertFalse(AuthzHelper.isMemberOfRole(role, "user.unknown", devTeamFetcher));
    }

    @Test
    public void testIsMemberOfRoleNullMembers() {
        Role role = new Role().setName("coretech:role.role1");
        assertFalse(AuthzHelper.isMemberOfRole(role, "user.joe", devTeamFetcher));
    }

    @Test
    public void testCheckRoleMemberValidity() {

        List<RoleMember> roleMembers = new ArrayList<>();

        // valid members

        RoleMember roleMemberJoe = new RoleMember()
                .setMemberName("user.joe")
                .setPrincipalType(Principal.Type.USER.getValue());
        RoleMember roleMemberJane = new RoleMember()
                .setMemberName("user.jane")
                .setSystemDisabled(null)
                .setExpiration(null);
        RoleMember roleMemberJohn = new RoleMember()
                .setSystemDisabled(0)
                .setMemberName("user.john")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000));

        roleMembers.add(roleMemberJoe);
        roleMembers.add(roleMemberJane);
        roleMembers.add(roleMemberJohn);

        // invalid members

        RoleMember roleMemberJoeBad = new RoleMember()
                .setMemberName("user.joe-bad")
                .setSystemDisabled(1);
        RoleMember roleMemberJaneBad = new RoleMember()
                .setMemberName("user.jane-bad")
                .setSystemDisabled(null)
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 1));
        RoleMember roleMemberJohnBad = new RoleMember()
                .setSystemDisabled(3)
                .setMemberName("user.john-bad")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 10000));
        RoleMember roleGroup1  = new RoleMember()
                .setMemberName("coretech:group.dev-team")
                .setPrincipalType(Principal.Type.GROUP.getValue());

        roleMembers.add(roleMemberJoeBad);
        roleMembers.add(roleMemberJaneBad);
        roleMembers.add(roleMemberJohnBad);
        roleMembers.add(roleGroup1);

        // carry out the checks

        assertTrue(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.joe", nullFetcher));
        assertTrue(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.jane", nullFetcher));
        assertTrue(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.john", nullFetcher));

        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.joe-bad", nullFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.jane-bad", nullFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.john-bad", nullFetcher));

        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.unknown", nullFetcher));
    }

    @Test
    public void testCheckRoleMemberValidityGroupMember() {

        List<RoleMember> roleMembers = new ArrayList<>();

        // valid members

        RoleMember roleMemberJoe = new RoleMember()
                .setMemberName("user.joe")
                .setPrincipalType(Principal.Type.USER.getValue());
        RoleMember roleMemberJane = new RoleMember()
                .setMemberName("user.jane");
        RoleMember roleGroup1  = new RoleMember()
                .setMemberName("coretech:group.dev-team")
                .setPrincipalType(Principal.Type.GROUP.getValue());

        roleMembers.add(roleMemberJoe);
        roleMembers.add(roleMemberJane);
        roleMembers.add(roleGroup1);

        // carry out the checks

        assertTrue(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.joe", devTeamFetcher));
        assertTrue(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.jane", devTeamFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.john", devTeamFetcher));

        assertTrue(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.valid", devTeamFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.disabled", devTeamFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.expired", devTeamFetcher));

        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.unknown", devTeamFetcher));
    }

    @Test
    public void testCheckRoleMemberValidityExpiredGroupMember() {

        List<RoleMember> roleMembers = new ArrayList<>();

        // valid members

        RoleMember roleGroup1  = new RoleMember()
                .setMemberName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(1000))
                .setPrincipalType(Principal.Type.GROUP.getValue());

        roleMembers.add(roleGroup1);

        // carry out the checks

        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.joe", devTeamFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.jane", devTeamFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.john", devTeamFetcher));

        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.valid", devTeamFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.disabled", devTeamFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.expired", devTeamFetcher));

        assertFalse(AuthzHelper.checkRoleMemberValidity(roleMembers, "user.unknown", devTeamFetcher));
    }

    @Test
    public void testCheckRoleMemberExpiration() {

        RoleMember roleMember1 = new RoleMember();
        roleMember1.setExpiration(Timestamp.fromMillis(1001));
        roleMember1.setMemberName("user.athenz1");

        RoleMember roleMember2 = new RoleMember();
        roleMember2.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 10000));
        roleMember2.setMemberName("user.athenz2");

        List<RoleMember> members = new ArrayList<>();
        members.add(roleMember1);
        members.add(roleMember2);

        assertTrue(AuthzHelper.checkRoleMemberValidity(members, "user.athenz2", nullFetcher));
        assertFalse(AuthzHelper.checkRoleMemberValidity(members, "user.athenz1", nullFetcher));
    }
}
