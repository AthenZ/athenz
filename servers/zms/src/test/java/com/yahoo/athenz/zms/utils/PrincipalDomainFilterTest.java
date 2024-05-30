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

package com.yahoo.athenz.zms.utils;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.zms.*;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.*;

import java.lang.reflect.Member;
import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.*;

public class PrincipalDomainFilterTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

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
        MockitoAnnotations.openMocks(this);
        zmsTestInitializer.setUp();
    }

    @Test
    public void testPrincipalDomainFilter() {

        // empty filter has no processing and always returns true for validation

        PrincipalDomainFilter filter = new PrincipalDomainFilter("");
        assertNull(filter.allowedDomains);
        assertNull(filter.disallowedSubDomains);
        assertNull(filter.allowedSubDomains);
        assertTrue(filter.validate(null, Principal.Type.USER));
        assertTrue(filter.validate(null, Principal.Type.GROUP));

        filter = new PrincipalDomainFilter(null);
        assertNull(filter.allowedDomains);
        assertNull(filter.disallowedSubDomains);
        assertNull(filter.allowedSubDomains);
        assertTrue(filter.validate(null, Principal.Type.USER));
        assertTrue(filter.validate(null, Principal.Type.GROUP));

        // now let's test some valid filters

        filter = new PrincipalDomainFilter("domain1,domain2");
        assertNotNull(filter.allowedDomains);
        assertEquals(filter.allowedDomains.size(), 2);
        assertTrue(filter.allowedDomains.contains("domain1."));
        assertTrue(filter.allowedDomains.contains("domain2."));
        assertNull(filter.disallowedSubDomains);
        assertNull(filter.allowedSubDomains);

        filter = new PrincipalDomainFilter("domain1,domain2.api,+domain3,-domain4");
        assertNotNull(filter.allowedDomains);
        assertEquals(filter.allowedDomains.size(), 2);
        assertTrue(filter.allowedDomains.contains("domain1."));
        assertTrue(filter.allowedDomains.contains("domain2.api."));
        assertNotNull(filter.allowedSubDomains);
        assertEquals(filter.allowedSubDomains.size(), 1);
        assertTrue(filter.allowedSubDomains.contains("domain3."));
        assertNotNull(filter.disallowedSubDomains);
        assertEquals(filter.disallowedSubDomains.size(), 1);
        assertTrue(filter.disallowedSubDomains.contains("domain4."));

        filter = new PrincipalDomainFilter("domain2.api,+domain1,+domain2,-domain1.api,-domain2.prod");
        assertNotNull(filter.allowedDomains);
        assertEquals(filter.allowedDomains.size(), 1);
        assertTrue(filter.allowedDomains.contains("domain2.api."));
        assertNotNull(filter.allowedSubDomains);
        assertEquals(filter.allowedSubDomains.size(), 2);
        assertTrue(filter.allowedSubDomains.contains("domain1."));
        assertTrue(filter.allowedSubDomains.contains("domain2."));
        assertNotNull(filter.disallowedSubDomains);
        assertEquals(filter.disallowedSubDomains.size(), 2);
        assertTrue(filter.disallowedSubDomains.contains("domain1.api."));
        assertTrue(filter.disallowedSubDomains.contains("domain2.prod."));
    }

    @DataProvider(name = "DomainFilterData")
    public static Object[][] domainFilterData() {
        return new Object[][] {
                { "user", "user.joe", Principal.Type.USER, true },
                { "user", "sports.api", Principal.Type.SERVICE, false },
                { "user", "athenz:group.dev-team", Principal.Type.GROUP, false },
                { "-home", "user.joe", Principal.Type.USER, true },
                { "-home", "sports.api", Principal.Type.SERVICE, true },
                { "-home", "athenz:group.dev-team", Principal.Type.GROUP, true },
                { "-home", "home.api", Principal.Type.SERVICE, false },
                { "-home", "home.prod.api", Principal.Type.SERVICE, false },
                { "+sports.prod", "user.joe", Principal.Type.USER, false },
                { "+sports.prod", "sports.api", Principal.Type.SERVICE, false },
                { "+sports.prod", "athenz:group.dev-team", Principal.Type.GROUP, false },
                { "+sports.prod", "sports.prod.api", Principal.Type.SERVICE, true },
                { "+sports.prod", "sports.prod.west2.api", Principal.Type.SERVICE, true },
                { "+sports.prod", "weather.api", Principal.Type.SERVICE, false },
                { "user,+sports,-sports.prod", "user.joe", Principal.Type.USER, true },
                { "user,+sports,-sports.prod", "sports.api", Principal.Type.SERVICE, true },
                { "user,+sports,-sports.prod", "sports.dev.api", Principal.Type.SERVICE, true },
                { "user,+sports,-sports.prod", "sports.prod.api", Principal.Type.SERVICE, false },
                { "user,+sports,-sports.prod", "sports.prod.west2.api", Principal.Type.SERVICE, false },
                { "user,+sports,-sports.prod", "weather.api", Principal.Type.SERVICE, false },
                { "user,+sports,-sports.prod", "athenz:group.dev-team", Principal.Type.GROUP, false },
                { "+sports,-sports.prod", "user.joe", Principal.Type.USER, false },
                { "+sports,-sports.prod", "sports.api", Principal.Type.SERVICE, true },
                { "+sports,-sports.prod", "sports.dev.api", Principal.Type.SERVICE, true },
                { "+sports,-sports.prod", "sports.prod.api", Principal.Type.SERVICE, false },
                { "+sports,-sports.prod", "sports.prod.west2.api", Principal.Type.SERVICE, false },
                { "+sports,-sports.prod", "weather.api", Principal.Type.SERVICE, false },
                { "+sports,-sports.prod", "athenz:group.dev-team", Principal.Type.GROUP, false },
        };
    }
    @Test(dataProvider = "DomainFilterData")
    public void testDomainFilterValidation(String filter, String principalName, Principal.Type type, boolean expectedResult) {
        PrincipalDomainFilter domainFilter = new PrincipalDomainFilter(filter);
        assertEquals(domainFilter.validate(principalName, type), expectedResult);
    }

    @Test
    public void testPutRoleWithDomainFilter() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-with-domain-filter";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject("sports",
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject("sports", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports", "api", auditRef, false, null, service1);

        Group group1 = zmsTestInitializer.createGroupObject("sports", "group1", null, null);
        zmsImpl.putGroup(ctx, "sports", "group1", auditRef, false, null, group1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject("prod", "sports", "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postSubDomain(ctx, "sports", auditRef, null, subDom1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject("sports.prod", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports.prod", "api", auditRef, false, null, service2);

        SubDomain subDom2 = zmsTestInitializer.createSubDomainObject("dev", "sports", "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postSubDomain(ctx, "sports", auditRef, null, subDom2);

        ServiceIdentity service3 = zmsTestInitializer.createServiceObject("sports.dev", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports.dev", "api", auditRef, false, null, service3);

        // add a role with the domain filter and allowed members

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user1"));
        roleMembers.add(new RoleMember().setMemberName("sports.api"));
        roleMembers.add(new RoleMember().setMemberName("sports:group.group1"));
        roleMembers.add(new RoleMember().setMemberName("sports.dev.api"));

        final String roleName1 = "filter-role1";
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName1, null, roleMembers);
        role1.setPrincipalDomainFilter("user,+sports,-sports.prod");
        zmsImpl.putRole(ctx, domainName, roleName1, auditRef, false, null, role1);

        // add a role with the domain filter and no allowed members

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.user1"));
        roleMembers.add(new RoleMember().setMemberName("sports.api"));
        roleMembers.add(new RoleMember().setMemberName("sports:group.group1"));
        roleMembers.add(new RoleMember().setMemberName("sports.dev.api"));
        roleMembers.add(new RoleMember().setMemberName("sports.prod.api"));
        role1.setRoleMembers(roleMembers);

        // sports.prod.api should be rejected

        try {
            zmsImpl.putRole(ctx, domainName, roleName1, auditRef, false, null, role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertEquals(ex.getMessage().contains("Principal sports.prod.api is not allowed for the role"), true);
        }

        zmsImpl.deleteSubDomain(ctx, "sports", "dev", auditRef, null);
        zmsImpl.deleteSubDomain(ctx, "sports", "prod", auditRef, null);
        zmsImpl.deleteMembership(ctx, domainName, roleName1, "sports:group.group1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "sports", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutRoleMembershipWithDomainFilter() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-mbr-with-domain-filter";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject("sports",
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject("sports", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports", "api", auditRef, false, null, service1);

        Group group1 = zmsTestInitializer.createGroupObject("sports", "group1", null, null);
        zmsImpl.putGroup(ctx, "sports", "group1", auditRef, false, null, group1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject("prod", "sports", "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postSubDomain(ctx, "sports", auditRef, null, subDom1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject("sports.prod", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports.prod", "api", auditRef, false, null, service2);

        SubDomain subDom2 = zmsTestInitializer.createSubDomainObject("dev", "sports", "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postSubDomain(ctx, "sports", auditRef, null, subDom2);

        ServiceIdentity service3 = zmsTestInitializer.createServiceObject("sports.dev", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports.dev", "api", auditRef, false, null, service3);

        // add a role with the domain filter

        final String roleName1 = "filter-role1";
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName1, null, null);
        role1.setPrincipalDomainFilter("user,+sports,-sports.prod");
        zmsImpl.putRole(ctx, domainName, roleName1, auditRef, false, null, role1);

        // user.user1 should be able to be added to the role

        Membership membership = new Membership().setMemberName("user.user1");
        zmsImpl.putMembership(ctx, domainName, roleName1, "user.user1", auditRef, false, null, membership);

        // sports.api should be able to be added to the role

        membership = new Membership().setMemberName("sports.api");
        zmsImpl.putMembership(ctx, domainName, roleName1, "sports.api", auditRef, false, null, membership);

        // sports:group.group1 should be allowed to be added to the role

        membership = new Membership().setMemberName("sports:group.group1");
        zmsImpl.putMembership(ctx, domainName, roleName1, "sports:group.group1", auditRef, false, null, membership);

        // sports.dev.api should be able to be added to the role

        membership = new Membership().setMemberName("sports.dev.api");
        zmsImpl.putMembership(ctx, domainName, roleName1, "sports.dev.api", auditRef, false, null, membership);

        // sports.prod.api should be rejected

        membership = new Membership().setMemberName("sports.prod.api");
        try {
            zmsImpl.putMembership(ctx, domainName, roleName1, "sports.prod.api", auditRef, false, null, membership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertEquals(ex.getMessage().contains("Principal sports.prod.api is not allowed for the role"), true);
        }

        zmsImpl.deleteSubDomain(ctx, "sports", "dev", auditRef, null);
        zmsImpl.deleteSubDomain(ctx, "sports", "prod", auditRef, null);
        zmsImpl.deleteMembership(ctx, domainName, roleName1, "sports:group.group1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "sports", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutGroupWithDomainFilter() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-with-domain-filter";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject("sports",
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject("sports", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports", "api", auditRef, false, null, service1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject("prod", "sports", "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postSubDomain(ctx, "sports", auditRef, null, subDom1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject("sports.prod", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports.prod", "api", auditRef, false, null, service2);

        SubDomain subDom2 = zmsTestInitializer.createSubDomainObject("dev", "sports", "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postSubDomain(ctx, "sports", auditRef, null, subDom2);

        ServiceIdentity service3 = zmsTestInitializer.createServiceObject("sports.dev", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports.dev", "api", auditRef, false, null, service3);

        // add a group with the domain filter and allowed members

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user1"));
        groupMembers.add(new GroupMember().setMemberName("sports.api"));
        groupMembers.add(new GroupMember().setMemberName("sports.dev.api"));

        final String groupName1 = "filter-group1";
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName1, groupMembers);
        group1.setPrincipalDomainFilter("user,+sports,-sports.prod");
        zmsImpl.putGroup(ctx, domainName, groupName1, auditRef, false, null, group1);

        // add a group with the domain filter and no allowed members

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user1"));
        groupMembers.add(new GroupMember().setMemberName("sports.api"));
        groupMembers.add(new GroupMember().setMemberName("sports.dev.api"));
        groupMembers.add(new GroupMember().setMemberName("sports.prod.api"));
        group1.setGroupMembers(groupMembers);

        // sports.prod.api should be rejected

        try {
            zmsImpl.putGroup(ctx, domainName, groupName1, auditRef, false, null, group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertEquals(ex.getMessage().contains("Principal sports.prod.api is not allowed for the group"), true);
        }

        zmsImpl.deleteSubDomain(ctx, "sports", "dev", auditRef, null);
        zmsImpl.deleteSubDomain(ctx, "sports", "prod", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "sports", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutGroupMembershipWithDomainFilter() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-mbr-with-domain-filter";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject("sports",
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject("sports", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports", "api", auditRef, false, null, service1);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject("prod", "sports", "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postSubDomain(ctx, "sports", auditRef, null, subDom1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject("sports.prod", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports.prod", "api", auditRef, false, null, service2);

        SubDomain subDom2 = zmsTestInitializer.createSubDomainObject("dev", "sports", "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postSubDomain(ctx, "sports", auditRef, null, subDom2);

        ServiceIdentity service3 = zmsTestInitializer.createServiceObject("sports.dev", "api",
                "http://localhost:8080", null, null, null, null);
        zmsImpl.putServiceIdentity(ctx, "sports.dev", "api", auditRef, false, null, service3);

        // add a group with the domain filter

        final String groupName1 = "filter-group1";
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName1, null, null);
        group1.setPrincipalDomainFilter("user,+sports,-sports.prod");
        zmsImpl.putGroup(ctx, domainName, groupName1, auditRef, false, null, group1);

        // user.user1 should be able to be added to the group

        GroupMembership membership = new GroupMembership().setMemberName("user.user1");
        zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.user1", auditRef, false, null, membership);

        // sports.api should be able to be added to the group

        membership = new GroupMembership().setMemberName("sports.api");
        zmsImpl.putGroupMembership(ctx, domainName, groupName1, "sports.api", auditRef, false, null, membership);

        // sports.dev.api should be able to be added to the group

        membership = new GroupMembership().setMemberName("sports.dev.api");
        zmsImpl.putGroupMembership(ctx, domainName, groupName1, "sports.dev.api", auditRef, false, null, membership);

        // sports.prod.api should be rejected

        membership = new GroupMembership().setMemberName("sports.prod.api");
        try {
            zmsImpl.putGroupMembership(ctx, domainName, groupName1, "sports.prod.api", auditRef, false, null, membership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertEquals(ex.getMessage().contains("Principal sports.prod.api is not allowed for the group"), true);
        }

        zmsImpl.deleteSubDomain(ctx, "sports", "dev", auditRef, null);
        zmsImpl.deleteSubDomain(ctx, "sports", "prod", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "sports", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testUnknownDomainFilterName() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "unknown-domain-filter-name";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        try {
            Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null, null);
            role1.setPrincipalDomainFilter("user,unknown-domain-name");
            zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("No such domain: unknown-domain-name"));
        }

        try {
            Group group1 = zmsTestInitializer.createGroupObject(domainName, "group1", null, null);
            group1.setPrincipalDomainFilter("user,unknown-domain-name");
            zmsImpl.putGroup(ctx, domainName, "group1", auditRef, false, null, group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("No such domain: unknown-domain-name"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
