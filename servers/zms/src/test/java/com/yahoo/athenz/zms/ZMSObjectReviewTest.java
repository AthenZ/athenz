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

package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class ZMSObjectReviewTest {

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
    public void testIsAllowedObjectReviewLookup() {

        Principal principal = getPrincipal("user", "john");
        assertNotNull(principal);

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // without any setup, the principal will only work if the checkPrincipal
        // matches the principal

        assertTrue(zmsImpl.isAllowedObjectReviewLookup(principal, "user.john"));
        assertFalse(zmsImpl.isAllowedObjectReviewLookup(principal, "user.jane"));

        // invalid principals should return failure

        assertFalse(zmsImpl.isAllowedObjectReviewLookup(principal, "unknown-domain"));

        // asking for a domain that doesn't exist, must return failure

        assertFalse(zmsImpl.isAllowedObjectReviewLookup(principal, "unknown-domain.service"));

        // now let's set up the user as system role lookup user

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.john"));

        Role role = zmsTestInitializer.createRoleObject("sys.auth", "review-role", null, roleMembers);
        zmsImpl.putRole(ctx, "sys.auth", "review-role", auditRef, false, role);

        Policy policy = zmsTestInitializer.createPolicyObject("sys.auth", "review-policy", "review-role",
                "access", "sys.auth:meta.review.lookup", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "sys.auth", "review-policy", auditRef, false, policy);

        // now our access check should work

        assertTrue(zmsImpl.isAllowedObjectReviewLookup(principal, "user.jane"));

        zmsImpl.deletePolicy(ctx, "sys.auth", "review-policy", auditRef);
        zmsImpl.deleteRole(ctx, "sys.auth", "review-role", auditRef);
    }

    private Principal getPrincipal(final String domainName, final String userName) {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        final String unsignedCreds = "v=U1;d=" + domainName + ";n=" + userName;
        return SimplePrincipal.create(domainName, userName, unsignedCreds + ";s=signature", 0, principalAuthority);
    }

    @Test
    public void testGetRolesForReviewUnauthorized() {
        Principal principal = getPrincipal("user", "john");
        assertNotNull(principal);

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        try {
            zmsImpl.getRolesForReview(rsrcCtx1, zmsTestInitializer.getAdminUser());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.FORBIDDEN, ex.getCode());
        }
    }

    @Test
    public void testGetRolesForReview() {

        Principal principal = getPrincipal("user", "john");
        assertNotNull(principal);

        createDomain("domain1", principal.getFullName());
        createDomain("domain2", principal.getFullName());
        createDomain("domain3", principal.getFullName());

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        insertRecordsForRoleReviewTest(principal.getFullName());

        // our roles without any config are not going to be returned

        ReviewObjects reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, null);
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 0);

        reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 0);

        // now let us set up 2 of the roles with expiry settings and
        // make sure both of them are returned without any review date

        RoleMeta meta = new RoleMeta().setMemberExpiryDays(30).setServiceExpiryDays(60);
        zmsImpl.putRoleMeta(rsrcCtx1, "domain1", "role1", auditRef, meta);

        meta = new RoleMeta().setMemberReviewDays(30);
        zmsImpl.putRoleMeta(rsrcCtx1, "domain3", "role1", auditRef, meta);

        // we should get back our 2 roles in domain1 and domain3

        reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 2);

        assertTrue(verifyReviewObjectExists(reviewObjects, "domain1", "role1"));
        assertTrue(verifyReviewObjectExists(reviewObjects, "domain3", "role1"));

        // we're going to set last reviewed date on the role in domain1 to current
        // value thus it should not be returned in our list

        Role role = new Role().setName("domain1:role.role1").setRoleMembers(Collections.emptyList());
        zmsImpl.putRoleReview(rsrcCtx1, "domain1", "role1", auditRef, false, role);

        // we should get back our domain3 role only

        reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 1);

        assertTrue(verifyReviewObjectExists(reviewObjects, "domain3", "role1"));

        zmsImpl.deleteTopLevelDomain(ctx,"domain1", auditRef);
        zmsImpl.deleteTopLevelDomain(ctx,"domain2", auditRef);
        zmsImpl.deleteTopLevelDomain(ctx,"domain3", auditRef);
    }

    boolean verifyReviewObjectExists(ReviewObjects objects, final String domainName, final String objectName) {
        for (ReviewObject object : objects.getList()) {
            if (object.getDomainName().equals(domainName) && object.getName().equals(objectName)) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void testGetGroupsForReviewUnauthorized() {
        Principal principal = getPrincipal("user", "john");
        assertNotNull(principal);

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        try {
            zmsImpl.getGroupsForReview(rsrcCtx1, zmsTestInitializer.getAdminUser());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.FORBIDDEN, ex.getCode());
        }
    }

    @Test
    public void testGetGroupsForReview() {

        Principal principal = getPrincipal("user", "john");
        assertNotNull(principal);

        createDomain("domain1", principal.getFullName());
        createDomain("domain2", principal.getFullName());
        createDomain("domain3", principal.getFullName());

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        ResourceContext rsrcCtx1 = zmsTestInitializer.createResourceContext(principal);

        insertRecordsForGroupReviewTest(principal.getFullName());

        // our roles without any config are not going to be returned

        ReviewObjects reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, null);
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 0);

        reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 0);

        // now let us setup 2 of the groups with expiry settings and
        // make sure both of them are returned without any review date

        GroupMeta meta = new GroupMeta().setMemberExpiryDays(30).setServiceExpiryDays(60);
        zmsImpl.putGroupMeta(rsrcCtx1, "domain1", "group1", auditRef, meta);

        meta = new GroupMeta().setServiceExpiryDays(30);
        zmsImpl.putGroupMeta(rsrcCtx1, "domain3", "group1", auditRef, meta);

        // we should get back our 2 groups in domain1 and domain3

        reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 2);

        assertTrue(verifyReviewObjectExists(reviewObjects, "domain1", "group1"));
        assertTrue(verifyReviewObjectExists(reviewObjects, "domain3", "group1"));

        // we're going to set last reviewed date on the group in domain1 to current
        // value thus it should not be returned in our list

        Group group = new Group().setName("domain1:group.group1").setGroupMembers(Collections.emptyList());
        zmsImpl.putGroupReview(rsrcCtx1, "domain1", "group1", auditRef, false, group);

        // we should get back our domain3 group only

        reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 1);

        assertTrue(verifyReviewObjectExists(reviewObjects, "domain3", "group1"));

        zmsImpl.deleteTopLevelDomain(ctx,"domain1", auditRef);
        zmsImpl.deleteTopLevelDomain(ctx,"domain2", auditRef);
        zmsImpl.deleteTopLevelDomain(ctx,"domain3", auditRef);
    }

    private void insertRecordsForRoleReviewTest(final String principal) {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName("user.test2"));
        roleMembers.add(new RoleMember().setMemberName(principal));

        // Create role1 in domain1 with members and principal
        Role role = zmsTestInitializer.createRoleObject("domain1", "role1", null, roleMembers);
        zmsImpl.putRole(ctx, "domain1", "Role1", auditRef, false, role);

        // Create role2 in domain1 with members and principal
        role = zmsTestInitializer.createRoleObject("domain1", "role2", null, roleMembers);
        zmsImpl.putRole(ctx, "domain1", "Role2", auditRef, false, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName("user.test2"));

        // Create role1 in domain2 with members but without the principal
        role = zmsTestInitializer.createRoleObject("domain2", "role1", null, roleMembers);
        zmsImpl.putRole(ctx, "domain2", "Role1", auditRef, false, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName(principal));

        // Create role1 in domain3 only principal
        role = zmsTestInitializer.createRoleObject("domain3", "role1", null, roleMembers);
        zmsImpl.putRole(ctx, "domain3", "role1", auditRef, false, role);
    }

    private void insertRecordsForGroupReviewTest(final String principal) {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.test1"));
        groupMembers.add(new GroupMember().setMemberName("user.test2"));
        groupMembers.add(new GroupMember().setMemberName(principal));

        // Create role1 in domain1 with members and principal
        Group group = zmsTestInitializer.createGroupObject("domain1", "group1", groupMembers);
        zmsImpl.putGroup(ctx, "domain1", "group1", auditRef, false, group);

        // Create role2 in domain1 with members and principal
        group = zmsTestInitializer.createGroupObject("domain1", "group2", groupMembers);
        zmsImpl.putGroup(ctx, "domain1", "group2", auditRef, false, group);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.test1"));
        groupMembers.add(new GroupMember().setMemberName("user.test2"));

        // Create role1 in domain2 with members but without the principal
        group = zmsTestInitializer.createGroupObject("domain2", "group1", groupMembers);
        zmsImpl.putGroup(ctx, "domain2", "group1", auditRef, false, group);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName(principal));

        // Create role1 in domain3 only principal
        group = zmsTestInitializer.createGroupObject("domain3", "group1", groupMembers);
        zmsImpl.putGroup(ctx, "domain3", "group1", auditRef, false, group);
    }

    private void createDomain(final String domainName, final String principal) {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test " + domainName, "testOrg", zmsTestInitializer.getAdminUser());
        dom.getAdminUsers().add(principal);
        zmsImpl.postTopLevelDomain(ctx, auditRef, dom);
    }
}
