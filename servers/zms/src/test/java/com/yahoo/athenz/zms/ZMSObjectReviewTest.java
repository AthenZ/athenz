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
import com.yahoo.rdl.Timestamp;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

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

        // try the access check with role based principal

        List<String> roles = List.of("review-role");
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        principal = SimplePrincipal.create("sys.auth", "unsigned-creds", roles, principalAuthority);

        assertTrue(zmsImpl.isAllowedObjectReviewLookup(principal, "user.jane"));

        // without the required role, we should get failure

        roles = List.of("role1", "role2");
        principal = SimplePrincipal.create("sys.auth", "unsigned-creds", roles, principalAuthority);

        assertFalse(zmsImpl.isAllowedObjectReviewLookup(principal, "user.jane"));

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

        System.setProperty(ZMSConsts.ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_UPDATED_OBJECT, "30");

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
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

        // now let us setup 2 of the role with expiry settings and
        // make sure both of them are not returned since they're configured
        // with review date set in the past over 15 days

        Timestamp past15Days = Timestamp.fromMillis(System.currentTimeMillis() -
                TimeUnit.MILLISECONDS.convert(15, TimeUnit.DAYS));

        RoleMeta meta = new RoleMeta().setMemberExpiryDays(30).setServiceExpiryDays(60)
                        .setLastReviewedDate(past15Days);
        zmsImpl.putRoleMeta(rsrcCtx1, "domain1", "role1", auditRef, meta);

        meta = new RoleMeta().setMemberReviewDays(30).setLastReviewedDate(past15Days);
        zmsImpl.putRoleMeta(rsrcCtx1, "domain3", "role1", auditRef, meta);

        // we should get back no roles in domain1 and domain3

        reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertTrue(reviewObjects.getList().isEmpty());

        // now let's set the expiry to a value 15 days for domain3
        // and we should get back that entry in our list

        meta = new RoleMeta().setServiceExpiryDays(15);
        zmsImpl.putRoleMeta(rsrcCtx1, "domain3", "role1", auditRef, meta);

        reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 1);

        assertTrue(verifyReviewObjectExists(reviewObjects, "domain3", "role1"));

        // we're going to set last reviewed date on the group in domain3 to current
        // value thus it should not be returned in our list

        Role role = new Role().setName("domain3:role.role1").setRoleMembers(Collections.emptyList());
        zmsImpl.putRoleReview(rsrcCtx1, "domain3", "role1", auditRef, false, role);

        // we should get back no roles in domain1 and domain3

        reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertTrue(reviewObjects.getList().isEmpty());

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

        System.setProperty(ZMSConsts.ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_UPDATED_OBJECT, "30");

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
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
        // make sure both of them are not returned since they're configured
        // with review date set in the past over 15 days

        Timestamp past15Days = Timestamp.fromMillis(System.currentTimeMillis() -
                TimeUnit.MILLISECONDS.convert(15, TimeUnit.DAYS));
        GroupMeta meta = new GroupMeta().setMemberExpiryDays(30).setServiceExpiryDays(60)
                .setLastReviewedDate(past15Days);
        zmsImpl.putGroupMeta(rsrcCtx1, "domain1", "group1", auditRef, meta);

        meta = new GroupMeta().setServiceExpiryDays(30).setLastReviewedDate(past15Days);
        zmsImpl.putGroupMeta(rsrcCtx1, "domain3", "group1", auditRef, meta);

        // we should get back no groups in domain1 and domain3

        reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertTrue(reviewObjects.getList().isEmpty());

        // now let's set the expiry to a value 15 days for domain3
        // and we should get back that entry in our list

        meta = new GroupMeta().setServiceExpiryDays(15);
        zmsImpl.putGroupMeta(rsrcCtx1, "domain3", "group1", auditRef, meta);

        reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 1);

        assertTrue(verifyReviewObjectExists(reviewObjects, "domain3", "group1"));

        // we're going to set last reviewed date on the group in domain3 to current
        // value thus it should not be returned in our list

        Group group = new Group().setName("domain3:group.group1").setGroupMembers(Collections.emptyList());
        zmsImpl.putGroupReview(rsrcCtx1, "domain3", "group1", auditRef, false, group);

        // we should get back no entries

        reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertTrue(reviewObjects.getList().isEmpty());

        zmsImpl.deleteTopLevelDomain(ctx,"domain1", auditRef);
        zmsImpl.deleteTopLevelDomain(ctx,"domain2", auditRef);
        zmsImpl.deleteTopLevelDomain(ctx,"domain3", auditRef);

        System.clearProperty(ZMSConsts.ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_UPDATED_OBJECT);
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

        // Create group1 in domain1 with members and principal
        Group group = zmsTestInitializer.createGroupObject("domain1", "group1", groupMembers);
        zmsImpl.putGroup(ctx, "domain1", "group1", auditRef, false, group);

        // Create group2 in domain1 with members and principal
        group = zmsTestInitializer.createGroupObject("domain1", "group2", groupMembers);
        zmsImpl.putGroup(ctx, "domain1", "group2", auditRef, false, group);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.test1"));
        groupMembers.add(new GroupMember().setMemberName("user.test2"));

        // Create group1 in domain2 with members but without the principal
        group = zmsTestInitializer.createGroupObject("domain2", "group1", groupMembers);
        zmsImpl.putGroup(ctx, "domain2", "group1", auditRef, false, group);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName(principal));

        // Create group1 in domain3 only principal
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

    @Test
    public void testRoleWithLastReviewedDate() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "insert-role-last-reviewed-date";
        final String roleName = "role1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1",
                "testOrg", zmsTestInitializer.getAdminUser());
        dom1.getAdminUsers().add("user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, dom1);

        // now let's create a role with some settings including last reviewed date

        Timestamp now = Timestamp.fromCurrentTime();
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, Collections.emptyList());
        role1.setLastReviewedDate(now);
        role1.setMemberExpiryDays(10);
        role1.setCertExpiryMins(60);
        role1.setDescription("test role with last reviewed date");
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, role1);

        // now let's get our role object

        Role role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);

        assertEquals(role.getLastReviewedDate(), now);
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(role.getCertExpiryMins(), Integer.valueOf(60));
        assertEquals(role.getDescription(), "test role with last reviewed date");
        assertNull(role.getServiceReviewDays());

        // now let's update our role with the updated last review date and settings

        Timestamp now2 = Timestamp.fromMillis(now.millis() + 1);
        role1.setLastReviewedDate(now2);
        role1.setServiceReviewDays(50);

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, role1);

        // now let's get our role object again

        role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);

        assertEquals(role.getLastReviewedDate(), now2);
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(role.getCertExpiryMins(), Integer.valueOf(60));
        assertEquals(role.getServiceReviewDays(), Integer.valueOf(50));
        assertEquals(role.getDescription(), "test role with last reviewed date");

        // now update the role using meta api

        Timestamp now3 = Timestamp.fromMillis(now.millis() + 2);
        RoleMeta roleMeta = new RoleMeta().setMemberExpiryDays(20).setCertExpiryMins(120)
                        .setLastReviewedDate(now3);
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, roleMeta);

        // fetch the role again and verify the values

        role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);

        assertEquals(role.getLastReviewedDate(), now3);
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(20));
        assertEquals(role.getCertExpiryMins(), Integer.valueOf(120));
        assertEquals(role.getServiceReviewDays(), Integer.valueOf(50));
        assertEquals(role.getDescription(), "test role with last reviewed date");

        // by default, we allow the last reviewed date to be set to up to 3 days
        // in the past so let's try with 2 days and verify it works

        Timestamp now4 = Timestamp.fromMillis(now.millis() - TimeUnit.MILLISECONDS.convert(2, TimeUnit.DAYS));
        roleMeta.setLastReviewedDate(now4);
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, roleMeta);

        // fetch the role again and verify the values

        role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);

        assertEquals(role.getLastReviewedDate(), now4);
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(20));
        assertEquals(role.getCertExpiryMins(), Integer.valueOf(120));
        assertEquals(role.getServiceReviewDays(), Integer.valueOf(50));
        assertEquals(role.getDescription(), "test role with last reviewed date");

        // let's change the last reviewed date to only 1 day

        zmsImpl.dbService.maxLastReviewDateOffsetMillisForUpdatedObjects = TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS);

        // our update should still work since we're not going to change the value

        roleMeta.setMemberExpiryDays(25);
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, roleMeta);

        // fetch the role again and verify the values

        role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);

        assertEquals(role.getLastReviewedDate(), now4);
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(25));
        assertEquals(role.getCertExpiryMins(), Integer.valueOf(120));
        assertEquals(role.getServiceReviewDays(), Integer.valueOf(50));
        assertEquals(role.getDescription(), "test role with last reviewed date");

        // now let's set the value to 2 days in the past + 1 milli which should fail

        Timestamp now5 = Timestamp.fromMillis(now.millis() - TimeUnit.MILLISECONDS.convert(2, TimeUnit.DAYS) + 1);
        roleMeta.setLastReviewedDate(now5);
        try {
            zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, roleMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the past"));
        }

        // we're also not allowed to set the last reviewed date to the future

        Timestamp now6 = Timestamp.fromMillis(now.millis() + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS));
        roleMeta.setLastReviewedDate(now6);
        try {
            zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, roleMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the future"));
        }

        // modify only the description in a new role-meta object and verify
        // the last review date is not changed

        RoleMeta roleMeta1 = new RoleMeta().setDescription("test role with last reviewed date - updated");
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, roleMeta1);

        // fetch the role again and verify the values

        role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);

        assertEquals(role.getLastReviewedDate(), now4);
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(25));
        assertEquals(role.getCertExpiryMins(), Integer.valueOf(120));
        assertEquals(role.getServiceReviewDays(), Integer.valueOf(50));
        assertEquals(role.getDescription(), "test role with last reviewed date - updated");

        zmsImpl.dbService.maxLastReviewDateOffsetMillisForUpdatedObjects = TimeUnit.MILLISECONDS.convert(7, TimeUnit.DAYS);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef);
    }

    @Test
    public void testRoleWithLastReviewedDateNewObject() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "new-role-last-reviewed-date";
        final String roleName = "role1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1",
                "testOrg", zmsTestInitializer.getAdminUser());
        dom1.getAdminUsers().add("user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, dom1);

        // the default setting last reviewed date is allowed for new object
        // is set to 365 days. So we should not be able to set the last
        // reviewed date to more than 365 days in the past

        Timestamp moreThanYearAgo = Timestamp.fromMillis(
                System.currentTimeMillis() - TimeUnit.MILLISECONDS.convert(366, TimeUnit.DAYS));
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, Collections.emptyList());
        role1.setLastReviewedDate(moreThanYearAgo);
        role1.setMemberExpiryDays(10);
        role1.setCertExpiryMins(60);
        role1.setDescription("test role with last reviewed date");

        try {
            zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the past"));
        }

        // now let's update our role object to be less than one year and
        // the request must complete successfully

        Timestamp lessThanYearAgo = Timestamp.fromMillis(
                System.currentTimeMillis() - TimeUnit.MILLISECONDS.convert(364, TimeUnit.DAYS));
        role1.setLastReviewedDate(lessThanYearAgo);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, role1);

        Role role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);

        assertEquals(role.getLastReviewedDate(), lessThanYearAgo);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef);
    }

    @Test
    public void testGroupWithLastReviewedDate() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "insert-group-last-reviewed-date";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1",
                "testOrg", zmsTestInitializer.getAdminUser());
        dom1.getAdminUsers().add("user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, dom1);

        // now let's create a group with some settings including last reviewed date

        Timestamp now = Timestamp.fromCurrentTime();
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, null, null);
        group1.setLastReviewedDate(now);
        group1.setMemberExpiryDays(10);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, group1);

        // now let's get our group object

        Group group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);

        assertEquals(group.getLastReviewedDate(), now);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(10));
        assertNull(group.getServiceExpiryDays());

        // now let's update our group with the updated last review date and settings

        Timestamp now2 = Timestamp.fromMillis(now.millis() + 1);
        group1.setLastReviewedDate(now2);
        group1.setServiceExpiryDays(50);

        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, group1);

        // now let's get our group object again

        group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);

        assertEquals(group.getLastReviewedDate(), now2);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(group.getServiceExpiryDays(), Integer.valueOf(50));

        // now update the group using meta api

        Timestamp now3 = Timestamp.fromMillis(now.millis() + 2);
        GroupMeta groupMeta = new GroupMeta().setMemberExpiryDays(20).setServiceExpiryDays(120)
                .setLastReviewedDate(now3);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, groupMeta);

        // fetch the group again and verify the values

        group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);

        assertEquals(group.getLastReviewedDate(), now3);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(20));
        assertEquals(group.getServiceExpiryDays(), Integer.valueOf(120));

        // by default, we allow the last reviewed date to be set to up to 3 days
        // in the past so let's try with 2 days and verify it works

        Timestamp now4 = Timestamp.fromMillis(now.millis() - TimeUnit.MILLISECONDS.convert(2, TimeUnit.DAYS));
        groupMeta.setLastReviewedDate(now4);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, groupMeta);

        // fetch the group again and verify the values

        group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);

        assertEquals(group.getLastReviewedDate(), now4);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(20));
        assertEquals(group.getServiceExpiryDays(), Integer.valueOf(120));

        // let's change the last reviewed date to only 1 day

        zmsImpl.dbService.maxLastReviewDateOffsetMillisForUpdatedObjects = TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS);

        // our update should still work since we're not going to change the value

        groupMeta.setMemberExpiryDays(25);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, groupMeta);

        // fetch the group again and verify the values

        group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);

        assertEquals(group.getLastReviewedDate(), now4);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(25));
        assertEquals(group.getServiceExpiryDays(), Integer.valueOf(120));

        // now let's set the value to 2 days in the past + 1 milli which should fail

        Timestamp now5 = Timestamp.fromMillis(now.millis() - TimeUnit.MILLISECONDS.convert(2, TimeUnit.DAYS) + 1);
        groupMeta.setLastReviewedDate(now5);
        try {
            zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, groupMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the past"));
        }

        // we're also not allowed to set the last reviewed date to the future

        Timestamp now6 = Timestamp.fromMillis(now.millis() + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS));
        groupMeta.setLastReviewedDate(now6);
        try {
            zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, groupMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the future"));
        }

        // modify only the delete protection in a new group-meta object and verify
        // the last review date is not changed

        GroupMeta groupMeta1 = new GroupMeta().setDeleteProtection(true);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, groupMeta1);

        // fetch the group again and verify the values

        group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);

        assertEquals(group.getLastReviewedDate(), now4);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(25));
        assertEquals(group.getServiceExpiryDays(), Integer.valueOf(120));
        assertTrue(group.getDeleteProtection());

        zmsImpl.dbService.maxLastReviewDateOffsetMillisForUpdatedObjects = TimeUnit.MILLISECONDS.convert(7, TimeUnit.DAYS);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef);
    }

    @Test
    public void testGroupWithLastReviewedDateNewObject() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "new-group-last-reviewed-date";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1",
                "testOrg", zmsTestInitializer.getAdminUser());
        dom1.getAdminUsers().add("user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, dom1);

        // the default setting last reviewed date is allowed for new object
        // is set to 365 days. So we should not be able to set the last
        // reviewed date to more than 365 days in the past

        Timestamp moreThanYearAgo = Timestamp.fromMillis(
                System.currentTimeMillis() - TimeUnit.MILLISECONDS.convert(366, TimeUnit.DAYS));
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, null, null);
        group1.setLastReviewedDate(moreThanYearAgo);
        group1.setMemberExpiryDays(10);

        try {
            zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the past"));
        }

        // now let's update our role object to be less than one year and
        // the request must complete successfully

        Timestamp lessThanYearAgo = Timestamp.fromMillis(
                System.currentTimeMillis() - TimeUnit.MILLISECONDS.convert(364, TimeUnit.DAYS));
        group1.setLastReviewedDate(lessThanYearAgo);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, group1);

        // now let's get our group object

        Group group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef);
    }
}
