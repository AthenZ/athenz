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
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.mockito.Mockito.when;
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
        zmsImpl.putRole(ctx, "sys.auth", "review-role", auditRef, false, null, role);

        Policy policy = zmsTestInitializer.createPolicyObject("sys.auth", "review-policy", "review-role",
                "access", "sys.auth:meta.review.lookup", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "sys.auth", "review-policy", auditRef, false, null, policy);

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

        zmsImpl.deletePolicy(ctx, "sys.auth", "review-policy", auditRef, null);
        zmsImpl.deleteRole(ctx, "sys.auth", "review-role", auditRef, null);
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
        zmsImpl.putRoleMeta(rsrcCtx1, "domain1", "role1", auditRef, null, meta);

        meta = new RoleMeta().setMemberReviewDays(30).setLastReviewedDate(past15Days);
        zmsImpl.putRoleMeta(rsrcCtx1, "domain3", "role1", auditRef, null, meta);

        // we should get back no roles in domain1 and domain3

        reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertTrue(reviewObjects.getList().isEmpty());

        // now let's set the expiry to a value 15 days for domain3
        // and we should get back that entry in our list

        meta = new RoleMeta().setServiceExpiryDays(15);
        zmsImpl.putRoleMeta(rsrcCtx1, "domain3", "role1", auditRef, null, meta);

        reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 1);

        assertTrue(verifyReviewObjectExists(reviewObjects, "domain3", "role1"));

        // we're going to set last reviewed date on the group in domain3 to current
        // value thus it should not be returned in our list

        Role role = new Role().setName("domain3:role.role1").setRoleMembers(Collections.emptyList());
        zmsImpl.putRoleReview(rsrcCtx1, "domain3", "role1", auditRef, false, null, role);

        // we should get back no roles in domain1 and domain3

        reviewObjects = zmsImpl.getRolesForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertTrue(reviewObjects.getList().isEmpty());

        zmsImpl.deleteTopLevelDomain(ctx, "domain1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "domain2", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "domain3", auditRef, null);
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
        zmsImpl.putGroupMeta(rsrcCtx1, "domain1", "group1", auditRef, null, meta);

        meta = new GroupMeta().setServiceExpiryDays(30).setLastReviewedDate(past15Days);
        zmsImpl.putGroupMeta(rsrcCtx1, "domain3", "group1", auditRef, null, meta);

        // we should get back no groups in domain1 and domain3

        reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertTrue(reviewObjects.getList().isEmpty());

        // now let's set the expiry to a value 15 days for domain3
        // and we should get back that entry in our list

        meta = new GroupMeta().setServiceExpiryDays(15);
        zmsImpl.putGroupMeta(rsrcCtx1, "domain3", "group1", auditRef, null, meta);

        reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertEquals(reviewObjects.getList().size(), 1);

        assertTrue(verifyReviewObjectExists(reviewObjects, "domain3", "group1"));

        // we're going to set last reviewed date on the group in domain3 to current
        // value thus it should not be returned in our list

        Group group = new Group().setName("domain3:group.group1").setGroupMembers(Collections.emptyList());
        zmsImpl.putGroupReview(rsrcCtx1, "domain3", "group1", auditRef, false, null, group);

        // we should get back no entries

        reviewObjects = zmsImpl.getGroupsForReview(rsrcCtx1, principal.getFullName());
        assertNotNull(reviewObjects);
        assertNotNull(reviewObjects.getList());
        assertTrue(reviewObjects.getList().isEmpty());

        zmsImpl.deleteTopLevelDomain(ctx,"domain1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx,"domain2", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx,"domain3", auditRef, null);

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
        zmsImpl.putRole(ctx, "domain1", "Role1", auditRef, false, null, role);

        // Create role2 in domain1 with members and principal
        role = zmsTestInitializer.createRoleObject("domain1", "role2", null, roleMembers);
        zmsImpl.putRole(ctx, "domain1", "Role2", auditRef, false, null, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName("user.test2"));

        // Create role1 in domain2 with members but without the principal
        role = zmsTestInitializer.createRoleObject("domain2", "role1", null, roleMembers);
        zmsImpl.putRole(ctx, "domain2", "Role1", auditRef, false, null, role);

        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName(principal));

        // Create role1 in domain3 only principal
        role = zmsTestInitializer.createRoleObject("domain3", "role1", null, roleMembers);
        zmsImpl.putRole(ctx, "domain3", "role1", auditRef, false, null, role);
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
        zmsImpl.putGroup(ctx, "domain1", "group1", auditRef, false, null, group);

        // Create group2 in domain1 with members and principal
        group = zmsTestInitializer.createGroupObject("domain1", "group2", groupMembers);
        zmsImpl.putGroup(ctx, "domain1", "group2", auditRef, false, null, group);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.test1"));
        groupMembers.add(new GroupMember().setMemberName("user.test2"));

        // Create group1 in domain2 with members but without the principal
        group = zmsTestInitializer.createGroupObject("domain2", "group1", groupMembers);
        zmsImpl.putGroup(ctx, "domain2", "group1", auditRef, false, null, group);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName(principal));

        // Create group1 in domain3 only principal
        group = zmsTestInitializer.createGroupObject("domain3", "group1", groupMembers);
        zmsImpl.putGroup(ctx, "domain3", "group1", auditRef, false, null, group);
    }

    private void createDomain(final String domainName, final String principal) {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test " + domainName, "testOrg", zmsTestInitializer.getAdminUser());
        dom.getAdminUsers().add(principal);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);
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
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // now let's create a role with some settings including last reviewed date

        Timestamp now = Timestamp.fromCurrentTime();
        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, Collections.emptyList());
        role1.setLastReviewedDate(now);
        role1.setMemberExpiryDays(10);
        role1.setCertExpiryMins(60);
        role1.setDescription("test role with last reviewed date");
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

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

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

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
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, roleMeta);

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
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, roleMeta);

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
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, roleMeta);

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
            zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, roleMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the past"));
        }

        // we're also not allowed to set the last reviewed date to the future

        Timestamp now6 = Timestamp.fromMillis(now.millis() + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS));
        roleMeta.setLastReviewedDate(now6);
        try {
            zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, roleMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the future"));
        }

        // modify only the description in a new role-meta object and verify
        // the last review date is not changed

        RoleMeta roleMeta1 = new RoleMeta().setDescription("test role with last reviewed date - updated");
        zmsImpl.putRoleMeta(ctx, domainName, roleName, auditRef, null, roleMeta1);

        // fetch the role again and verify the values

        role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);

        assertEquals(role.getLastReviewedDate(), now4);
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(25));
        assertEquals(role.getCertExpiryMins(), Integer.valueOf(120));
        assertEquals(role.getServiceReviewDays(), Integer.valueOf(50));
        assertEquals(role.getDescription(), "test role with last reviewed date - updated");

        zmsImpl.dbService.maxLastReviewDateOffsetMillisForUpdatedObjects = TimeUnit.MILLISECONDS.convert(7, TimeUnit.DAYS);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
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
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

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
            zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);
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
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        Role role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);

        assertEquals(role.getLastReviewedDate(), lessThanYearAgo);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
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
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // now let's create a group with some settings including last reviewed date

        Timestamp now = Timestamp.fromCurrentTime();
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, null, null);
        group1.setLastReviewedDate(now);
        group1.setMemberExpiryDays(10);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group1);

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

        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group1);

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
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, groupMeta);

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
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, groupMeta);

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
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, groupMeta);

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
            zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, groupMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the past"));
        }

        // we're also not allowed to set the last reviewed date to the future

        Timestamp now6 = Timestamp.fromMillis(now.millis() + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS));
        groupMeta.setLastReviewedDate(now6);
        try {
            zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, groupMeta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("in the future"));
        }

        // modify only the delete protection in a new group-meta object and verify
        // the last review date is not changed

        GroupMeta groupMeta1 = new GroupMeta().setDeleteProtection(true);
        zmsImpl.putGroupMeta(ctx, domainName, groupName, auditRef, null, groupMeta1);

        // fetch the group again and verify the values

        group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);

        assertEquals(group.getLastReviewedDate(), now4);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(25));
        assertEquals(group.getServiceExpiryDays(), Integer.valueOf(120));
        assertTrue(group.getDeleteProtection());

        zmsImpl.dbService.maxLastReviewDateOffsetMillisForUpdatedObjects = TimeUnit.MILLISECONDS.convert(7, TimeUnit.DAYS);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
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
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // the default setting last reviewed date is allowed for new object
        // is set to 365 days. So we should not be able to set the last
        // reviewed date to more than 365 days in the past

        Timestamp moreThanYearAgo = Timestamp.fromMillis(
                System.currentTimeMillis() - TimeUnit.MILLISECONDS.convert(366, TimeUnit.DAYS));
        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, null, null);
        group1.setLastReviewedDate(moreThanYearAgo);
        group1.setMemberExpiryDays(10);

        try {
            zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group1);
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
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group1);

        // now let's get our group object

        Group group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutRoleReviewExpiration() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-review-dom";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.john", "user.jane");
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        Timestamp tenDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        Timestamp sixtyDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(60, TimeUnit.DAYS));

        Timestamp fortyFiveDaysLowerBoundExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(45, TimeUnit.DAYS));
        Timestamp fortyFiveDaysUpperBoundExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(45, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES));

        Timestamp fiftyDaysLowerBoundExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(50, TimeUnit.DAYS));
        Timestamp fiftyDaysUpperBoundExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(50, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES));

        Timestamp fiftyFiveDaysLowerBoundExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(55, TimeUnit.DAYS));
        Timestamp fiftyFiveDaysUpperBoundExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(55, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES));

        Membership mbr = zmsTestInitializer.generateMembership("role1", "user.doe", tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", "user.doe", auditRef, false, null, mbr);

        Group group1 = zmsTestInitializer.createGroupObject(domainName, "group1", null);
        zmsImpl.putGroup(ctx, domainName, "group1", auditRef, false, null, group1);

        mbr = zmsTestInitializer.generateMembership("role1", domainName + ":group.group1", tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", domainName + ":group.group1", auditRef, false, null, mbr);

        mbr = zmsTestInitializer.generateMembership("role1", "sys.auth.zms", tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", "sys.auth.zms", auditRef, false, null, mbr);

        RoleMeta rm = ZMSTestUtils.createRoleMetaObject(true);
        rm.setMemberExpiryDays(45);
        rm.setServiceExpiryDays(50);
        rm.setGroupExpiryDays(55);
        zmsImpl.putRoleMeta(ctx, domainName, "role1", auditRef, null, rm);

        Role inputRole = new Role().setName("role1");
        List<RoleMember> inputMembers = new ArrayList<>();
        inputRole.setRoleMembers(inputMembers);
        inputMembers.add(new RoleMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new RoleMember().setMemberName("user.doe").setActive(true)
                .setExpiration(sixtyDaysExpiry));
        inputMembers.add(new RoleMember().setMemberName(domainName + ":group.group1").setActive(true)
                .setExpiration(sixtyDaysExpiry));
        inputMembers.add(new RoleMember().setMemberName("sys.auth.zms").setActive(true)
                .setExpiration(sixtyDaysExpiry));
        zmsImpl.putRoleReview(ctx, domainName, "role1", auditRef, false, null, inputRole);

        Role resRole1 = zmsImpl.getRole(ctx, domainName, "role1", false, false, false);

        int userChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.jane":
                case "user.doe":
                    userChecked += 1;
                    assertTrue(roleMember.getExpiration().toDate().after(fortyFiveDaysLowerBoundExpiry.toDate()) && roleMember.getExpiration().toDate().before(fortyFiveDaysUpperBoundExpiry.toDate()));
                    assertTrue(roleMember.getApproved());
                    break;
                case "sys.auth.zms":
                    userChecked += 1;
                    assertTrue(roleMember.getExpiration().toDate().after(fiftyDaysLowerBoundExpiry.toDate()) && roleMember.getExpiration().toDate().before(fiftyDaysUpperBoundExpiry.toDate()));
                    assertTrue(roleMember.getApproved());
                    break;
                case domainName + ":group.group1":
                    userChecked += 1;
                    assertTrue(roleMember.getExpiration().toDate().after(fiftyFiveDaysLowerBoundExpiry.toDate()) && roleMember.getExpiration().toDate().before(fiftyFiveDaysUpperBoundExpiry.toDate()));
                    assertTrue(roleMember.getApproved());
                    break;
            }
        }
        assertEquals(userChecked, 4);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutRoleReviewReviewReminder() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-review-reminder";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.john", "user.jane");
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        Timestamp tenDaysReminder = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        Timestamp sixtyDaysReminder = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(60, TimeUnit.DAYS));

        Timestamp fortyFiveDaysLowerBoundReminder = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(45, TimeUnit.DAYS));
        Timestamp fortyFiveDaysUpperBoundReminder = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(45, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES));

        Timestamp fiftyDaysLowerBoundReminder = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(50, TimeUnit.DAYS));
        Timestamp fiftyDaysUpperBoundReminder = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(50, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES));

        Timestamp fiftyFiveDaysLowerBoundReminder = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(55, TimeUnit.DAYS));
        Timestamp fiftyFiveDaysUpperBoundReminder = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(55, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES));

        Membership mbr = zmsTestInitializer.generateMembership("role1", "user.doe", tenDaysReminder);
        zmsImpl.putMembership(ctx, domainName, "role1", "user.doe", auditRef, false, null, mbr);

        Group group1 = zmsTestInitializer.createGroupObject(domainName, "group1", null);
        zmsImpl.putGroup(ctx, domainName, "group1", auditRef, false, null, group1);

        mbr = zmsTestInitializer.generateMembership("role1", domainName + ":group.group1", tenDaysReminder);
        zmsImpl.putMembership(ctx, domainName, "role1", domainName + ":group.group1", auditRef, false, null, mbr);

        mbr = zmsTestInitializer.generateMembership("role1", "sys.auth.zms", tenDaysReminder);
        zmsImpl.putMembership(ctx, domainName, "role1", "sys.auth.zms", auditRef, false, null, mbr);

        RoleMeta rm = ZMSTestUtils.createRoleMetaObject(true);
        rm.setMemberReviewDays(45);
        rm.setServiceReviewDays(50);
        rm.setGroupReviewDays(55);
        zmsImpl.putRoleMeta(ctx, domainName, "role1", auditRef, null, rm);

        Role inputRole = new Role().setName("role1");
        List<RoleMember> inputMembers = new ArrayList<>();
        inputRole.setRoleMembers(inputMembers);
        inputMembers.add(new RoleMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new RoleMember().setMemberName("user.doe").setActive(true)
                .setReviewReminder(sixtyDaysReminder));
        inputMembers.add(new RoleMember().setMemberName(domainName + ":group.group1").setActive(true)
                .setReviewReminder(sixtyDaysReminder));
        inputMembers.add(new RoleMember().setMemberName("sys.auth.zms").setActive(true)
                .setReviewReminder(sixtyDaysReminder));
        zmsImpl.putRoleReview(ctx, domainName, "role1", auditRef, false, null, inputRole);

        Role resRole1 = zmsImpl.getRole(ctx, domainName, "role1", false, false, false);

        int userChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.jane":
                case "user.doe":
                    userChecked += 1;
                    assertTrue(roleMember.getReviewReminder().toDate().after(fortyFiveDaysLowerBoundReminder.toDate()) && roleMember.getReviewReminder().toDate().before(fortyFiveDaysUpperBoundReminder.toDate()));
                    assertTrue(roleMember.getApproved());
                    break;
                case "sys.auth.zms":
                    userChecked += 1;
                    assertTrue(roleMember.getReviewReminder().toDate().after(fiftyDaysLowerBoundReminder.toDate()) && roleMember.getReviewReminder().toDate().before(fiftyDaysUpperBoundReminder.toDate()));
                    assertTrue(roleMember.getApproved());
                    break;
                case domainName + ":group.group1":
                    userChecked += 1;
                    assertTrue(roleMember.getReviewReminder().toDate().after(fiftyFiveDaysLowerBoundReminder.toDate()) && roleMember.getReviewReminder().toDate().before(fiftyFiveDaysUpperBoundReminder.toDate()));
                    assertTrue(roleMember.getApproved());
                    break;
            }
        }
        assertEquals(userChecked, 4);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutRoleReviewNoChanges() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-review-no-changes";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.john", "user.jane");
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        Timestamp tenDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        Timestamp twentyDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(20, TimeUnit.DAYS));

        Membership mbr = zmsTestInitializer.generateMembership("role1", "user.doe", tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", "user.doe", auditRef, false, null, mbr);

        mbr = zmsTestInitializer.generateMembership("role1", "user.user1", null);
        mbr.setReviewReminder(tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", "user.user1", auditRef, false, null, mbr);

        mbr = zmsTestInitializer.generateMembership("role1", "user.user2", null);
        mbr.setReviewReminder(tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", "user.user2", auditRef, false, null, mbr);

        mbr = zmsTestInitializer.generateMembership("role1", "sys.auth.zms", tenDaysExpiry);
        mbr.setReviewReminder(tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", "sys.auth.zms", auditRef, false, null, mbr);

        Group group1 = zmsTestInitializer.createGroupObject(domainName, "group1", null);
        zmsImpl.putGroup(ctx, domainName, "group1", auditRef, false, null, group1);

        mbr = zmsTestInitializer.generateMembership("role1", domainName + ":group.group1", tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", domainName + ":group.group1", auditRef, false, null, mbr);

        Role inputRole = new Role().setName("role1");
        List<RoleMember> inputMembers = new ArrayList<>();
        inputRole.setRoleMembers(inputMembers);
        inputMembers.add(new RoleMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new RoleMember().setMemberName("user.doe").setActive(true)
                .setExpiration(twentyDaysExpiry));
        inputMembers.add(new RoleMember().setMemberName("user.jane").setActive(true)
                .setExpiration(tenDaysExpiry));
        inputMembers.add(new RoleMember().setMemberName("user.user1").setActive(true)
                .setReviewReminder(twentyDaysExpiry));
        inputMembers.add(new RoleMember().setMemberName("user.user2").setActive(true));
        inputMembers.add(new RoleMember().setMemberName("sys.auth.zms").setActive(true)
                .setReviewReminder(twentyDaysExpiry));
        inputMembers.add(new RoleMember().setMemberName(domainName + ":group.group1").setActive(true)
                .setReviewReminder(twentyDaysExpiry));

        zmsImpl.putRoleReview(ctx, domainName, "role1", auditRef, false, null, inputRole);

        Role resRole1 = zmsImpl.getRole(ctx, domainName, "role1", false, false, false);

        // john should be deleted and all others should stay as before - no changes

        int userChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            switch (roleMember.getMemberName()) {
                case "user.jane":
                    assertTrue(roleMember.getApproved());
                    assertNull(roleMember.getExpiration());
                    assertNull(roleMember.getReviewReminder());
                    userChecked += 1;
                    break;
                case "user.doe":
                case domainName + ":group.group1":
                    assertTrue(roleMember.getApproved());
                    assertEquals(roleMember.getExpiration(), tenDaysExpiry);
                    assertNull(roleMember.getReviewReminder());
                    userChecked += 1;
                    break;
                case "user.user1":
                case "user.user2":
                    assertTrue(roleMember.getApproved());
                    assertEquals(roleMember.getReviewReminder(), tenDaysExpiry);
                    assertNull(roleMember.getExpiration());
                    userChecked += 1;
                    break;
                case "sys.auth.zms":
                    assertTrue(roleMember.getApproved());
                    assertEquals(roleMember.getReviewReminder(), tenDaysExpiry);
                    assertEquals(roleMember.getExpiration(), tenDaysExpiry);
                    userChecked += 1;
                    break;
                case "user.john":
                    fail();
                    break;
            }
        }
        assertEquals(userChecked, 6);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutRoleReviewError() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-review-error";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.john", "user.jane");
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        Timestamp tenDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        Timestamp sixtyDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(60, TimeUnit.DAYS));

        Membership mbr = zmsTestInitializer.generateMembership("role1", "user.doe", tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", "user.doe", auditRef, false, null, mbr);

        RoleMeta rm = ZMSTestUtils.createRoleMetaObject(true);
        rm.setMemberExpiryDays(45);
        zmsImpl.putRoleMeta(ctx, domainName, "role1", auditRef, null, rm);

        Role inputRole = new Role().setName("role2");
        List<RoleMember> inputMembers = new ArrayList<>();
        inputRole.setRoleMembers(inputMembers);
        inputMembers.add(new RoleMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new RoleMember().setMemberName("user.doe").setActive(true).setExpiration(sixtyDaysExpiry));

        try {
            zmsImpl.putRoleReview(ctx, domainName, "role1", auditRef, false, null, inputRole);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 400);
        }

        inputRole.setName("role1");
        try {
            zmsImpl.putRoleReview(ctx, "role-review-dom1", "role1", auditRef, false, null, inputRole);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutRoleReviewAuditEnabled() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "role-review-audit-enabled";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.john", "user.jane");
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        Timestamp tenDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        Timestamp sixtyDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(60, TimeUnit.DAYS));
        Timestamp fortyFiveDaysLowerBoundExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(45, TimeUnit.DAYS));

        Membership mbr = zmsTestInitializer.generateMembership("role1", "user.doe", tenDaysExpiry);
        zmsImpl.putMembership(ctx, domainName, "role1", "user.doe", auditRef, false, null, mbr);

        RoleMeta rm = ZMSTestUtils.createRoleMetaObject(true);
        rm.setMemberExpiryDays(45);
        zmsImpl.putRoleMeta(ctx, domainName, "role1", auditRef, null, rm);

        DomainMeta meta = zmsTestInitializer.createDomainMetaObject("Domain Meta for Role review test", "NewOrg",
                true, true, "12345", 1001);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "auditenabled", auditRef, meta);

        RoleSystemMeta rsm = ZMSTestUtils.createRoleSystemMetaObject(true);
        zmsImpl.putRoleSystemMeta(ctx, domainName, "role1", "auditenabled", auditRef, rsm);

        Role inputRole = new Role().setName("role1");
        List<RoleMember> inputMembers = new ArrayList<>();
        inputRole.setRoleMembers(inputMembers);
        inputMembers.add(new RoleMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new RoleMember().setMemberName("user.doe").setActive(true).setExpiration(sixtyDaysExpiry));
        zmsImpl.putRoleReview(ctx, domainName, "role1", auditRef, false, null, inputRole);

        Role resRole1 = zmsImpl.getRole(ctx, domainName, "role1", false, false, true);

        Timestamp fortyFiveDaysUpperBoundExpiry = Timestamp.fromMillis(System.currentTimeMillis() +
                TimeUnit.MILLISECONDS.convert(45, TimeUnit.DAYS) + TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES));

        int userChecked = 0;
        for (RoleMember roleMember : resRole1.getRoleMembers()) {
            if (roleMember.getMemberName().equals("user.jane")) {
                userChecked += 1;
                assertTrue(roleMember.getExpiration().toDate().after(fortyFiveDaysLowerBoundExpiry.toDate())
                        && roleMember.getExpiration().toDate().before(fortyFiveDaysUpperBoundExpiry.toDate()));
                assertTrue(roleMember.getApproved());
            }

            // 2 records for user.doe - one approved before making the domain auditEnabled with
            //expiry date = now + 10 and another pending as part of putRoleReview with expiry date = now + 45

            if (roleMember.getMemberName().equals("user.doe")) {
                userChecked += 1;
                if (roleMember.getApproved() == Boolean.TRUE) {
                    assertEquals(roleMember.getExpiration(), tenDaysExpiry);
                } else {
                    assertTrue(roleMember.getExpiration().toDate().after(fortyFiveDaysLowerBoundExpiry.toDate())
                            && roleMember.getExpiration().toDate().before(fortyFiveDaysUpperBoundExpiry.toDate()));
                }

            }
        }
        assertEquals(userChecked, 3);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutRoleReviewDeletedPrincipal() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        DynamicConfigBoolean origValidateServiceRoleMembersBool = zmsImpl.validateServiceRoleMembers;
        DynamicConfigBoolean validateServiceRoleMembersBool = Mockito.mock(DynamicConfigBoolean.class);
        when(validateServiceRoleMembersBool.get()).thenReturn(true);
        zmsImpl.validateServiceRoleMembers = validateServiceRoleMembersBool;

        final String domainName = "role-review-dom-del-principal";
        final String roleName = "role1";
        final String serviceName = "svc1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName, serviceName,
                "http://localhost", null, null, null, "host1");
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null, "user.john", service.getName());
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        // now delete the service

        zmsImpl.deleteServiceIdentity(ctx, domainName, serviceName, auditRef, null);

        // reivew the role which should fail since the service is no longer valid

        Role inputRole = new Role().setName(roleName);
        List<RoleMember> inputMembers = new ArrayList<>();
        inputRole.setRoleMembers(inputMembers);
        inputMembers.add(new RoleMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new RoleMember().setMemberName(service.getName()).setActive(true));

        try {
            zmsImpl.putRoleReview(ctx, domainName, roleName, auditRef, false, null, inputRole);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal " + service.getName() + " is not a valid service"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.validateServiceRoleMembers = origValidateServiceRoleMembersBool;
    }

    @Test
    public void testPutGroupReview() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-review-dom";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, "user.john", "user.jane");
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        Group inputGroup = new Group().setName(groupName);
        List<GroupMember> inputMembers = new ArrayList<>();
        inputGroup.setGroupMembers(inputMembers);
        inputMembers.add(new GroupMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new GroupMember().setMemberName("user.jane").setActive(true));
        zmsImpl.putGroupReview(ctx, domainName, groupName, auditRef, false, null, inputGroup);

        Group resGroup = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertEquals(resGroup.getGroupMembers().size(), 1);
        assertEquals(resGroup.getGroupMembers().get(0).getMemberName(), "user.jane");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutGroupReviewNoChanges() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-review-no-changes";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group group1 = zmsTestInitializer.createGroupObject(domainName, "group1", "user.john", "user.jane");
        zmsImpl.putGroup(ctx, domainName, "group1", auditRef, false, null, group1);

        Timestamp tenDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS));
        Timestamp twentyDaysExpiry = Timestamp.fromMillis(System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(20, TimeUnit.DAYS));

        GroupMembership mbr = zmsTestInitializer.generateGroupMembership("group1", "user.doe", tenDaysExpiry);
        zmsImpl.putGroupMembership(ctx, domainName, "group1", "user.doe", auditRef, false, null, mbr);

        mbr = zmsTestInitializer.generateGroupMembership("group1", "sys.auth.zms", tenDaysExpiry);
        zmsImpl.putGroupMembership(ctx, domainName, "group1", "sys.auth.zms", auditRef, false, null, mbr);

        Group inputGroup = new Group().setName("group1");
        List<GroupMember> inputMembers = new ArrayList<>();
        inputGroup.setGroupMembers(inputMembers);
        inputMembers.add(new GroupMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new GroupMember().setMemberName("user.doe").setActive(true)
                .setExpiration(twentyDaysExpiry));
        inputMembers.add(new GroupMember().setMemberName("user.jane").setActive(true)
                .setExpiration(tenDaysExpiry));
        inputMembers.add(new GroupMember().setMemberName("sys.auth.zms").setActive(true)
                .setExpiration(twentyDaysExpiry));

        zmsImpl.putGroupReview(ctx, domainName, "group1", auditRef, false, null, inputGroup);

        Group resGroup1 = zmsImpl.getGroup(ctx, domainName, "group1", false, false);

        // john should be deleted and all others should stay as before - no changes

        int userChecked = 0;
        for (GroupMember groupMember : resGroup1.getGroupMembers()) {
            switch (groupMember.getMemberName()) {
                case "user.jane":
                    assertTrue(groupMember.getApproved());
                    assertNull(groupMember.getExpiration());
                    userChecked += 1;
                    break;
                case "user.doe":
                case "sys.auth.zms":
                    assertTrue(groupMember.getApproved());
                    assertEquals(groupMember.getExpiration(), tenDaysExpiry);
                    userChecked += 1;
                    break;
                case "user.john":
                    fail();
                    break;
            }
        }
        assertEquals(userChecked, 3);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutGroupReviewError() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-review-dom-err";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, "user.john", "user.jane");
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        Group inputGroup = new Group().setName(groupName);
        List<GroupMember> inputMembers = new ArrayList<>();
        inputGroup.setGroupMembers(inputMembers);
        inputMembers.add(new GroupMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new GroupMember().setMemberName("user.joe").setActive(true));
        zmsImpl.putGroupReview(ctx, domainName, groupName, auditRef, false, null, inputGroup);

        // This operation will be no-op as the changes were already implemented.
        zmsImpl.putGroupReview(ctx, domainName, groupName, auditRef, false, null, inputGroup);

        inputGroup.setName("group2");
        try {
            zmsImpl.putGroupReview(ctx, domainName, groupName, auditRef, false, null, inputGroup);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.BAD_REQUEST);
        }

        inputGroup.setName(groupName);
        try {
            zmsImpl.putGroupReview(ctx, "invalid-domain", groupName, auditRef, false, null, inputGroup);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.NOT_FOUND);
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutGroupReviewDeletedPrincipal() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "group-review-dom-del-principal";
        final String groupName = "group1";
        final String serviceName = "svc1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Role review Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName, serviceName,
                "http://localhost", null, null, null, "host1");
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, "user.john", service.getName());
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        // now delete the service

        zmsImpl.deleteServiceIdentity(ctx, domainName, serviceName, auditRef, null);

        // reivew the group which should fail since the service is no longer valid

        Group inputGroup = new Group().setName(groupName);
        List<GroupMember> inputMembers = new ArrayList<>();
        inputGroup.setGroupMembers(inputMembers);
        inputMembers.add(new GroupMember().setMemberName("user.john").setActive(false));
        inputMembers.add(new GroupMember().setMemberName(service.getName()).setActive(true));

        try {
            zmsImpl.putGroupReview(ctx, domainName, groupName, auditRef, false, null, inputGroup);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal " + service.getName() + " is not a valid service"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
