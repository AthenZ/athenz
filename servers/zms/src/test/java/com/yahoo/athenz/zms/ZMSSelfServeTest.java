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
import java.util.List;

import static org.testng.Assert.*;

public class ZMSSelfServeTest {

    // unique marker embedded in the objects created by this test so that our
    // cross-domain search assertions are not affected by data created elsewhere

    private static final String MARKER = "zmsselfservemarker";

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

    private Principal getPrincipal(final String domainName, final String userName) {
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        final String unsignedCreds = "v=U1;d=" + domainName + ";n=" + userName;
        return SimplePrincipal.create(domainName, userName, unsignedCreds + ";s=signature", 0, principalAuthority);
    }

    private void createDomain(final String domainName) {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test " + domainName, "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);
    }

    private boolean containsObject(SelfServeObjects objects, final String domainName, final String name) {
        for (SelfServeObject object : objects.getList()) {
            if (object.getDomainName().equals(domainName) && object.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }

    private SelfServeObject findObject(SelfServeObjects objects, final String domainName, final String name) {
        for (SelfServeObject object : objects.getList()) {
            if (object.getDomainName().equals(domainName) && object.getName().equals(name)) {
                return object;
            }
        }
        return null;
    }

    @Test
    public void testGetSelfServeRoles() {

        final String domainName = "self-serve-role-dom";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        createDomain(domainName);

        Principal principal = getPrincipal("user", "john");
        ResourceContext rsrcCtx = zmsTestInitializer.createResourceContext(principal);

        // a self-service role whose description contains the marker with two active
        // members (review is intentionally left disabled so the members are active
        // and therefore counted in the member_count column)

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName("user.test2"));
        Role descRole = zmsTestInitializer.createRoleObject(domainName, "sredb-readers", null, roleMembers);
        descRole.setSelfServe(true);
        descRole.setDescription("grants " + MARKER + " read access");
        descRole.setSelfRenew(true);
        descRole.setSelfRenewMins(4320);
        descRole.setMaxMembers(500);
        descRole.setMemberExpiryDays(90);
        zmsImpl.putRole(ctx, domainName, "sredb-readers", auditRef, false, null, descRole);

        // a self-service, review-enabled role whose name contains the marker (no members)

        Role nameRole = zmsTestInitializer.createRoleObject(domainName, MARKER + "-role", null, null);
        nameRole.setSelfServe(true);
        nameRole.setReviewEnabled(true);
        nameRole.setDescription("plain description");
        zmsImpl.putRole(ctx, domainName, MARKER + "-role", auditRef, false, null, nameRole);

        // a role that is NOT self-service but whose description contains the marker;
        // it must never be returned by the self-service search

        Role nonSelfServeRole = zmsTestInitializer.createRoleObject(domainName, "restricted", null, null);
        nonSelfServeRole.setDescription("internal " + MARKER + " only");
        zmsImpl.putRole(ctx, domainName, "restricted", auditRef, false, null, nonSelfServeRole);

        SelfServeObjects selfServeObjects = zmsImpl.getSelfServeRoles(rsrcCtx, MARKER, false);
        assertNotNull(selfServeObjects);
        assertNotNull(selfServeObjects.getList());

        // both self-service roles (name and description match) are returned; the
        // non self-service role is excluded even though its description matches

        assertTrue(containsObject(selfServeObjects, domainName, "sredb-readers"));
        assertTrue(containsObject(selfServeObjects, domainName, MARKER + "-role"));
        assertFalse(containsObject(selfServeObjects, domainName, "restricted"));

        // verify the returned metadata (including member count) is populated

        SelfServeObject descObject = findObject(selfServeObjects, domainName, "sredb-readers");
        assertNotNull(descObject);
        assertEquals(descObject.getDescription(), "grants " + MARKER + " read access");
        assertEquals(descObject.getSelfRenew(), Boolean.TRUE);
        assertEquals(descObject.getSelfRenewMins(), Integer.valueOf(4320));
        assertEquals(descObject.getReviewEnabled(), Boolean.FALSE);
        assertEquals(descObject.getMaxMembers(), Integer.valueOf(500));
        assertEquals(descObject.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(descObject.getMemberCount(), Integer.valueOf(2));
        assertNotNull(descObject.getCreated());

        // the review-enabled, memberless role reports review enabled and a zero count

        SelfServeObject nameObject = findObject(selfServeObjects, domainName, MARKER + "-role");
        assertNotNull(nameObject);
        assertEquals(nameObject.getReviewEnabled(), Boolean.TRUE);
        assertEquals(nameObject.getMemberCount(), Integer.valueOf(0));

        // the match is case-insensitive

        SelfServeObjects mixedCase = zmsImpl.getSelfServeRoles(rsrcCtx, "  ZmsSelfServeMarker  ", false);
        assertTrue(containsObject(mixedCase, domainName, "sredb-readers"));
        assertTrue(containsObject(mixedCase, domainName, MARKER + "-role"));

        // a substring with no matches returns an empty list

        SelfServeObjects noMatch = zmsImpl.getSelfServeRoles(rsrcCtx, "no-such-substring-value", false);
        assertNotNull(noMatch);
        assertTrue(noMatch.getList().isEmpty());

        // an empty/null substring returns all self-service roles (still excluding
        // the non self-service role)

        SelfServeObjects allRoles = zmsImpl.getSelfServeRoles(rsrcCtx, null, false);
        assertTrue(containsObject(allRoles, domainName, "sredb-readers"));
        assertTrue(containsObject(allRoles, domainName, MARKER + "-role"));
        assertFalse(containsObject(allRoles, domainName, "restricted"));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetSelfServeGroups() {

        final String domainName = "self-serve-group-dom";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        createDomain(domainName);

        Principal principal = getPrincipal("user", "john");
        ResourceContext rsrcCtx = zmsTestInitializer.createResourceContext(principal);

        // a self-service group whose name contains the marker with two active members
        // (review left disabled so the members are active and counted)

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.test1"));
        groupMembers.add(new GroupMember().setMemberName("user.test2"));
        Group selfServeGroup = zmsTestInitializer.createGroupObject(domainName, MARKER + "-team", groupMembers);
        selfServeGroup.setSelfServe(true);
        selfServeGroup.setSelfRenew(true);
        selfServeGroup.setSelfRenewMins(1440);
        selfServeGroup.setMaxMembers(50);
        selfServeGroup.setMemberExpiryDays(30);
        zmsImpl.putGroup(ctx, domainName, MARKER + "-team", auditRef, false, null, selfServeGroup);

        // a group that is NOT self-service - it must never be returned

        Group nonSelfServeGroup = zmsTestInitializer.createGroupObject(domainName, MARKER + "-private", null);
        zmsImpl.putGroup(ctx, domainName, MARKER + "-private", auditRef, false, null, nonSelfServeGroup);

        SelfServeObjects selfServeObjects = zmsImpl.getSelfServeGroups(rsrcCtx, MARKER.toUpperCase(), false);
        assertNotNull(selfServeObjects);
        assertNotNull(selfServeObjects.getList());

        assertTrue(containsObject(selfServeObjects, domainName, MARKER + "-team"));
        assertFalse(containsObject(selfServeObjects, domainName, MARKER + "-private"));

        SelfServeObject groupObject = findObject(selfServeObjects, domainName, MARKER + "-team");
        assertNotNull(groupObject);
        // groups have no description column, so the field is not populated
        assertNull(groupObject.getDescription());
        assertEquals(groupObject.getSelfRenew(), Boolean.TRUE);
        assertEquals(groupObject.getSelfRenewMins(), Integer.valueOf(1440));
        assertEquals(groupObject.getReviewEnabled(), Boolean.FALSE);
        assertEquals(groupObject.getMaxMembers(), Integer.valueOf(50));
        assertEquals(groupObject.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(groupObject.getMemberCount(), Integer.valueOf(2));
        assertNotNull(groupObject.getCreated());

        // a substring with no matches returns an empty list

        SelfServeObjects noMatch = zmsImpl.getSelfServeGroups(rsrcCtx, "no-such-substring-value", false);
        assertNotNull(noMatch);
        assertTrue(noMatch.getList().isEmpty());

        // an empty/null substring returns all self-service groups

        SelfServeObjects allGroups = zmsImpl.getSelfServeGroups(rsrcCtx, "", false);
        assertTrue(containsObject(allGroups, domainName, MARKER + "-team"));
        assertFalse(containsObject(allGroups, domainName, MARKER + "-private"));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetSelfServeEffectiveMemberExpiry() {

        final String domainName = "self-serve-expiry-dom";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        createDomain(domainName);

        Principal principal = getPrincipal("user", "john");
        ResourceContext rsrcCtx = zmsTestInitializer.createResourceContext(principal);

        // create the self-service roles/groups first (before the domain cap is set)
        // so their own member_expiry_days values are stored as specified

        Role highRole = zmsTestInitializer.createRoleObject(domainName, MARKER + "-high", null, null);
        highRole.setSelfServe(true);
        highRole.setMemberExpiryDays(90);
        zmsImpl.putRole(ctx, domainName, MARKER + "-high", auditRef, false, null, highRole);

        Role lowRole = zmsTestInitializer.createRoleObject(domainName, MARKER + "-low", null, null);
        lowRole.setSelfServe(true);
        lowRole.setMemberExpiryDays(10);
        zmsImpl.putRole(ctx, domainName, MARKER + "-low", auditRef, false, null, lowRole);

        Role noneRole = zmsTestInitializer.createRoleObject(domainName, MARKER + "-none", null, null);
        noneRole.setSelfServe(true);
        zmsImpl.putRole(ctx, domainName, MARKER + "-none", auditRef, false, null, noneRole);

        Group highGroup = zmsTestInitializer.createGroupObject(domainName, MARKER + "-hgroup", null);
        highGroup.setSelfServe(true);
        highGroup.setMemberExpiryDays(90);
        zmsImpl.putGroup(ctx, domainName, MARKER + "-hgroup", auditRef, false, null, highGroup);

        Group lowGroup = zmsTestInitializer.createGroupObject(domainName, MARKER + "-lgroup", null);
        lowGroup.setSelfServe(true);
        lowGroup.setMemberExpiryDays(10);
        zmsImpl.putGroup(ctx, domainName, MARKER + "-lgroup", auditRef, false, null, lowGroup);

        // now cap the whole domain at 30 days

        DomainMeta meta = new DomainMeta().setMemberExpiryDays(30);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);

        // the returned member expiry is the lowest of the domain and role/group
        // setting (0 on either side means "no limit" and is ignored)

        SelfServeObjects roles = zmsImpl.getSelfServeRoles(rsrcCtx, MARKER, false);
        assertEquals(findObject(roles, domainName, MARKER + "-high").getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(findObject(roles, domainName, MARKER + "-low").getMemberExpiryDays(), Integer.valueOf(10));
        assertEquals(findObject(roles, domainName, MARKER + "-none").getMemberExpiryDays(), Integer.valueOf(30));

        SelfServeObjects groups = zmsImpl.getSelfServeGroups(rsrcCtx, MARKER, false);
        assertEquals(findObject(groups, domainName, MARKER + "-hgroup").getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(findObject(groups, domainName, MARKER + "-lgroup").getMemberExpiryDays(), Integer.valueOf(10));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetSelfServeMembershipOverlay() {

        final String domainName = "self-serve-overlay-dom";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        createDomain(domainName);

        // the overlay is computed for the calling principal - user.john

        Principal principal = getPrincipal("user", "john");
        ResourceContext rsrcCtx = zmsTestInitializer.createResourceContext(principal);

        // a self-service role where john is a direct, active member with an expiration

        com.yahoo.rdl.Timestamp expiry = com.yahoo.rdl.Timestamp.fromMillis(
                System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000);
        List<RoleMember> directMembers = new ArrayList<>();
        directMembers.add(new RoleMember().setMemberName("user.john").setExpiration(expiry));
        Role directRole = zmsTestInitializer.createRoleObject(domainName, MARKER + "-direct", null, directMembers);
        directRole.setSelfServe(true);
        zmsImpl.putRole(ctx, domainName, MARKER + "-direct", auditRef, false, null, directRole);

        // a self-service role john has no relationship with

        Role otherRole = zmsTestInitializer.createRoleObject(domainName, MARKER + "-other", null, null);
        otherRole.setSelfServe(true);
        zmsImpl.putRole(ctx, domainName, MARKER + "-other", auditRef, false, null, otherRole);

        // a group john belongs to, added as a member of a self-service role so that
        // john inherits that role through the group

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.john"));
        Group engGroup = zmsTestInitializer.createGroupObject(domainName, MARKER + "-enggroup", groupMembers);
        zmsImpl.putGroup(ctx, domainName, MARKER + "-enggroup", auditRef, false, null, engGroup);

        final String groupPrincipal = domainName + ":group." + MARKER + "-enggroup";
        List<RoleMember> inheritedMembers = new ArrayList<>();
        inheritedMembers.add(new RoleMember().setMemberName(groupPrincipal));
        Role inheritedRole = zmsTestInitializer.createRoleObject(domainName, MARKER + "-inherited", null, inheritedMembers);
        inheritedRole.setSelfServe(true);
        zmsImpl.putRole(ctx, domainName, MARKER + "-inherited", auditRef, false, null, inheritedRole);

        // full list carries the per-principal overlay

        SelfServeObjects roles = zmsImpl.getSelfServeRoles(rsrcCtx, MARKER, false);

        SelfServeObject direct = findObject(roles, domainName, MARKER + "-direct");
        assertNotNull(direct);
        assertEquals(direct.getMemberStatus(), "member");
        assertNotNull(direct.getExpiration());
        assertNull(direct.getInheritedFrom());

        SelfServeObject other = findObject(roles, domainName, MARKER + "-other");
        assertNotNull(other);
        assertEquals(other.getMemberStatus(), "none");
        assertNull(other.getInheritedFrom());

        SelfServeObject inherited = findObject(roles, domainName, MARKER + "-inherited");
        assertNotNull(inherited);
        assertEquals(inherited.getMemberStatus(), "member");
        assertEquals(inherited.getInheritedFrom(), groupPrincipal);

        // memberOnly filters out the role john has no relationship with

        SelfServeObjects mine = zmsImpl.getSelfServeRoles(rsrcCtx, MARKER, true);
        assertTrue(containsObject(mine, domainName, MARKER + "-direct"));
        assertTrue(containsObject(mine, domainName, MARKER + "-inherited"));
        assertFalse(containsObject(mine, domainName, MARKER + "-other"));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testNormalizeSelfServeSubstring() {
        assertNull(ZMSImpl.normalizeSelfServeSubstring(null));
        assertEquals(ZMSImpl.normalizeSelfServeSubstring("  MixedCase  "), "mixedcase");
        assertEquals(ZMSImpl.normalizeSelfServeSubstring(""), "");
    }
}
