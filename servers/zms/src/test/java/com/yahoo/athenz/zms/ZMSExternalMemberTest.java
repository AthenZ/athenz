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
import org.testng.annotations.*;

import java.util.List;

import static org.testng.Assert.*;

public class ZMSExternalMemberTest {

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
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void shutDown() {
        zmsTestInitializer.shutDown();
    }

    @Test
    public void testAccessCheckWithExternalMember() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-mbr-access-test";
        final String roleName = "readers";
        final String regularMember = "user.joe";
        final String externalMember = domainName + ":ext.partner-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        // configure the external member validator on the domain so
        // external members can be added to roles

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        // create a role with a regular user and an external member

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null,
                regularMember, null);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        Membership extMbr = zmsTestInitializer.generateMembership(roleName, externalMember);
        zmsImpl.putMembership(ctx, domainName, roleName, externalMember,
                auditRef, false, null, extMbr);

        // create a policy that grants READ access on the domain's resources
        // to members of the readers role

        Policy policy = zmsTestInitializer.createPolicyObject(domainName, "read-policy",
                roleName, "READ", domainName + ":data", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, domainName, "read-policy", auditRef, false, null, policy);

        // verify that the regular member has access

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal regularPrincipal = principalAuthority.authenticate(
                "v=U1;d=user;n=joe;s=signature", "10.11.12.13", "GET", null);
        ResourceContext regularCtx = zmsTestInitializer.createResourceContext(regularPrincipal);

        Access access = zmsImpl.getAccess(regularCtx, "READ", domainName + ":data", null, null);
        assertTrue(access.getGranted(), "Regular member should have READ access");

        // verify that the external member has access using checkPrincipal

        access = zmsImpl.getAccess(regularCtx, "READ", domainName + ":data", null, externalMember);
        assertTrue(access.getGranted(), "External member should have READ access");

        // remove the external member from the role

        zmsImpl.deleteMembership(ctx, domainName, roleName, externalMember, auditRef, null);

        // verify the external member no longer has access

        access = zmsImpl.getAccess(regularCtx, "READ", domainName + ":data", null, externalMember);
        assertFalse(access.getGranted(), "External member should no longer have READ access after removal");

        // verify that the regular member still has access

        access = zmsImpl.getAccess(regularCtx, "READ", domainName + ":data", null, null);
        assertTrue(access.getGranted(), "Regular member should still have READ access");


        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAccessCheckWithExternalMemberViaGroup() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-mbr-group-access";
        final String roleName = "readers";
        final String groupName = "partners";
        final String regularMember = "user.joe";
        final String externalMember = domainName + ":ext.partner-user";
        final String groupResourceName = domainName + ":group." + groupName;

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        // configure the external member validator on the domain

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        // create a group and add the external member to it

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName,
                null, null);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        GroupMembership gmbr = zmsTestInitializer.generateGroupMembership(groupName, externalMember);
        zmsImpl.putGroupMembership(ctx, domainName, groupName, externalMember,
                auditRef, false, null, gmbr);

        // create a role with a regular user and the group as members

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null,
                regularMember, groupResourceName);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        // create a policy that grants READ access to members of the readers role

        Policy policy = zmsTestInitializer.createPolicyObject(domainName, "read-policy",
                roleName, "READ", domainName + ":data", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, domainName, "read-policy", auditRef, false, null, policy);

        // verify that the regular member has access

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal regularPrincipal = principalAuthority.authenticate(
                "v=U1;d=user;n=joe;s=signature", "10.11.12.13", "GET", null);
        ResourceContext regularCtx = zmsTestInitializer.createResourceContext(regularPrincipal);

        Access access = zmsImpl.getAccess(regularCtx, "READ", domainName + ":data", null, null);
        assertTrue(access.getGranted(), "Regular member should have READ access");

        // verify that the external member has access through group membership

        access = zmsImpl.getAccess(regularCtx, "READ", domainName + ":data", null, externalMember);
        assertTrue(access.getGranted(),
                "External member should have READ access through group membership");

        // remove the external member from the group

        zmsImpl.deleteGroupMembership(ctx, domainName, groupName, externalMember, auditRef, null);

        // verify the external member no longer has access

        access = zmsImpl.getAccess(regularCtx, "READ", domainName + ":data", null, externalMember);
        assertFalse(access.getGranted(),
                "External member should no longer have READ access after removal from group");

        // verify that the regular member still has access

        access = zmsImpl.getAccess(regularCtx, "READ", domainName + ":data", null, null);
        assertTrue(access.getGranted(), "Regular member should still have READ access");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutMembershipExternalMemberValidator() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-mbr-role-validator";
        final String roleName = "role1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, "user.joe", "user.jane");
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        // step 1: try to add an external member without any validator configured.
        // the request should be rejected since no validator is available for the domain

        Membership mbr = zmsTestInitializer.generateMembership(roleName, domainName + ":ext.external-user");
        try {
            zmsImpl.putMembership(ctx, domainName, roleName, domainName + ":ext.external-user",
                    auditRef, false, null, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("External member validator for domain ext-mbr-role-validator is not available"));
        }

        // step 2: configure the domain with a valid external validator class and
        // refresh the validator manager so it picks up the new configuration

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl, ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getExternalMemberValidator(), "com.yahoo.athenz.zms.TestExternalMemberValidator");

        zmsImpl.externalMemberValidatorManager.refreshValidators();
        assertTrue(zmsImpl.externalMemberValidatorManager.getDomainNamesWithValidator().contains(domainName));

        // step 3: now add the external member again - should succeed since the
        // validator is configured and the member name does not contain "invalid"

        mbr = zmsTestInitializer.generateMembership(roleName, domainName + ":ext.external-user");
        zmsImpl.putMembership(ctx, domainName, roleName, domainName + ":ext.external-user",
                auditRef, false, null, mbr);

        Role role = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotNull(role);
        boolean extMemberFound = false;
        for (RoleMember member : role.getRoleMembers()) {
            if (member.getMemberName().equals(domainName + ":ext.external-user")) {
                extMemberFound = true;
                break;
            }
        }
        assertTrue(extMemberFound);

        // step 4: try to add an external member whose name contains "invalid"
        // which causes TestExternalMemberValidator.validateMember to return false

        mbr = zmsTestInitializer.generateMembership(roleName, domainName + ":ext.invalid-user");
        try {
            zmsImpl.putMembership(ctx, domainName, roleName, domainName + ":ext.invalid-user",
                    auditRef, false, null, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Member invalid-user is not valid according to the external member validator for domain ext-mbr-role-validator"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateExternalMemberValidMember() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-validate-valid";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.partner-user", "testCaller");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateExternalMemberWildcardAtEnd() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-validate-wc-end";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.partner*", "testCaller");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateExternalMemberWildcardOnly() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-validate-wc-only";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.*", "testCaller");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateExternalMemberWildcards() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-validate-wc-mid";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.part*ner", "testCaller");
        zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.*:partner-user", "testCaller");
        zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.*partner*", "testCaller");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateExternalMemberNoValidator() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-validate-no-val";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        try {
            zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.partner-user", "testCaller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("External member validator for domain "
                    + domainName + " is not available"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateExternalMemberInvalidMember() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-validate-inv-mbr";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        try {
            zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.invalid-user", "testCaller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("is not valid according to the external member validator for domain "
                    + domainName));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateExternalMemberInvalidMemberWithWildcard() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-validate-inv-wc";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        try {
            zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.invalid*", "testCaller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("is not valid according to the external member validator for domain "
                    + domainName));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutGroupMembershipExternalMemberValidator() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-mbr-group-validator";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, "user.joe", "user.jane");
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group1);

        // step 1: try to add an external member without any validator configured.
        // the request should be rejected since no validator is available for the domain

        GroupMembership gmbr = zmsTestInitializer.generateGroupMembership(groupName,
                domainName + ":ext.external-user");
        try {
            zmsImpl.putGroupMembership(ctx, domainName, groupName, domainName + ":ext.external-user",
                    auditRef, false, null, gmbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("External member validator for domain ext-mbr-group-validator is not available"));
        }

        // step 2: configure the domain with a valid external validator class and
        // refresh the validator manager so it picks up the new configuration

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl, ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getExternalMemberValidator(), "com.yahoo.athenz.zms.TestExternalMemberValidator");

        zmsImpl.externalMemberValidatorManager.refreshValidators();
        assertTrue(zmsImpl.externalMemberValidatorManager.getDomainNamesWithValidator().contains(domainName));

        // step 3: now add the external member again - should succeed since the
        // validator is configured and the member name does not contain "invalid"

        gmbr = zmsTestInitializer.generateGroupMembership(groupName, domainName + ":ext.external-user");
        zmsImpl.putGroupMembership(ctx, domainName, groupName, domainName + ":ext.external-user",
                auditRef, false, null, gmbr);

        Group group = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotNull(group);
        boolean extMemberFound = false;
        for (GroupMember member : group.getGroupMembers()) {
            if (member.getMemberName().equals(domainName + ":ext.external-user")) {
                extMemberFound = true;
                break;
            }
        }
        assertTrue(extMemberFound);

        // step 4: try to add an external member whose name contains "invalid"
        // which causes TestExternalMemberValidator.validateMember to return false

        gmbr = zmsTestInitializer.generateGroupMembership(groupName, domainName + ":ext.invalid-user");
        try {
            zmsImpl.putGroupMembership(ctx, domainName, groupName, domainName + ":ext.invalid-user",
                    auditRef, false, null, gmbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Member invalid-user is not valid according to the external member validator for domain ext-mbr-group-validator"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesWithExternalMember() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName1 = "ext-mbr-princ-roles1";
        final String domainName2 = "ext-mbr-princ-roles2";
        final String externalMember = domainName1 + ":ext.partner-user";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName1, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        // create two roles in domain1 with the external member

        Role role1 = zmsTestInitializer.createRoleObject(domainName1, "role1", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName1, "role1", auditRef, false, null, role1);

        Membership extMbr = zmsTestInitializer.generateMembership("role1", externalMember);
        zmsImpl.putMembership(ctx, domainName1, "role1", externalMember,
                auditRef, false, null, extMbr);

        Role role2 = zmsTestInitializer.createRoleObject(domainName1, "role2", null,
                "user.jane", null);
        zmsImpl.putRole(ctx, domainName1, "role2", auditRef, false, null, role2);

        extMbr = zmsTestInitializer.generateMembership("role2", externalMember);
        zmsImpl.putMembership(ctx, domainName1, "role2", externalMember,
                auditRef, false, null, extMbr);

        // create a role in domain2 without the external member

        Role role3 = zmsTestInitializer.createRoleObject(domainName2, "role1", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName2, "role1", auditRef, false, null, role3);

        // get all roles for the external member across all domains

        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, null, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberName(), externalMember);
        List<MemberRole> memberRoles = domainRoleMember.getMemberRoles();
        assertEquals(memberRoles.size(), 2);

        boolean foundRole1 = false;
        boolean foundRole2 = false;
        for (MemberRole memberRole : memberRoles) {
            assertEquals(memberRole.getDomainName(), domainName1);
            if ("role1".equals(memberRole.getRoleName())) {
                foundRole1 = true;
            } else if ("role2".equals(memberRole.getRoleName())) {
                foundRole2 = true;
            }
        }
        assertTrue(foundRole1);
        assertTrue(foundRole2);

        // get roles filtered by domain1 only

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, domainName1, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberName(), externalMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 2);

        // get roles filtered by domain2 - external member is not in any role there

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, domainName2, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberName(), externalMember);
        assertTrue(domainRoleMember.getMemberRoles().isEmpty());

        // remove the external member from role1 and verify updated results

        zmsImpl.deleteMembership(ctx, domainName1, "role1", externalMember, auditRef, null);

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, null, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 1);
        assertEquals(domainRoleMember.getMemberRoles().get(0).getRoleName(), "role2");

        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
    }

    @Test
    public void testGetPrincipalRolesWithExternalMemberDifferentDomains() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName1 = "ext-mbr-princ-roles1";
        final String domainName2 = "ext-mbr-princ-roles2";
        final String extDomainName = "ext-mbr-princ-roles";
        final String externalMember = extDomainName + ":ext.partner-user";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        TopLevelDomain extDom = zmsTestInitializer.createTopLevelDomainObject(extDomainName,
            "External Domain", "testOrg", zmsTestInitializer.getAdminUser(),
            ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, extDom);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, extDomainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        // create two roles in domain1 with the external member

        Role role1 = zmsTestInitializer.createRoleObject(domainName1, "role1", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName1, "role1", auditRef, false, null, role1);

        Membership extMbr = zmsTestInitializer.generateMembership("role1", externalMember);
        zmsImpl.putMembership(ctx, domainName1, "role1", externalMember,
                auditRef, false, null, extMbr);

        Role role2 = zmsTestInitializer.createRoleObject(domainName1, "role2", null,
                "user.jane", null);
        zmsImpl.putRole(ctx, domainName1, "role2", auditRef, false, null, role2);

        extMbr = zmsTestInitializer.generateMembership("role2", externalMember);
        zmsImpl.putMembership(ctx, domainName1, "role2", externalMember,
                auditRef, false, null, extMbr);

        // create a role in domain2 without the external member

        Role role3 = zmsTestInitializer.createRoleObject(domainName2, "role1", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName2, "role1", auditRef, false, null, role3);

        // get all roles for the external member across all domains

        DomainRoleMember domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, null, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberName(), externalMember);
        List<MemberRole> memberRoles = domainRoleMember.getMemberRoles();
        assertEquals(memberRoles.size(), 2);

        boolean foundRole1 = false;
        boolean foundRole2 = false;
        for (MemberRole memberRole : memberRoles) {
            assertEquals(memberRole.getDomainName(), domainName1);
            if ("role1".equals(memberRole.getRoleName())) {
                foundRole1 = true;
            } else if ("role2".equals(memberRole.getRoleName())) {
                foundRole2 = true;
            }
        }
        assertTrue(foundRole1);
        assertTrue(foundRole2);

        // get roles filtered by domain1 only

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, domainName1, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberName(), externalMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 2);

        // get roles filtered by domain2 - external member is not in any role there

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, domainName2, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberName(), externalMember);
        assertTrue(domainRoleMember.getMemberRoles().isEmpty());

        // remove the external member from role1 and verify updated results

        zmsImpl.deleteMembership(ctx, domainName1, "role1", externalMember, auditRef, null);

        domainRoleMember = zmsImpl.getPrincipalRoles(ctx, externalMember, null, null);
        assertNotNull(domainRoleMember);
        assertEquals(domainRoleMember.getMemberRoles().size(), 1);
        assertEquals(domainRoleMember.getMemberRoles().get(0).getRoleName(), "role2");

        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
    }

    @Test
    public void testGetResourceAccessListWithExternalMember() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-mbr-res-access";
        final String externalMember = domainName + ":ext.partner-user";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        // create a role with regular user and an external member

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "readers", null,
                "user.joe", null);
        zmsImpl.putRole(ctx, domainName, "readers", auditRef, false, null, role1);

        Membership extMbr = zmsTestInitializer.generateMembership("readers", externalMember);
        zmsImpl.putMembership(ctx, domainName, "readers", externalMember,
                auditRef, false, null, extMbr);

        // create a second role with only the external member

        Role role2 = zmsTestInitializer.createRoleObject(domainName, "writers", null,
                null, null);
        zmsImpl.putRole(ctx, domainName, "writers", auditRef, false, null, role2);

        extMbr = zmsTestInitializer.generateMembership("writers", externalMember);
        zmsImpl.putMembership(ctx, domainName, "writers", externalMember,
                auditRef, false, null, extMbr);

        // create policies for the roles

        Policy policy1 = zmsTestInitializer.createPolicyObject(domainName, "read-policy",
                "readers", "READ", domainName + ":data", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, domainName, "read-policy", auditRef, false, null, policy1);

        Policy policy2 = zmsTestInitializer.createPolicyObject(domainName, "write-policy",
                "writers", "WRITE", domainName + ":data", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, domainName, "write-policy", auditRef, false, null, policy2);

        // get resource access list for the external member with null action
        // should return both READ and WRITE assertions

        ResourceAccessList resourceAccessList = zmsImpl.getResourceAccessList(ctx,
                externalMember, null, null);
        assertNotNull(resourceAccessList);

        List<ResourceAccess> resources = resourceAccessList.getResources();
        assertEquals(resources.size(), 1);
        ResourceAccess rsrcAccess = resources.get(0);
        assertEquals(rsrcAccess.getPrincipal(), externalMember);
        assertEquals(rsrcAccess.getAssertions().size(), 2);

        // get resource access list for the external member with READ action

        resourceAccessList = zmsImpl.getResourceAccessList(ctx,
                externalMember, "READ", null);
        assertNotNull(resourceAccessList);

        resources = resourceAccessList.getResources();
        assertEquals(resources.size(), 1);
        rsrcAccess = resources.get(0);
        assertEquals(rsrcAccess.getPrincipal(), externalMember);
        assertEquals(rsrcAccess.getAssertions().size(), 1);
        assertEquals(rsrcAccess.getAssertions().get(0).getAction(), "read");
        assertEquals(rsrcAccess.getAssertions().get(0).getResource(), domainName + ":data");

        // get resource access list for the external member with WRITE action

        resourceAccessList = zmsImpl.getResourceAccessList(ctx,
                externalMember, "WRITE", null);
        assertNotNull(resourceAccessList);

        resources = resourceAccessList.getResources();
        assertEquals(resources.size(), 1);
        rsrcAccess = resources.get(0);
        assertEquals(rsrcAccess.getPrincipal(), externalMember);
        assertEquals(rsrcAccess.getAssertions().size(), 1);
        assertEquals(rsrcAccess.getAssertions().get(0).getAction(), "write");

        // get resource access list with an action the external member has no access to

        resourceAccessList = zmsImpl.getResourceAccessList(ctx,
                externalMember, "DELETE", null);
        assertNotNull(resourceAccessList);

        resources = resourceAccessList.getResources();
        assertEquals(resources.size(), 1);
        rsrcAccess = resources.get(0);
        assertEquals(rsrcAccess.getPrincipal(), externalMember);
        assertTrue(rsrcAccess.getAssertions().isEmpty());

        // remove the external member from the readers role and verify
        // only WRITE access remains

        zmsImpl.deleteMembership(ctx, domainName, "readers", externalMember, auditRef, null);

        resourceAccessList = zmsImpl.getResourceAccessList(ctx,
                externalMember, null, null);
        assertNotNull(resourceAccessList);

        resources = resourceAccessList.getResources();
        assertEquals(resources.size(), 1);
        rsrcAccess = resources.get(0);
        assertEquals(rsrcAccess.getPrincipal(), externalMember);
        assertEquals(rsrcAccess.getAssertions().size(), 1);
        assertEquals(rsrcAccess.getAssertions().get(0).getAction(), "write");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetPrincipalGroupsWithExternalMember() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName1 = "ext-mbr-princ-grps1";
        final String domainName2 = "ext-mbr-princ-grps2";
        final String externalMember = domainName1 + ":ext.partner-user";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName1, "externalmembervalidator", auditRef, dm);
        zmsImpl.putDomainSystemMeta(ctx, domainName2, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        // create a group in domain1 with the external member

        Group group1 = zmsTestInitializer.createGroupObject(domainName1, "partners",
                null, null);
        zmsImpl.putGroup(ctx, domainName1, "partners", auditRef, false, null, group1);

        GroupMembership gmbr = zmsTestInitializer.generateGroupMembership("partners", externalMember);
        zmsImpl.putGroupMembership(ctx, domainName1, "partners", externalMember,
                auditRef, false, null, gmbr);

        // create a group in domain2 with the external member

        Group group2 = zmsTestInitializer.createGroupObject(domainName2, "vendors",
                null, null);
        zmsImpl.putGroup(ctx, domainName2, "vendors", auditRef, false, null, group2);

        gmbr = zmsTestInitializer.generateGroupMembership("vendors", externalMember);
        zmsImpl.putGroupMembership(ctx, domainName2, "vendors", externalMember,
                auditRef, false, null, gmbr);

        // get all groups for the external member across all domains

        DomainGroupMember dgm = zmsImpl.getPrincipalGroups(ctx, externalMember, null);
        assertNotNull(dgm);
        assertEquals(dgm.getMemberName(), externalMember);
        List<GroupMember> memberGroups = dgm.getMemberGroups();
        assertEquals(memberGroups.size(), 2);

        boolean foundPartners = false;
        boolean foundVendors = false;
        for (GroupMember gm : memberGroups) {
            if ("partners".equals(gm.getGroupName()) && domainName1.equals(gm.getDomainName())) {
                foundPartners = true;
            } else if ("vendors".equals(gm.getGroupName()) && domainName2.equals(gm.getDomainName())) {
                foundVendors = true;
            }
        }
        assertTrue(foundPartners);
        assertTrue(foundVendors);

        // get groups filtered by domain1

        dgm = zmsImpl.getPrincipalGroups(ctx, externalMember, domainName1);
        assertNotNull(dgm);
        assertEquals(dgm.getMemberName(), externalMember);
        memberGroups = dgm.getMemberGroups();
        assertEquals(memberGroups.size(), 1);
        assertEquals(memberGroups.get(0).getGroupName(), "partners");
        assertEquals(memberGroups.get(0).getDomainName(), domainName1);

        // get groups filtered by domain2

        dgm = zmsImpl.getPrincipalGroups(ctx, externalMember, domainName2);
        assertNotNull(dgm);
        assertEquals(dgm.getMemberName(), externalMember);
        memberGroups = dgm.getMemberGroups();
        assertEquals(memberGroups.size(), 1);
        assertEquals(memberGroups.get(0).getGroupName(), "vendors");
        assertEquals(memberGroups.get(0).getDomainName(), domainName2);

        // remove the external member from group in domain1 and verify

        zmsImpl.deleteGroupMembership(ctx, domainName1, "partners", externalMember, auditRef, null);

        dgm = zmsImpl.getPrincipalGroups(ctx, externalMember, null);
        assertNotNull(dgm);
        memberGroups = dgm.getMemberGroups();
        assertEquals(memberGroups.size(), 1);
        assertEquals(memberGroups.get(0).getGroupName(), "vendors");
        assertEquals(memberGroups.get(0).getDomainName(), domainName2);

        // verify domain1 returns empty after removal

        dgm = zmsImpl.getPrincipalGroups(ctx, externalMember, domainName1);
        assertNotNull(dgm);
        assertTrue(dgm.getMemberGroups().isEmpty());

        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
    }

    @Test
    public void testValidateExternalMemberNoSeparator() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        try {
            zmsImpl.externalMemberValidatorManager.validateMember("domain1", "member-without-separator", "testCaller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal member-without-separator is not valid"));
        }
    }

    @Test
    public void testValidateExternalMemberEmptyName() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        try {
            zmsImpl.externalMemberValidatorManager.validateMember("domain1", "", "testCaller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal  is not valid"));
        }
    }

    @Test
    public void testValidateExternalMemberPlainUser() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        try {
            zmsImpl.externalMemberValidatorManager.validateMember("domain1", "user.joe", "testCaller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal user.joe is not valid"));
        }
    }

    @Test
    public void testValidateExternalMemberPartialSeparator() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // "ext." without the leading colon is not a valid separator
        try {
            zmsImpl.externalMemberValidatorManager.validateMember("domain1", "ext.partner-user", "testCaller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal ext.partner-user is not valid"));
        }

        // colon without "ext." suffix is not a valid separator
        try {
            zmsImpl.externalMemberValidatorManager.validateMember("domain1", "domain1:partner-user", "testCaller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal domain1:partner-user is not valid"));
        }
    }

    @Test
    public void testValidateExternalMemberWithValidSeparator() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "ext-validate-sep";

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(),
                ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl,
                ctx.principal().getFullName(), auditRef);

        DomainMeta dm = new DomainMeta().setExternalMemberValidator(
                "com.yahoo.athenz.zms.TestExternalMemberValidator");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "externalmembervalidator", auditRef, dm);
        zmsImpl.externalMemberValidatorManager.refreshValidators();

        // valid separator present - should not throw since the member name
        // does not contain "invalid"

        zmsImpl.externalMemberValidatorManager.validateMember(domainName, domainName + ":ext.partner-user", "testCaller");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
