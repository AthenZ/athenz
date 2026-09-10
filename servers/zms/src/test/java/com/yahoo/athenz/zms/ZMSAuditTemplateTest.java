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

import com.yahoo.athenz.zms.config.AuditTemplate;
import com.yahoo.rdl.Timestamp;
import jakarta.ws.rs.core.Response;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.*;

public class ZMSAuditTemplateTest {

    private static final String AUDIT_TEMPLATE_FNAME = "src/test/resources/audit_template.json";

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
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME, AUDIT_TEMPLATE_FNAME);
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void shutDown() {
        zmsTestInitializer.shutDown();
        System.clearProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME);
    }

    /**
     * verify that the given due date is set to the specified number
     * of days from now (allowing a small window for the test runtime)
     */
    private void assertDueDateInDays(Timestamp dueDate, int days) {
        assertNotNull(dueDate);
        long expectedMillis = System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(days, TimeUnit.DAYS);
        long deltaMillis = Math.abs(expectedMillis - dueDate.millis());
        assertTrue(deltaMillis < TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES),
                "due date " + dueDate + " not within " + days + " days");
    }

    private RoleMember getRoleMember(List<RoleMember> members, final String memberName) {
        for (RoleMember member : members) {
            if (memberName.equals(member.getMemberName())) {
                return member;
            }
        }
        fail("role member not found: " + memberName);
        return null;
    }

    private GroupMember getGroupMember(List<GroupMember> members, final String memberName) {
        for (GroupMember member : members) {
            if (memberName.equals(member.getMemberName())) {
                return member;
            }
        }
        fail("group member not found: " + memberName);
        return null;
    }

    @Test
    public void testLoadAuditTemplate() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // the template must have been loaded during startup and
        // passed to the db service configuration

        AuditTemplate template = zmsImpl.auditTemplate;
        assertNotNull(template);
        assertSame(zmsImpl.dbService.zmsConfig.getAuditTemplate(), template);

        assertEquals(template.getDomain().getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(template.getDomain().getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(template.getDomain().getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(template.getRole().getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(template.getRole().getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(template.getRole().getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(template.getRole().getMemberReviewDays(), Integer.valueOf(45));
        assertEquals(template.getRole().getServiceReviewDays(), Integer.valueOf(30));
        assertEquals(template.getRole().getGroupReviewDays(), Integer.valueOf(15));
        assertEquals(template.getGroup().getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(template.getGroup().getServiceExpiryDays(), Integer.valueOf(120));

        // if the property is not set then no template is loaded

        System.clearProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME);
        zmsImpl.auditTemplate = null;
        zmsImpl.loadAuditTemplate();
        assertNull(zmsImpl.auditTemplate);

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME, "");
        zmsImpl.loadAuditTemplate();
        assertNull(zmsImpl.auditTemplate);

        // reload our template

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME, AUDIT_TEMPLATE_FNAME);
        zmsImpl.loadAuditTemplate();
        assertNotNull(zmsImpl.auditTemplate);
    }

    @Test
    public void testLoadAuditTemplateFailures() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        // missing file

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME, "src/test/resources/audit_template_missing.json");
        try {
            zmsImpl.loadAuditTemplate();
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid audit template file");
        }

        // invalid json file

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME, "src/test/resources/audit_template_invalid.json");
        try {
            zmsImpl.loadAuditTemplate();
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid audit template file");
        }

        // negative values

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME, "src/test/resources/audit_template_negative.json");
        try {
            zmsImpl.loadAuditTemplate();
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("role.memberExpiryDays"), ex.getMessage());
        }

        // the server constructor must fail as well

        try {
            zmsTestInitializer.zmsInit();
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("role.memberExpiryDays"), ex.getMessage());
        }

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME, AUDIT_TEMPLATE_FNAME);
    }

    @Test
    public void testAuditTemplateTopLevelDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String auditDomainName = "audit-template-tld1";
        final String regularDomainName = "audit-template-tld2";

        // audit enabled domain: member expiry bigger than the limit,
        // service expiry smaller than the limit and no group expiry

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(auditDomainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        dom1.setMemberExpiryDays(180);
        dom1.setServiceExpiryDays(100);
        Domain resDom1 = zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        assertEquals(resDom1.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resDom1.getServiceExpiryDays(), Integer.valueOf(100));
        assertEquals(resDom1.getGroupExpiryDays(), Integer.valueOf(60));

        Domain domain = zmsImpl.getDomain(ctx, auditDomainName);
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(100));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(60));

        // regular domain: no changes

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(regularDomainName,
                "Audit Template Test Domain2", "testOrg", "user.user1");
        dom2.setMemberExpiryDays(180);
        Domain resDom2 = zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        assertEquals(resDom2.getMemberExpiryDays(), Integer.valueOf(180));
        assertNull(resDom2.getServiceExpiryDays());
        assertNull(resDom2.getGroupExpiryDays());

        zmsImpl.deleteTopLevelDomain(ctx, auditDomainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, regularDomainName, auditRef, null);
    }

    @Test
    public void testAuditTemplateSubDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String parentDomainName = "audit-template-parent";
        final String subDomainName = "sub1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(parentDomainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // the sub-domain inherits the audit enabled flag from the parent
        // so the template settings must be applied

        SubDomain dom2 = zmsTestInitializer.createSubDomainObject(subDomainName, parentDomainName,
                "Audit Template Test Domain2", "testOrg", "user.user1");
        dom2.setMemberExpiryDays(200);
        dom2.setGroupExpiryDays(0);
        Domain resDom2 = zmsImpl.postSubDomain(ctx, parentDomainName, auditRef, null, dom2);

        assertTrue(resDom2.getAuditEnabled());
        assertEquals(resDom2.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resDom2.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(resDom2.getGroupExpiryDays(), Integer.valueOf(60));

        zmsImpl.deleteSubDomain(ctx, parentDomainName, subDomainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, parentDomainName, auditRef, null);
    }

    @Test
    public void testAuditTemplateUserDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        final String auditRef = zmsTestInitializer.getAuditRef();

        RsrcCtxWrapper ctx = zmsTestInitializer.contextWithMockPrincipal("postUserDomain");
        UserDomain dom1 = zmsTestInitializer.createUserDomainObject("john-doe", "Test Domain1", "testOrg");
        dom1.setAuditEnabled(true);
        dom1.setMemberExpiryDays(365);
        dom1.setServiceExpiryDays(120);
        Domain resDom1 = zmsImpl.postUserDomain(ctx, "john-doe", auditRef, null, dom1);

        assertEquals(resDom1.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resDom1.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(resDom1.getGroupExpiryDays(), Integer.valueOf(60));

        zmsImpl.deleteUserDomain(ctx, "john-doe", auditRef, null);
    }

    @Test
    public void testAuditTemplateDomainMeta() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String auditDomainName = "audit-template-meta1";
        final String regularDomainName = "audit-template-meta2";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(auditDomainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, auditDomainName);
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(60));

        // member expiry bigger than the limit, service expiry smaller than
        // the limit and group expiry not specified (stays as is)

        DomainMeta meta = new DomainMeta().setDescription("Audit Template Test Domain1")
                .setOrg("testOrg").setMemberExpiryDays(365).setServiceExpiryDays(30);
        zmsImpl.putDomainMeta(ctx, auditDomainName, auditRef, null, meta);

        domain = zmsImpl.getDomain(ctx, auditDomainName);
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(30));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(60));

        // setting the value to 0 (no expiry) is also not allowed

        meta = new DomainMeta().setDescription("Audit Template Test Domain1")
                .setOrg("testOrg").setServiceExpiryDays(0);
        zmsImpl.putDomainMeta(ctx, auditDomainName, auditRef, null, meta);

        domain = zmsImpl.getDomain(ctx, auditDomainName);
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(60));

        // regular domain: no changes

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(regularDomainName,
                "Audit Template Test Domain2", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        meta = new DomainMeta().setDescription("Audit Template Test Domain2")
                .setOrg("testOrg").setMemberExpiryDays(365);
        zmsImpl.putDomainMeta(ctx, regularDomainName, auditRef, null, meta);

        domain = zmsImpl.getDomain(ctx, regularDomainName);
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(365));
        assertNull(domain.getServiceExpiryDays());
        assertNull(domain.getGroupExpiryDays());

        zmsImpl.deleteTopLevelDomain(ctx, auditDomainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, regularDomainName, auditRef, null);
    }

    @Test
    public void testAuditTemplateDomainSystemMeta() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-sysmeta";
        final String roleName = "role1";

        // create a regular domain with member expiry bigger than the limit
        // and a role with members without any expiration

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setMemberExpiryDays(200);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null, "user.john", "user.jane");
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        Role resRole = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.john").getExpiration(), 200);

        // now enable the audit flag on the domain

        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl, ctx.principal().getFullName(), auditRef);

        DomainMeta meta = new DomainMeta().setAuditEnabled(true);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "auditenabled", auditRef, meta);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertTrue(domain.getAuditEnabled());
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(60));

        // the existing role members must have their expiration reduced

        resRole = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.john").getExpiration(), 90);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.jane").getExpiration(), 90);

        // disabling the audit flag does not change any settings

        meta = new DomainMeta().setAuditEnabled(false);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "auditenabled", auditRef, meta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertFalse(domain.getAuditEnabled());
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(60));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplatePutRole() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-putrole";
        final String auditRoleName = "audit-role";
        final String regularRoleName = "regular-role";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // audit enabled role: member expiry bigger than the limit, service
        // expiry smaller than the limit, group expiry set to 0, service
        // review smaller than the limit and no member/group review

        Role role = zmsTestInitializer.createRoleObject(domainName, auditRoleName, null, "user.john", "user.jane");
        role.setAuditEnabled(true);
        role.setMemberExpiryDays(180);
        role.setServiceExpiryDays(60);
        role.setGroupExpiryDays(0);
        role.setServiceReviewDays(10);
        Response response = zmsImpl.putRole(ctx, domainName, auditRoleName, auditRef, true, null, role);
        Role resRole = (Role) response.getEntity();

        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resRole.getServiceExpiryDays(), Integer.valueOf(60));
        assertEquals(resRole.getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(resRole.getMemberReviewDays(), Integer.valueOf(45));
        assertEquals(resRole.getServiceReviewDays(), Integer.valueOf(10));
        assertEquals(resRole.getGroupReviewDays(), Integer.valueOf(15));

        // the members (pending since the role is audit enabled) must have
        // their expiration and review dates set based on the template

        resRole = zmsImpl.getRole(ctx, domainName, auditRoleName, false, false, true);
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resRole.getMemberReviewDays(), Integer.valueOf(45));

        RoleMember member = getRoleMember(resRole.getRoleMembers(), "user.john");
        assertDueDateInDays(member.getExpiration(), 90);
        assertDueDateInDays(member.getReviewReminder(), 45);

        // regular role in the same domain: no changes

        role = zmsTestInitializer.createRoleObject(domainName, regularRoleName, null, "user.john", "user.jane");
        role.setMemberExpiryDays(180);
        response = zmsImpl.putRole(ctx, domainName, regularRoleName, auditRef, true, null, role);
        resRole = (Role) response.getEntity();

        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(180));
        assertNull(resRole.getServiceExpiryDays());
        assertNull(resRole.getGroupExpiryDays());
        assertNull(resRole.getMemberReviewDays());
        assertNull(resRole.getServiceReviewDays());
        assertNull(resRole.getGroupReviewDays());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplatePutRoleMeta() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-rolemeta";
        final String auditRoleName = "audit-role";
        final String regularRoleName = "regular-role";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role = zmsTestInitializer.createRoleObject(domainName, auditRoleName, null);
        role.setAuditEnabled(true);
        role.setMemberExpiryDays(30);
        role.setServiceExpiryDays(30);
        zmsImpl.putRole(ctx, domainName, auditRoleName, auditRef, false, null, role);

        Role resRole = zmsImpl.getRole(ctx, domainName, auditRoleName, false, false, false);
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(resRole.getServiceExpiryDays(), Integer.valueOf(30));
        assertEquals(resRole.getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(resRole.getMemberReviewDays(), Integer.valueOf(45));
        assertEquals(resRole.getServiceReviewDays(), Integer.valueOf(30));
        assertEquals(resRole.getGroupReviewDays(), Integer.valueOf(15));

        // the meta request does not include the audit enabled flag, but
        // it's carried forward from the role. member expiry bigger than
        // the limit, service expiry within the limit and the rest not
        // specified thus not changed

        RoleMeta meta = new RoleMeta().setMemberExpiryDays(180).setServiceExpiryDays(20);
        zmsImpl.putRoleMeta(ctx, domainName, auditRoleName, auditRef, null, meta);

        resRole = zmsImpl.getRole(ctx, domainName, auditRoleName, false, false, false);
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resRole.getServiceExpiryDays(), Integer.valueOf(20));
        assertEquals(resRole.getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(resRole.getMemberReviewDays(), Integer.valueOf(45));
        assertEquals(resRole.getServiceReviewDays(), Integer.valueOf(30));
        assertEquals(resRole.getGroupReviewDays(), Integer.valueOf(15));

        // regular role in the same domain: no changes

        role = zmsTestInitializer.createRoleObject(domainName, regularRoleName, null);
        zmsImpl.putRole(ctx, domainName, regularRoleName, auditRef, false, null, role);

        meta = new RoleMeta().setMemberExpiryDays(180);
        zmsImpl.putRoleMeta(ctx, domainName, regularRoleName, auditRef, null, meta);

        resRole = zmsImpl.getRole(ctx, domainName, regularRoleName, false, false, false);
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(180));
        assertNull(resRole.getServiceExpiryDays());
        assertNull(resRole.getGroupExpiryDays());
        assertNull(resRole.getMemberReviewDays());
        assertNull(resRole.getServiceReviewDays());
        assertNull(resRole.getGroupReviewDays());

        // setting the audit enabled flag on the regular role using the
        // meta api (no members) must apply the template settings

        meta = new RoleMeta().setAuditEnabled(true);
        zmsImpl.putRoleMeta(ctx, domainName, regularRoleName, auditRef, null, meta);

        resRole = zmsImpl.getRole(ctx, domainName, regularRoleName, false, false, false);
        assertTrue(resRole.getAuditEnabled());
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resRole.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(resRole.getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(resRole.getMemberReviewDays(), Integer.valueOf(45));
        assertEquals(resRole.getServiceReviewDays(), Integer.valueOf(30));
        assertEquals(resRole.getGroupReviewDays(), Integer.valueOf(15));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplatePutRoleSystemMeta() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-rolesysmeta";
        final String roleName = "role1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // regular role with members: john has no expiration, jane has
        // an expiration bigger than the limit and jack has one smaller

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null, "user.john", null);
        role.getRoleMembers().add(new RoleMember().setMemberName("user.jane")
                .setExpiration(ZMSTestUtils.buildExpiration(180, false)));
        role.getRoleMembers().add(new RoleMember().setMemberName("user.jack")
                .setExpiration(ZMSTestUtils.buildExpiration(10, false)));
        role.setMemberExpiryDays(365);
        role.setMemberReviewDays(0);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        Role resRole = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(365));
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.john").getExpiration(), 365);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.jane").getExpiration(), 180);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.jack").getExpiration(), 10);
        assertNull(getRoleMember(resRole.getRoleMembers(), "user.john").getReviewReminder());

        // now enable the audit flag on the role

        RoleSystemMeta rsm = ZMSTestUtils.createRoleSystemMetaObject(true);
        zmsImpl.putRoleSystemMeta(ctx, domainName, roleName, "auditenabled", auditRef, rsm);

        resRole = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertTrue(resRole.getAuditEnabled());
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resRole.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(resRole.getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(resRole.getMemberReviewDays(), Integer.valueOf(45));
        assertEquals(resRole.getServiceReviewDays(), Integer.valueOf(30));
        assertEquals(resRole.getGroupReviewDays(), Integer.valueOf(15));

        // members with no or bigger expiration must be reduced while
        // the member with a smaller expiration is not changed. all
        // members must now have a review reminder set

        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.john").getExpiration(), 90);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.jane").getExpiration(), 90);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.jack").getExpiration(), 10);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.john").getReviewReminder(), 45);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.jane").getReviewReminder(), 45);
        assertDueDateInDays(getRoleMember(resRole.getRoleMembers(), "user.jack").getReviewReminder(), 45);

        // disabling the audit flag does not change any settings

        rsm = ZMSTestUtils.createRoleSystemMetaObject(false);
        zmsImpl.putRoleSystemMeta(ctx, domainName, roleName, "auditenabled", auditRef, rsm);

        resRole = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertNotEquals(resRole.getAuditEnabled(), Boolean.TRUE);
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resRole.getMemberReviewDays(), Integer.valueOf(45));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplatePutGroup() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-putgroup";
        final String auditGroupName = "audit-group";
        final String regularGroupName = "regular-group";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // audit enabled group: member expiry bigger than the limit
        // and service expiry not specified

        Group group = zmsTestInitializer.createGroupObject(domainName, auditGroupName, "user.john", "user.jane");
        group.setAuditEnabled(true);
        group.setMemberExpiryDays(180);
        Response response = zmsImpl.putGroup(ctx, domainName, auditGroupName, auditRef, true, null, group);
        Group resGroup = (Group) response.getEntity();

        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resGroup.getServiceExpiryDays(), Integer.valueOf(120));

        // the members (pending since the group is audit enabled) must
        // have their expiration set based on the template

        resGroup = zmsImpl.getGroup(ctx, domainName, auditGroupName, false, true);
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resGroup.getServiceExpiryDays(), Integer.valueOf(120));
        assertDueDateInDays(getGroupMember(resGroup.getGroupMembers(), "user.john").getExpiration(), 90);

        // regular group in the same domain: no changes

        group = zmsTestInitializer.createGroupObject(domainName, regularGroupName, "user.john", "user.jane");
        group.setMemberExpiryDays(180);
        response = zmsImpl.putGroup(ctx, domainName, regularGroupName, auditRef, true, null, group);
        resGroup = (Group) response.getEntity();

        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(180));
        assertNull(resGroup.getServiceExpiryDays());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplatePutGroupMeta() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-groupmeta";
        final String auditGroupName = "audit-group";
        final String regularGroupName = "regular-group";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Group group = zmsTestInitializer.createGroupObject(domainName, auditGroupName, null, null);
        group.setAuditEnabled(true);
        group.setMemberExpiryDays(30);
        group.setServiceExpiryDays(30);
        zmsImpl.putGroup(ctx, domainName, auditGroupName, auditRef, false, null, group);

        Group resGroup = zmsImpl.getGroup(ctx, domainName, auditGroupName, false, false);
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(resGroup.getServiceExpiryDays(), Integer.valueOf(30));

        // the meta request does not include the audit enabled flag, but
        // it's carried forward from the group. member expiry bigger than
        // the limit and service expiry not specified thus not changed

        GroupMeta meta = new GroupMeta().setMemberExpiryDays(180);
        zmsImpl.putGroupMeta(ctx, domainName, auditGroupName, auditRef, null, meta);

        resGroup = zmsImpl.getGroup(ctx, domainName, auditGroupName, false, false);
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resGroup.getServiceExpiryDays(), Integer.valueOf(30));

        // regular group in the same domain: no changes

        group = zmsTestInitializer.createGroupObject(domainName, regularGroupName, null, null);
        zmsImpl.putGroup(ctx, domainName, regularGroupName, auditRef, false, null, group);

        meta = new GroupMeta().setMemberExpiryDays(180);
        zmsImpl.putGroupMeta(ctx, domainName, regularGroupName, auditRef, null, meta);

        resGroup = zmsImpl.getGroup(ctx, domainName, regularGroupName, false, false);
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(180));
        assertNull(resGroup.getServiceExpiryDays());

        // setting the audit enabled flag on the regular group using the
        // meta api (no members) must apply the template settings

        meta = new GroupMeta().setAuditEnabled(true);
        zmsImpl.putGroupMeta(ctx, domainName, regularGroupName, auditRef, null, meta);

        resGroup = zmsImpl.getGroup(ctx, domainName, regularGroupName, false, false);
        assertTrue(resGroup.getAuditEnabled());
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resGroup.getServiceExpiryDays(), Integer.valueOf(120));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplatePutGroupSystemMeta() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-groupsysmeta";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // regular group with members: john has no expiration, jane has
        // an expiration bigger than the limit and jack has one smaller

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName, "user.john", null);
        group.getGroupMembers().add(new GroupMember().setMemberName("user.jane")
                .setExpiration(ZMSTestUtils.buildExpiration(180, false)));
        group.getGroupMembers().add(new GroupMember().setMemberName("user.jack")
                .setExpiration(ZMSTestUtils.buildExpiration(10, false)));
        group.setMemberExpiryDays(365);
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        Group resGroup = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(365));
        assertDueDateInDays(getGroupMember(resGroup.getGroupMembers(), "user.john").getExpiration(), 365);
        assertDueDateInDays(getGroupMember(resGroup.getGroupMembers(), "user.jane").getExpiration(), 180);
        assertDueDateInDays(getGroupMember(resGroup.getGroupMembers(), "user.jack").getExpiration(), 10);

        // now enable the audit flag on the group

        GroupSystemMeta gsm = ZMSTestUtils.createGroupSystemMetaObject(true);
        zmsImpl.putGroupSystemMeta(ctx, domainName, groupName, "auditenabled", auditRef, gsm);

        resGroup = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertTrue(resGroup.getAuditEnabled());
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resGroup.getServiceExpiryDays(), Integer.valueOf(120));

        // members with no or bigger expiration must be reduced while
        // the member with a smaller expiration is not changed

        assertDueDateInDays(getGroupMember(resGroup.getGroupMembers(), "user.john").getExpiration(), 90);
        assertDueDateInDays(getGroupMember(resGroup.getGroupMembers(), "user.jane").getExpiration(), 90);
        assertDueDateInDays(getGroupMember(resGroup.getGroupMembers(), "user.jack").getExpiration(), 10);

        // disabling the audit flag does not change any settings

        gsm = ZMSTestUtils.createGroupSystemMetaObject(false);
        zmsImpl.putGroupSystemMeta(ctx, domainName, groupName, "auditenabled", auditRef, gsm);

        resGroup = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertNotEquals(resGroup.getAuditEnabled(), Boolean.TRUE);
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resGroup.getServiceExpiryDays(), Integer.valueOf(120));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
