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

import com.yahoo.athenz.common.ServerCommonConsts;
import jakarta.ws.rs.core.Response;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Verifies the behavior of the audit template when the server is configured
 * to only enforce the template on those domains that have the enforce audit
 * template feature flag bit enabled.
 */
public class ZMSAuditTemplateFeatureFlagTest {

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
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_DOMAIN_FEATURE_FLAG_CHECK, "true");
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void shutDown() {
        zmsTestInitializer.shutDown();
        System.clearProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_FNAME);
        System.clearProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_DOMAIN_FEATURE_FLAG_CHECK);
    }

    /**
     * enable the enforce audit template feature flag bit on the given domain
     */
    private void setEnforceAuditTemplateFlag(ZMSImpl zmsImpl, RsrcCtxWrapper ctx, final String domainName) {
        final String auditRef = zmsTestInitializer.getAuditRef();
        ZMSTestUtils.setupSystemMetaAuthorization(ctx, zmsImpl, ctx.principal().getFullName(), auditRef);
        DomainMeta meta = new DomainMeta()
                .setFeatureFlags(ServerCommonConsts.ZMS_DOMAIN_FEATURE_ENFORCE_AUDIT_TEMPLATE);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "featureflags", auditRef, meta);
    }

    @Test
    public void testLoadAuditTemplateFeatureFlagCheck() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        assertTrue(zmsImpl.auditTemplateDomainFeatureFlagCheck);
        assertTrue(zmsImpl.dbService.zmsConfig.isAuditTemplateDomainFeatureFlagCheck());

        // the setting is picked up from the property during load

        System.clearProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_DOMAIN_FEATURE_FLAG_CHECK);
        zmsImpl.loadAuditTemplate();
        assertFalse(zmsImpl.auditTemplateDomainFeatureFlagCheck);

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_TEMPLATE_DOMAIN_FEATURE_FLAG_CHECK, "true");
        zmsImpl.loadAuditTemplate();
        assertTrue(zmsImpl.auditTemplateDomainFeatureFlagCheck);
    }

    @Test
    public void testAuditTemplateDomainWithoutFeatureFlag() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-ff-disabled";

        // the domain is audit enabled but does not have the enforce audit
        // template feature flag bit set thus no settings are imposed

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        dom1.setMemberExpiryDays(180);
        Domain resDom1 = zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        assertEquals(resDom1.getMemberExpiryDays(), Integer.valueOf(180));
        assertNull(resDom1.getServiceExpiryDays());
        assertNull(resDom1.getGroupExpiryDays());

        // domain meta updates are not limited either

        DomainMeta meta = new DomainMeta().setDescription("Audit Template Test Domain1")
                .setOrg("testOrg").setMemberExpiryDays(365);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(365));

        // audit enabled roles are not limited

        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        role.setAuditEnabled(true);
        role.setMemberExpiryDays(180);
        Response response = zmsImpl.putRole(ctx, domainName, "role1", auditRef, true, null, role);
        Role resRole = (Role) response.getEntity();

        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(180));
        assertNull(resRole.getServiceExpiryDays());
        assertNull(resRole.getMemberReviewDays());

        RoleMeta roleMeta = new RoleMeta().setMemberExpiryDays(365);
        zmsImpl.putRoleMeta(ctx, domainName, "role1", auditRef, null, roleMeta);

        resRole = zmsImpl.getRole(ctx, domainName, "role1", false, false, false);
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(365));

        // audit enabled groups are not limited

        Group group = zmsTestInitializer.createGroupObject(domainName, "group1", "user.john", "user.jane");
        group.setAuditEnabled(true);
        group.setMemberExpiryDays(180);
        response = zmsImpl.putGroup(ctx, domainName, "group1", auditRef, true, null, group);
        Group resGroup = (Group) response.getEntity();

        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(180));
        assertNull(resGroup.getServiceExpiryDays());

        GroupMeta groupMeta = new GroupMeta().setMemberExpiryDays(365);
        zmsImpl.putGroupMeta(ctx, domainName, "group1", auditRef, null, groupMeta);

        resGroup = zmsImpl.getGroup(ctx, domainName, "group1", false, false);
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(365));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplateDomainWithFeatureFlag() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-ff-enabled";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        dom1.setMemberExpiryDays(180);
        Domain resDom1 = zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // the domain is created without any feature flags so the template
        // is not applied at creation time

        assertEquals(resDom1.getMemberExpiryDays(), Integer.valueOf(180));

        setEnforceAuditTemplateFlag(zmsImpl, ctx, domainName);

        // now that the bit is enabled the domain meta values are limited

        DomainMeta meta = new DomainMeta().setDescription("Audit Template Test Domain1")
                .setOrg("testOrg").setMemberExpiryDays(365).setServiceExpiryDays(30);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(30));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(60));

        // audit enabled roles are limited

        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null, "user.john", "user.jane");
        role.setAuditEnabled(true);
        role.setMemberExpiryDays(180);
        Response response = zmsImpl.putRole(ctx, domainName, "role1", auditRef, true, null, role);
        Role resRole = (Role) response.getEntity();

        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resRole.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(resRole.getMemberReviewDays(), Integer.valueOf(45));

        RoleMeta roleMeta = new RoleMeta().setMemberExpiryDays(365);
        zmsImpl.putRoleMeta(ctx, domainName, "role1", auditRef, null, roleMeta);

        resRole = zmsImpl.getRole(ctx, domainName, "role1", false, false, false);
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(90));

        // audit enabled groups are limited

        Group group = zmsTestInitializer.createGroupObject(domainName, "group1", "user.john", "user.jane");
        group.setAuditEnabled(true);
        group.setMemberExpiryDays(180);
        response = zmsImpl.putGroup(ctx, domainName, "group1", auditRef, true, null, group);
        Group resGroup = (Group) response.getEntity();

        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resGroup.getServiceExpiryDays(), Integer.valueOf(120));

        GroupMeta groupMeta = new GroupMeta().setMemberExpiryDays(365);
        zmsImpl.putGroupMeta(ctx, domainName, "group1", auditRef, null, groupMeta);

        resGroup = zmsImpl.getGroup(ctx, domainName, "group1", false, false);
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(90));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplateSystemMetaWithoutFeatureFlag() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-ff-sysmeta-off";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null, "user.john", null);
        role.setMemberExpiryDays(365);
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role);

        Group group = zmsTestInitializer.createGroupObject(domainName, "group1", "user.john", null);
        group.setMemberExpiryDays(365);
        zmsImpl.putGroup(ctx, domainName, "group1", auditRef, false, null, group);

        // enabling the audit flag on the role and group must not impose
        // any template settings since the domain does not have the bit

        RoleSystemMeta rsm = ZMSTestUtils.createRoleSystemMetaObject(true);
        zmsImpl.putRoleSystemMeta(ctx, domainName, "role1", "auditenabled", auditRef, rsm);

        Role resRole = zmsImpl.getRole(ctx, domainName, "role1", false, false, false);
        assertTrue(resRole.getAuditEnabled());
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(365));
        assertNull(resRole.getMemberReviewDays());

        GroupSystemMeta gsm = ZMSTestUtils.createGroupSystemMetaObject(true);
        zmsImpl.putGroupSystemMeta(ctx, domainName, "group1", "auditenabled", auditRef, gsm);

        Group resGroup = zmsImpl.getGroup(ctx, domainName, "group1", false, false);
        assertTrue(resGroup.getAuditEnabled());
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(365));
        assertNull(resGroup.getServiceExpiryDays());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplateSystemMetaWithFeatureFlag() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-template-ff-sysmeta-on";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        setEnforceAuditTemplateFlag(zmsImpl, ctx, domainName);

        Role role = zmsTestInitializer.createRoleObject(domainName, "role1", null, "user.john", null);
        role.setMemberExpiryDays(365);
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role);

        Group group = zmsTestInitializer.createGroupObject(domainName, "group1", "user.john", null);
        group.setMemberExpiryDays(365);
        zmsImpl.putGroup(ctx, domainName, "group1", auditRef, false, null, group);

        // enabling the audit flag on the role and group must impose the
        // template settings since the domain has the bit enabled

        RoleSystemMeta rsm = ZMSTestUtils.createRoleSystemMetaObject(true);
        zmsImpl.putRoleSystemMeta(ctx, domainName, "role1", "auditenabled", auditRef, rsm);

        Role resRole = zmsImpl.getRole(ctx, domainName, "role1", false, false, false);
        assertTrue(resRole.getAuditEnabled());
        assertEquals(resRole.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resRole.getMemberReviewDays(), Integer.valueOf(45));

        GroupSystemMeta gsm = ZMSTestUtils.createGroupSystemMetaObject(true);
        zmsImpl.putGroupSystemMeta(ctx, domainName, "group1", "auditenabled", auditRef, gsm);

        Group resGroup = zmsImpl.getGroup(ctx, domainName, "group1", false, false);
        assertTrue(resGroup.getAuditEnabled());
        assertEquals(resGroup.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(resGroup.getServiceExpiryDays(), Integer.valueOf(120));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testAuditTemplateDomainSystemMetaAuditEnabled() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String flagDomainName = "audit-template-ff-domsysmeta-on";
        final String regularDomainName = "audit-template-ff-domsysmeta-off";

        // domain with the feature flag bit enabled: turning on the audit
        // enabled flag must impose the template settings

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(flagDomainName,
                "Audit Template Test Domain1", "testOrg", "user.user1");
        dom1.setMemberExpiryDays(365);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        setEnforceAuditTemplateFlag(zmsImpl, ctx, flagDomainName);

        DomainMeta meta = new DomainMeta().setAuditEnabled(true);
        zmsImpl.putDomainSystemMeta(ctx, flagDomainName, "auditenabled", auditRef, meta);

        Domain domain = zmsImpl.getDomain(ctx, flagDomainName);
        assertTrue(domain.getAuditEnabled());
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(60));

        // domain without the bit: no settings are imposed

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(regularDomainName,
                "Audit Template Test Domain2", "testOrg", "user.user1");
        dom2.setMemberExpiryDays(365);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        meta = new DomainMeta().setAuditEnabled(true);
        zmsImpl.putDomainSystemMeta(ctx, regularDomainName, "auditenabled", auditRef, meta);

        domain = zmsImpl.getDomain(ctx, regularDomainName);
        assertTrue(domain.getAuditEnabled());
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(365));
        assertNull(domain.getServiceExpiryDays());
        assertNull(domain.getGroupExpiryDays());

        zmsImpl.deleteTopLevelDomain(ctx, flagDomainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, regularDomainName, auditRef, null);
    }
}
