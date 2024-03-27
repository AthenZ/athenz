/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms;

import org.testng.annotations.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;
import static org.testng.Assert.assertTrue;

public class ZMSTemplateTest {

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
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
    }

    @Test
    public void testPutDomainTemplateInvalidTemplate() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        String domainName = "templatelist-invalid";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // first no templates

        DomainTemplate templateList = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templateList.setTemplateNames(templates);

        try {
            zmsImpl.putDomainTemplate(ctx, domainName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("No templates specified"));
        }

        // then invalid template

        templates.add("test validate");
        try {
            zmsImpl.putDomainTemplate(ctx, domainName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateNotFoundTemplate() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "templatelist-invalid";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        DomainTemplate templateList = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add("InvalidTemplate");
        templateList.setTemplateNames(templates);
        try {
            zmsImpl.putDomainTemplate(ctx, domainName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateSingleTemplate() {

        String domainName = "templatelist-single";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        SubDomain domSysNetwork = zmsTestInitializer.createSubDomainObject("network", "sys", "Test Domain",
                "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postSubDomain(ctx, "sys", auditRef, null, domSysNetwork);

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        DomainTemplate domTemplate = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        domTemplate.setTemplateNames(templates);

        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domTemplate);

        // verify that our role collection includes the roles defined in template

        List<String> names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Role role = zmsImpl.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertTrue(role.getRoleMembers().isEmpty());

        role = zmsImpl.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());

        // verify that our policy collections includes the policies defined in the template

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Policy policy = zmsImpl.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        policy = zmsImpl.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
        assertEquals(domainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        // delete an applied service template
        //
        String templateName = "vipng";
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        // verify that our role collection does NOT include the roles defined in template

        names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        zmsImpl.deleteSubDomain(ctx, "sys", "network", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateMultipleTemplates() {

        String domainName = "templatelist-multiple";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        SubDomain domSysNetwork = zmsTestInitializer.createSubDomainObject("network", "sys", "Test Domain",
                "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postSubDomain(ctx, "sys", auditRef, null, domSysNetwork);

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        DomainTemplate domTemplate = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        templates.add("platforms");
        templates.add("user_provisioning");
        domTemplate.setTemplateNames(templates);

        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domTemplate);

        // verify that our role collection includes the roles defined in template

        List<String> names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(7, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        Role role = zmsImpl.dbService.getRole(domainName, "openstack_readers", false, false, false);
        assertEquals(domainName + ":role.openstack_readers", role.getName());
        assertNull(role.getTrust());
        assertEquals(2, role.getRoleMembers().size());

        List<String> checkList = new ArrayList<>();
        checkList.add("sys.builder");
        checkList.add("sys.openstack");
        zmsTestInitializer.checkRoleMember(checkList, role.getRoleMembers());

        role = zmsImpl.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());

        // verify that our policy collections includes the policies defined in the template

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(7, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        Policy policy = zmsImpl.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        policy = zmsImpl.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
        assertEquals(domainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        // delete applied service template
        //
        String templateName = "vipng";
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        // verify that our role collection does NOT include the vipng roles defined in template

        names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(5, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(5, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        // delete applied service template
        //
        templateName = "platforms";
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        // verify that our role collection does NOT include the platforms roles defined in template

        names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        // delete last applied service template
        //
        templateName = "user_provisioning";
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        // verify that our role collection does NOT include the user_provisioning roles defined in template

        names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        zmsImpl.deleteSubDomain(ctx, "sys", "network", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateExtInvalidTemplate() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "templatelist-invalid";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // first no templates

        DomainTemplate templateList = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templateList.setTemplateNames(templates);

        try {
            zmsImpl.putDomainTemplate(ctx, domainName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("No templates specified"));
        }

        final String templateName = "test validate";
        templates.add(templateName);
        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, templateName,
                    auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateExtNotFoundTemplate() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "templatelist-invalid";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        final String templateName = "InvalidTemplate";
        DomainTemplate templateList = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add(templateName);
        templateList.setTemplateNames(templates);
        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, templateName,
                    auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateExtEmptyTemplateList() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "templatelist-empty";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        DomainTemplate templateList = new DomainTemplate();
        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, "unknown",
                    auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        templateList.setTemplateNames(Collections.emptyList());
        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, "unknown",
                    auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateExtMultipleTemplate() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        String domainName = "templatelist-invalid";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        final String templateName = "vipng";
        DomainTemplate templateList = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add(templateName);
        templates.add("pes");
        templateList.setTemplateNames(templates);
        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, templateName,
                    auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateExtSingleTemplate() {

        String domainName = "templatelist-single";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        SubDomain domSysNetwork = zmsTestInitializer.createSubDomainObject("network", "sys", "Test Domain",
                "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postSubDomain(ctx, "sys", auditRef, null, domSysNetwork);

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        final String templateName = "vipng";
        DomainTemplate domTemplate = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add(templateName);
        domTemplate.setTemplateNames(templates);

        zmsImpl.putDomainTemplateExt(ctx, domainName, templateName, auditRef, domTemplate);

        // verify that our role collection includes the roles defined in template

        List<String> names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Role role = zmsImpl.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(domainName + ":role.vip_admin", role.getName());
        assertNull(role.getTrust());
        assertTrue(role.getRoleMembers().isEmpty());

        role = zmsImpl.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(domainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());

        // verify that our policy collections includes the policies defined in the template

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(3, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Policy policy = zmsImpl.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(domainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        policy = zmsImpl.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
        assertEquals(domainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(domainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(domainName + ":vip*", assertion.getResource());

        // delete an applied service template
        //
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        // verify that our role collection does NOT include the roles defined in template

        names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        zmsImpl.deleteSubDomain(ctx, "sys", "network", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetDomainTemplateListInvalid() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        try {
            zmsImpl.getDomainTemplateList(ctx, "invalid_domain name");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            zmsImpl.getDomainTemplateList(ctx, "not_found_domain_name");
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
    }

    @Test
    public void testGetDomainTemplateList() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "domaintemplatelist-valid";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // initially no templates

        DomainTemplateList domaintemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        List<String> templates = domaintemplateList.getTemplateNames();
        assertEquals(0, templates.size());

        // add a single template

        DomainTemplate domTemplate = new DomainTemplate();
        templates = new ArrayList<>();
        templates.add("user_provisioning");
        domTemplate.setTemplateNames(templates);

        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domTemplate);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(1, templates.size());
        assertTrue(templates.contains("user_provisioning"));

        // add 2 templates

        domTemplate = new DomainTemplate();
        templates = new ArrayList<>();
        templates.add("user_provisioning");
        templates.add("platforms");
        domTemplate.setTemplateNames(templates);

        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domTemplate);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(2, templates.size());
        assertTrue(templates.contains("user_provisioning"));
        assertTrue(templates.contains("platforms"));

        // add the same set of templates again and no change in results
        domTemplate = new DomainTemplate();
        domTemplate.setTemplateNames(templates);
        zmsImpl.putDomainTemplate(ctx, domainName, auditRef,
                domTemplate);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(2, templates.size());
        assertTrue(templates.contains("user_provisioning"));
        assertTrue(templates.contains("platforms"));

        // delete an applied service template
        //
        String templateName = "user_provisioning";
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(1, templates.size());
        assertTrue(templates.contains("platforms"));

        // delete last applied service template
        //
        templateName = "platforms";
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertTrue(templates.isEmpty());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPostSubDomainWithTemplates() {

        String domainName = "postsubdomain-withtemplate";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        SubDomain domSysNetwork = zmsTestInitializer.createSubDomainObject("network", "sys", "Test Domain",
                "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postSubDomain(ctx, "sys", auditRef, null, domSysNetwork);

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        SubDomain dom2 = zmsTestInitializer.createSubDomainObject("sub", domainName,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        DomainTemplateList templateList = new DomainTemplateList();
        List<String> templates = new ArrayList<>();
        templates.add("vipng");
        templates.add("platforms");
        templates.add("user_provisioning");
        templateList.setTemplateNames(templates);
        dom2.setTemplates(templateList);

        Domain resDom1 = zmsImpl.postSubDomain(ctx, domainName,
                auditRef, null, dom2);
        assertNotNull(resDom1);

        String subDomainName = domainName + ".sub";

        // verify that our role collection includes the roles defined in template

        List<String> names = zmsImpl.dbService.listRoles(subDomainName);
        assertEquals(7, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        Role role = zmsImpl.dbService.getRole(subDomainName, "openstack_readers", false, false, false);
        assertEquals(subDomainName + ":role.openstack_readers", role.getName());
        assertNull(role.getTrust());
        assertEquals(2, role.getRoleMembers().size());

        List<String> checkList = new ArrayList<>();
        checkList.add("sys.builder");
        checkList.add("sys.openstack");
        zmsTestInitializer.checkRoleMember(checkList, role.getRoleMembers());

        role = zmsImpl.dbService.getRole(subDomainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(subDomainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals("sys.network", role.getTrust());

        // verify that our policy collections includes the policies defined in the template

        names = zmsImpl.dbService.listPolicies(subDomainName);
        assertEquals(7, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        Policy policy = zmsImpl.dbService.getPolicy(subDomainName, "vip_admin", null);
        assertEquals(subDomainName + ":policy.vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(subDomainName + ":role.vip_admin", assertion.getRole());
        assertEquals(subDomainName + ":vip*", assertion.getResource());

        policy = zmsImpl.dbService.getPolicy(subDomainName, "sys_network_super_vip_admin", null);
        assertEquals(subDomainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(1, policy.getAssertions().size());
        assertion = policy.getAssertions().get(0);
        assertEquals("*", assertion.getAction());
        assertEquals(subDomainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(subDomainName + ":vip*", assertion.getResource());

        // verify the saved domain list

        DomainTemplateList domaintemplateList = zmsImpl.getDomainTemplateList(ctx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(3, templates.size());
        assertTrue(templates.contains("vipng"));
        assertTrue(templates.contains("platforms"));
        assertTrue(templates.contains("user_provisioning"));

        // delete an applied service template
        //
        String templateName = "vipng";
        zmsImpl.deleteDomainTemplate(ctx, subDomainName, templateName, auditRef);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(2, templates.size());
        assertTrue(templates.contains("platforms"));
        assertTrue(templates.contains("user_provisioning"));

        names = zmsImpl.dbService.listRoles(subDomainName);
        assertEquals(5, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zmsImpl.dbService.listPolicies(subDomainName);
        assertEquals(5, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        // delete an applied service template
        //
        templateName = "platforms";
        zmsImpl.deleteDomainTemplate(ctx, subDomainName, templateName, auditRef);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(1, templates.size());
        assertTrue(templates.contains("user_provisioning"));

        names = zmsImpl.dbService.listRoles(subDomainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zmsImpl.dbService.listPolicies(subDomainName);
        assertEquals(4, names.size());
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        // delete last applied service template
        //
        templateName = "user_provisioning";
        zmsImpl.deleteDomainTemplate(ctx, subDomainName, templateName, auditRef);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertTrue(templates.isEmpty());

        names = zmsImpl.dbService.listRoles(subDomainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        names = zmsImpl.dbService.listPolicies(subDomainName);
        assertEquals(1, names.size());
        assertTrue(names.contains("admin"));

        zmsImpl.deleteSubDomain(ctx, "sys", "network", auditRef, null);
        zmsImpl.deleteSubDomain(ctx, domainName, "sub", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateWithInvalidRoleNameSubstitution() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        String domainName = "github-actions-invalid-role-name";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        final String templateName = "github_actions_test";
        DomainTemplate templateList = new DomainTemplate();
        List<String> templateNames = new ArrayList<>();
        templateNames.add(templateName);
        templateList.setTemplateNames(templateNames);

        // the keywords to be specified for the rule substitution
        // "keywordsToReplace": "_event_,_service_,_member-service_,_role_,_rule-role_,_git-resource_",

        // we're going to create an invalid role name substitution

        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("event").setValue("push"));
        params.add(new TemplateParam().setName("service").setValue("api"));
        params.add(new TemplateParam().setName("member-service").setValue("api"));
        params.add(new TemplateParam().setName("role").setValue("api-role(1)"));
        params.add(new TemplateParam().setName("rule-role").setValue("api-rule-role"));
        params.add(new TemplateParam().setName("git-resource").setValue("repo:athenz/athenz:ref:refs/heads/main"));

        templateList.setParams(params);

        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, templateName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid Role error: String pattern mismatch"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateWithInvalidRoleMemberSubstitution() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        String domainName = "github-actions-invalid-role-member";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        final String templateName = "github_actions_test";
        DomainTemplate templateList = new DomainTemplate();
        List<String> templateNames = new ArrayList<>();
        templateNames.add(templateName);
        templateList.setTemplateNames(templateNames);

        // the keywords to be specified for the rule substitution
        // "keywordsToReplace": "_event_,_service_,_member-service_,_role_,_rule-role_,_git-resource_",

        // we're going to create an invalid role member substitution

        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("event").setValue("push"));
        params.add(new TemplateParam().setName("service").setValue("api"));
        params.add(new TemplateParam().setName("member-service").setValue("api(1)"));
        params.add(new TemplateParam().setName("role").setValue("api-role"));
        params.add(new TemplateParam().setName("rule-role").setValue("api-rule-role"));
        params.add(new TemplateParam().setName("git-resource").setValue("repo:athenz/athenz:ref:refs/heads/main"));

        templateList.setParams(params);

        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, templateName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid Role error: String pattern mismatch"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateWithInvalidServiceSubstitution() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        String domainName = "github-actions-invalid-service";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        final String templateName = "github_actions_test";
        DomainTemplate templateList = new DomainTemplate();
        List<String> templateNames = new ArrayList<>();
        templateNames.add(templateName);
        templateList.setTemplateNames(templateNames);

        // the keywords to be specified for the rule substitution
        // "keywordsToReplace": "_event_,_service_,_member-service_,_role_,_rule-role_,_git-resource_",

        // we're going to create an invalid service name substitution

        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("event").setValue("push"));
        params.add(new TemplateParam().setName("service").setValue("api(1)"));
        params.add(new TemplateParam().setName("member-service").setValue("api"));
        params.add(new TemplateParam().setName("role").setValue("api-role"));
        params.add(new TemplateParam().setName("rule-role").setValue("api-rule-role"));
        params.add(new TemplateParam().setName("git-resource").setValue("repo:athenz/athenz:ref:refs/heads/main"));

        templateList.setParams(params);

        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, templateName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid ServiceIdentity error: String pattern mismatch"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateWithInvalidPolicyRuleRoleSubstitution() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        String domainName = "github-actions-invalid-policy-rule-role";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        final String templateName = "github_actions_test";
        DomainTemplate templateList = new DomainTemplate();
        List<String> templateNames = new ArrayList<>();
        templateNames.add(templateName);
        templateList.setTemplateNames(templateNames);

        // the keywords to be specified for the rule substitution
        // "keywordsToReplace": "_event_,_service_,_member-service_,_role_,_rule-role_,_git-resource_",

        // we're going to create an invalid assertion role name substitution

        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("event").setValue("push"));
        params.add(new TemplateParam().setName("service").setValue("api"));
        params.add(new TemplateParam().setName("member-service").setValue("api"));
        params.add(new TemplateParam().setName("role").setValue("api-role"));
        params.add(new TemplateParam().setName("rule-role").setValue("api-rule-role(1)"));
        params.add(new TemplateParam().setName("git-resource").setValue("repo:athenz/athenz:ref:refs/heads/main"));

        templateList.setParams(params);

        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, templateName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid ResourceName error: String pattern mismatch"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
