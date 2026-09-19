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

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.store.ObjectStoreConnection;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.config.SolutionTemplates;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import org.testng.annotations.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
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
    public void shutDown() throws Exception {
        zmsTestInitializer.shutDown();
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
            assertEquals(ex.getCode(), 400);
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
            assertEquals(ex.getCode(), 404);
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
        assertEquals(names.size(), 3);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Role role = zmsImpl.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(role.getName(), domainName + ":role.vip_admin");
        assertNull(role.getTrust());
        assertTrue(role.getRoleMembers().isEmpty());

        role = zmsImpl.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(role.getName(), domainName + ":role.sys_network_super_vip_admin");
        assertEquals(role.getTrust(), "sys.network");

        // verify that our policy collections includes the policies defined in the template

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(names.size(), 3);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Policy policy = zmsImpl.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(policy.getName(), domainName + ":policy.vip_admin");
        assertEquals(policy.getAssertions().size(), 1);
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getAction(), "*");
        assertEquals(assertion.getRole(), domainName + ":role.vip_admin");
        assertEquals(assertion.getResource(), domainName + ":vip*");

        policy = zmsImpl.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
        assertEquals(policy.getName(), domainName + ":policy.sys_network_super_vip_admin");
        assertEquals(policy.getAssertions().size(), 1);
        assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getAction(), "*");
        assertEquals(assertion.getRole(), domainName + ":role.sys_network_super_vip_admin");
        assertEquals(assertion.getResource(), domainName + ":vip*");

        // delete an applied service template
        //
        String templateName = "vipng";
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        // verify that our role collection does NOT include the roles defined in template

        names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(names.size(), 1);
        assertTrue(names.contains("admin"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(names.size(), 1);
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
        assertEquals(names.size(), 7);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        Role role = zmsImpl.dbService.getRole(domainName, "openstack_readers", false, false, false);
        assertEquals(role.getName(), domainName + ":role.openstack_readers");
        assertNull(role.getTrust());
        assertEquals(role.getRoleMembers().size(), 2);

        List<String> checkList = new ArrayList<>();
        checkList.add("sys.builder");
        checkList.add("sys.openstack");
        zmsTestInitializer.checkRoleMember(checkList, role.getRoleMembers());

        role = zmsImpl.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(role.getName(), domainName + ":role.sys_network_super_vip_admin");
        assertEquals(role.getTrust(), "sys.network");

        // verify that our policy collections includes the policies defined in the template

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(names.size(), 7);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        Policy policy = zmsImpl.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(policy.getName(), domainName + ":policy.vip_admin");
        assertEquals(policy.getAssertions().size(), 1);
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getAction(), "*");
        assertEquals(assertion.getRole(), domainName + ":role.vip_admin");
        assertEquals(assertion.getResource(), domainName + ":vip*");

        policy = zmsImpl.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
        assertEquals(policy.getName(), domainName + ":policy.sys_network_super_vip_admin");
        assertEquals(policy.getAssertions().size(), 1);
        assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getAction(), "*");
        assertEquals(assertion.getRole(), domainName + ":role.sys_network_super_vip_admin");
        assertEquals(assertion.getResource(), domainName + ":vip*");

        // delete applied service template
        //
        String templateName = "vipng";
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        // verify that our role collection does NOT include the vipng roles defined in template

        names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(names.size(), 5);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(names.size(), 5);
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
        assertEquals(names.size(), 4);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(names.size(), 4);
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
        assertEquals(names.size(), 1);
        assertTrue(names.contains("admin"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(names.size(), 1);
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
            assertEquals(ex.getCode(), 400);
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
            assertEquals(ex.getCode(), 404);
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
            assertEquals(ex.getCode(), 400);
        }

        templateList.setTemplateNames(Collections.emptyList());
        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, "unknown",
                    auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
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
            assertEquals(ex.getCode(), 400);
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
        assertEquals(names.size(), 3);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Role role = zmsImpl.dbService.getRole(domainName, "vip_admin", false, false, false);
        assertEquals(role.getName(), domainName + ":role.vip_admin");
        assertNull(role.getTrust());
        assertTrue(role.getRoleMembers().isEmpty());

        role = zmsImpl.dbService.getRole(domainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(role.getName(), domainName + ":role.sys_network_super_vip_admin");
        assertEquals(role.getTrust(), "sys.network");

        // verify that our policy collections includes the policies defined in the template

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(names.size(), 3);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));

        Policy policy = zmsImpl.dbService.getPolicy(domainName, "vip_admin", null);
        assertEquals(policy.getName(), domainName + ":policy.vip_admin");
        assertEquals(policy.getAssertions().size(), 1);
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getAction(), "*");
        assertEquals(assertion.getRole(), domainName + ":role.vip_admin");
        assertEquals(assertion.getResource(), domainName + ":vip*");

        policy = zmsImpl.dbService.getPolicy(domainName, "sys_network_super_vip_admin", null);
        assertEquals(policy.getName(), domainName + ":policy.sys_network_super_vip_admin");
        assertEquals(policy.getAssertions().size(), 1);
        assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getAction(), "*");
        assertEquals(assertion.getRole(), domainName + ":role.sys_network_super_vip_admin");
        assertEquals(assertion.getResource(), domainName + ":vip*");

        // delete an applied service template
        //
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        // verify that our role collection does NOT include the roles defined in template

        names = zmsImpl.dbService.listRoles(domainName);
        assertEquals(names.size(), 1);
        assertTrue(names.contains("admin"));

        names = zmsImpl.dbService.listPolicies(domainName);
        assertEquals(names.size(), 1);
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
            assertEquals(ex.getCode(), 400);
        }

        try {
            zmsImpl.getDomainTemplateList(ctx, "not_found_domain_name");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
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
        assertEquals(templates.size(), 0);

        // add a single template

        DomainTemplate domTemplate = new DomainTemplate();
        templates = new ArrayList<>();
        templates.add("user_provisioning");
        domTemplate.setTemplateNames(templates);

        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domTemplate);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(templates.size(), 1);
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
        assertEquals(templates.size(), 2);
        assertTrue(templates.contains("user_provisioning"));
        assertTrue(templates.contains("platforms"));

        // add the same set of templates again and no change in results
        domTemplate = new DomainTemplate();
        domTemplate.setTemplateNames(templates);
        zmsImpl.putDomainTemplate(ctx, domainName, auditRef,
                domTemplate);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(templates.size(), 2);
        assertTrue(templates.contains("user_provisioning"));
        assertTrue(templates.contains("platforms"));

        // delete an applied service template
        //
        String templateName = "user_provisioning";
        zmsImpl.deleteDomainTemplate(ctx, domainName, templateName, auditRef);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(templates.size(), 1);
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
        assertEquals(names.size(), 7);
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
        assertEquals(role.getRoleMembers().size(), 2);

        List<String> checkList = new ArrayList<>();
        checkList.add("sys.builder");
        checkList.add("sys.openstack");
        zmsTestInitializer.checkRoleMember(checkList, role.getRoleMembers());

        role = zmsImpl.dbService.getRole(subDomainName, "sys_network_super_vip_admin", false, false, false);
        assertEquals(subDomainName + ":role.sys_network_super_vip_admin", role.getName());
        assertEquals(role.getTrust(), "sys.network");

        // verify that our policy collections includes the policies defined in the template

        names = zmsImpl.dbService.listPolicies(subDomainName);
        assertEquals(names.size(), 7);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("vip_admin"));
        assertTrue(names.contains("sys_network_super_vip_admin"));
        assertTrue(names.contains("platforms_deploy"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        Policy policy = zmsImpl.dbService.getPolicy(subDomainName, "vip_admin", null);
        assertEquals(subDomainName + ":policy.vip_admin", policy.getName());
        assertEquals(policy.getAssertions().size(), 1);
        Assertion assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getAction(), "*");
        assertEquals(subDomainName + ":role.vip_admin", assertion.getRole());
        assertEquals(subDomainName + ":vip*", assertion.getResource());

        policy = zmsImpl.dbService.getPolicy(subDomainName, "sys_network_super_vip_admin", null);
        assertEquals(subDomainName + ":policy.sys_network_super_vip_admin", policy.getName());
        assertEquals(policy.getAssertions().size(), 1);
        assertion = policy.getAssertions().get(0);
        assertEquals(assertion.getAction(), "*");
        assertEquals(subDomainName + ":role.sys_network_super_vip_admin", assertion.getRole());
        assertEquals(subDomainName + ":vip*", assertion.getResource());

        // verify the saved domain list

        DomainTemplateList domaintemplateList = zmsImpl.getDomainTemplateList(ctx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(templates.size(), 3);
        assertTrue(templates.contains("vipng"));
        assertTrue(templates.contains("platforms"));
        assertTrue(templates.contains("user_provisioning"));

        // delete an applied service template
        //
        String templateName = "vipng";
        zmsImpl.deleteDomainTemplate(ctx, subDomainName, templateName, auditRef);

        domaintemplateList = zmsImpl.getDomainTemplateList(ctx, subDomainName);
        templates = domaintemplateList.getTemplateNames();
        assertEquals(templates.size(), 2);
        assertTrue(templates.contains("platforms"));
        assertTrue(templates.contains("user_provisioning"));

        names = zmsImpl.dbService.listRoles(subDomainName);
        assertEquals(names.size(), 5);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("platforms_deployer"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zmsImpl.dbService.listPolicies(subDomainName);
        assertEquals(names.size(), 5);
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
        assertEquals(templates.size(), 1);
        assertTrue(templates.contains("user_provisioning"));

        names = zmsImpl.dbService.listRoles(subDomainName);
        assertEquals(names.size(), 4);
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("user"));
        assertTrue(names.contains("superuser"));
        assertTrue(names.contains("openstack_readers"));

        names = zmsImpl.dbService.listPolicies(subDomainName);
        assertEquals(names.size(), 4);
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
        assertEquals(names.size(), 1);
        assertTrue(names.contains("admin"));

        names = zmsImpl.dbService.listPolicies(subDomainName);
        assertEquals(names.size(), 1);
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
            assertEquals(ex.getCode(), 400);
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
            assertEquals(ex.getCode(), 400);
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
            assertEquals(ex.getCode(), 400);
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
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid ResourceName error: String pattern mismatch"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateWithInvalidServiceName() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        String domainName = "template-invalid-service-name";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        final String templateName = "template_service_test";
        DomainTemplate templateList = new DomainTemplate();
        List<String> templateNames = new ArrayList<>();
        templateNames.add(templateName);
        templateList.setTemplateNames(templateNames);

        // the keywords to be specified for the rule substitution
        // "keywordsToReplace": "_service_"

        // we're going to create an invalid service name

        List<TemplateParam> params = new ArrayList<>();
        params.add(new TemplateParam().setName("service").setValue("api.service"));
        templateList.setParams(params);

        try {
            zmsImpl.putDomainTemplateExt(ctx, domainName, templateName, auditRef, templateList);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid SimpleName error: String pattern mismatch"));
        }

        // verify simple service name is successful

        params = new ArrayList<>();
        params.add(new TemplateParam().setName("service").setValue("api"));
        templateList.setParams(params);

        zmsImpl.putDomainTemplateExt(ctx, domainName, templateName, auditRef, templateList);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testDeleteDomainTemplateWithGroupNoExternalRef() {

        String domainName = "templatelist-delgroup-noref";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // apply template_with_group which has a group named _domain_:group.tmpl_test_group

        DomainTemplate domTemplate = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add("template_with_group");
        domTemplate.setTemplateNames(templates);
        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domTemplate);

        // add the template group as a member to a role in the same domain only

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null, "user.john",
                ResourceUtils.groupResourceName(domainName, "tmpl_test_group"));
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        // delete the template - should succeed since the group is only
        // referenced by roles in the same domain

        zmsImpl.deleteDomainTemplate(ctx, domainName, "template_with_group", auditRef);

        // verify the template has been removed

        DomainTemplateList domainTemplateList = zmsImpl.getDomainTemplateList(ctx, domainName);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testDeleteDomainTemplateWithGroupExternalRef() {

        String domainName1 = "templatelist-delgroup-extref1";
        String domainName2 = "templatelist-delgroup-extref2";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        // apply template_with_group which has a group named _domain_:group.tmpl_test_group

        DomainTemplate domTemplate = new DomainTemplate();
        List<String> templates = new ArrayList<>();
        templates.add("template_with_group");
        domTemplate.setTemplateNames(templates);
        zmsImpl.putDomainTemplate(ctx, domainName1, auditRef, domTemplate);

        // add the template group as a member to a role in a different domain

        Role role2 = zmsTestInitializer.createRoleObject(domainName2, "role2", null, "user.john",
                ResourceUtils.groupResourceName(domainName1, "tmpl_test_group"));
        zmsImpl.putRole(ctx, domainName2, "role2", auditRef, false, null, role2);

        // delete the template - should fail since the group is
        // referenced by a role in another domain

        try {
            zmsImpl.deleteDomainTemplate(ctx, domainName1, "template_with_group", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains(ResourceUtils.roleResourceName(domainName2, "role2")));
        }

        // remove the cross-domain reference and try again

        zmsImpl.deleteRole(ctx, domainName2, "role2", auditRef, null);

        // now the deletion should succeed

        zmsImpl.deleteDomainTemplate(ctx, domainName1, "template_with_group", auditRef);

        DomainTemplateList domainTemplateList = zmsImpl.getDomainTemplateList(ctx, domainName1);
        assertTrue(domainTemplateList.getTemplateNames().isEmpty());

        zmsImpl.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName1, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateReplaceAdminWithTrust() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-replacement";
        final String trustDomain = "template-admin-replacement-trust";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);
        createAdminDelegation(zmsImpl, ctx, trustDomain, domainName,
                ctx.principal().getFullName(), auditRef);

        DomainTemplate domainTemplate = createAdminTrustTemplate(zmsImpl, trustDomain);
        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domainTemplate);

        Role adminRole = zmsImpl.getRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME,
                false, false, false);
        assertEquals(adminRole.getTrust(), trustDomain);
        assertTrue(ZMSUtils.isCollectionEmpty(adminRole.getRoleMembers()));
        assertNotNull(zmsImpl.getRole(ctx, domainName, "template-created-role", false, false, false));
        assertStoredAdminMembers(zmsImpl, domainName, 0);

        // Reapplying the template is safe once the same clean trust
        // handoff is already in place.

        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domainTemplate);
        assertStoredAdminMembers(zmsImpl, domainName, 0);

        // Verify that the requester can still administer the domain through
        // the delegated trust path after its direct admin membership is removed.

        Role newRole = zmsTestInitializer.createRoleObject(domainName, "post-handoff-role",
                null, ctx.principal().getFullName(), null);
        zmsImpl.putRole(ctx, domainName, "post-handoff-role", auditRef, false, null, newRole);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateReplaceAdminWithTrustThroughGroup() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-group-replacement";
        final String trustDomain = "template-admin-group-replacement-trust";
        final String groupName = "delegated-admins";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);

        Group group = zmsTestInitializer.createGroupObject(trustDomain, groupName,
                ctx.principal().getFullName(), null);
        zmsImpl.putGroup(ctx, trustDomain, groupName, auditRef, false, null, group);
        createAdminDelegation(zmsImpl, ctx, trustDomain, domainName,
                ResourceUtils.groupResourceName(trustDomain, groupName), auditRef);

        zmsImpl.putDomainTemplateExt(ctx, domainName, "template_admin_trust", auditRef,
                createAdminTrustTemplate(zmsImpl, trustDomain));

        Role adminRole = zmsImpl.getRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME,
                false, false, false);
        assertEquals(adminRole.getTrust(), trustDomain);
        assertTrue(ZMSUtils.isCollectionEmpty(adminRole.getRoleMembers()));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateWithoutAdminTrustPreservesMembers() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-regular-merge";
        createDomain(zmsImpl, ctx, domainName, auditRef);

        Role templateAdmin = zmsTestInitializer.createRoleObject("_domain_", ZMSConsts.ADMIN_ROLE_NAME,
                null, "user.user2", null);
        installTemplate(zmsImpl, "template_admin_regular", Collections.singletonList(templateAdmin));

        zmsImpl.putDomainTemplate(ctx, domainName, auditRef,
                new DomainTemplate().setTemplateNames(new ArrayList<>(Collections.singletonList("template_admin_regular"))));

        Role adminRole = zmsImpl.getRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME,
                false, false, false);
        assertNull(adminRole.getTrust());
        assertEquals(adminRole.getRoleMembers().size(), 2);
        zmsTestInitializer.checkRoleMember(Arrays.asList(ctx.principal().getFullName(), "user.user2"),
                adminRole.getRoleMembers());
        assertStoredAdminMembers(zmsImpl, domainName, 2);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateAdminTrustWithParameterizedRoleName() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-name-param";
        final String trustDomain = "template-admin-name-param-trust";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);
        createAdminDelegation(zmsImpl, ctx, trustDomain, domainName,
                ctx.principal().getFullName(), auditRef);

        Role templateAdmin = new Role().setName("_domain_:role._role-name_").setTrust("_trust-domain_");
        installTemplate(zmsImpl, "template_admin_parameterized", Collections.singletonList(templateAdmin));
        DomainTemplate domainTemplate = new DomainTemplate()
                .setTemplateNames(new ArrayList<>(Collections.singletonList("template_admin_parameterized")))
                .setParams(Arrays.asList(new TemplateParam().setName("role-name").setValue("admin"),
                        new TemplateParam().setName("trust-domain").setValue(trustDomain)));

        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domainTemplate);
        assertEquals(zmsImpl.getRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME, false, false, false)
                .getTrust(), trustDomain);
        assertStoredAdminMembers(zmsImpl, domainName, 0);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateNonAdminTrustPreservesMembers() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-non-admin-trust";
        final String trustDomain = "template-non-admin-trust-domain";
        final String roleName = "delegated-role";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null,
                zmsTestInitializer.createRoleObject(domainName, roleName, null,
                        ctx.principal().getFullName(), null));

        Role templateRole = new Role().setName("_domain_:role._role-name_").setTrust(trustDomain);
        installTemplate(zmsImpl, "template_non_admin_trust", Collections.singletonList(templateRole));
        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, new DomainTemplate()
                .setTemplateNames(new ArrayList<>(Collections.singletonList("template_non_admin_trust")))
                .setParams(Collections.singletonList(new TemplateParam().setName("role-name").setValue(roleName))));

        assertEquals(zmsImpl.getRole(ctx, domainName, roleName, false, false, false).getTrust(), trustDomain);
        try (ObjectStoreConnection con = zmsImpl.dbService.store.getConnection(true, false)) {
            assertEquals(con.countRoleMembers(domainName, roleName), 1);
        }
        assertAdminMemberUnchanged(zmsImpl, ctx, domainName);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
    }

    @DataProvider(name = "adminTrustDomainCreation")
    public Object[][] adminTrustDomainCreation() {
        return new Object[][] {{true, false}, {false, false}, {true, true}};
    }

    @Test(dataProvider = "adminTrustDomainCreation")
    public void testPostTopLevelDomainWithAdminTrust(boolean delegatedAccess, boolean additionalAdmin)
            throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-new-domain-admin-trust-" + delegatedAccess + "-" + additionalAdmin;
        final String trustDomain = domainName + "-source";
        createDomain(zmsImpl, ctx, trustDomain, auditRef);
        if (delegatedAccess) {
            createAdminDelegation(zmsImpl, ctx, trustDomain, domainName,
                    ctx.principal().getFullName(), auditRef);
        }
        installTemplate(zmsImpl, "template_admin_trust", Collections.singletonList(
                new Role().setName("_domain_:role.admin").setTrust(trustDomain)));
        TopLevelDomain domain = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Template Admin Test Domain", "testOrg", ctx.principal().getFullName());
        if (additionalAdmin) {
            domain.setAdminUsers(Arrays.asList(ctx.principal().getFullName(), "user.user2"));
        }
        domain.setTemplates(new DomainTemplateList()
                .setTemplateNames(new ArrayList<>(Collections.singletonList("template_admin_trust"))));

        if (delegatedAccess && !additionalAdmin) {
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, domain);
            assertEquals(zmsImpl.getRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME, false, false, false)
                    .getTrust(), trustDomain);
            assertStoredAdminMembers(zmsImpl, domainName, 0);
            zmsImpl.putRole(ctx, domainName, "post-handoff-role", auditRef, false, null,
                    zmsTestInitializer.createRoleObject(domainName, "post-handoff-role", null,
                            ctx.principal().getFullName(), null));
            zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        } else {
            try {
                zmsImpl.postTopLevelDomain(ctx, auditRef, null, domain);
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 400);
                assertTrue(ex.getMessage().contains(additionalAdmin ? "requester must be the sole admin member"
                        : "requester does not have delegated access"));
            }
            try {
                zmsImpl.getDomain(ctx, domainName);
                fail();
            } catch (ResourceException ex) {
                assertEquals(ex.getCode(), 404);
            }
        }

        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateReplaceProtectedAdminMember() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-delete-protection";
        final String trustDomain = "template-admin-delete-protection-trust";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);
        createAdminDelegation(zmsImpl, ctx, trustDomain, domainName,
                ctx.principal().getFullName(), auditRef);

        Role adminRole = zmsImpl.getRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME,
                false, false, false)
                .setReviewEnabled(true)
                .setDeleteProtection(true);
        zmsImpl.putRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME, auditRef,
                false, null, adminRole);

        zmsImpl.putDomainTemplate(ctx, domainName, auditRef,
                createAdminTrustTemplate(zmsImpl, trustDomain));

        Role updatedAdminRole = zmsImpl.getRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME,
                false, false, true);
        assertEquals(updatedAdminRole.getTrust(), trustDomain);
        assertTrue(ZMSUtils.isCollectionEmpty(updatedAdminRole.getRoleMembers()));
        assertStoredAdminMembers(zmsImpl, domainName, 0);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateReplaceAdminRequiresCurrentRegularRole() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-already-trusted";
        final String trustDomain = "template-admin-already-trusted-trust";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);
        createAdminDelegation(zmsImpl, ctx, trustDomain, domainName,
                ctx.principal().getFullName(), auditRef);

        // Reproduce the mixed state retained by older template applications.
        try (ObjectStoreConnection con = zmsImpl.dbService.store.getConnection(false, true)) {
            Role adminRole = con.getRole(domainName, ZMSConsts.ADMIN_ROLE_NAME);
            assertTrue(con.updateRole(domainName, adminRole.setTrust(trustDomain)));
            zmsImpl.dbService.saveChanges(con, domainName);
        }

        try {
            zmsImpl.putDomainTemplate(ctx, domainName, auditRef,
                    createAdminTrustTemplate(zmsImpl, trustDomain));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("current admin role must be a regular role"));
        }

        Role adminRole = zmsImpl.getRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME,
                false, false, false);
        assertEquals(adminRole.getTrust(), trustDomain);
        assertStoredAdminMembers(zmsImpl, domainName, 1);
        assertAdminTrustTemplateNotApplied(zmsImpl, ctx, domainName);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateReplaceAdminRequiresDelegatedAccess() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-no-delegation";
        final String trustDomain = "template-admin-no-delegation-trust";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);

        try {
            zmsImpl.putDomainTemplate(ctx, domainName, auditRef,
                    createAdminTrustTemplate(zmsImpl, trustDomain));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("requester does not have delegated access"));
        }

        assertAdminMemberUnchanged(zmsImpl, ctx, domainName);
        assertAdminTrustTemplateNotApplied(zmsImpl, ctx, domainName);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateReplaceAdminRequiresSoleRequester() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-multiple-members";
        final String trustDomain = "template-admin-multiple-members-trust";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);

        Role adminRole = zmsTestInitializer.createRoleObject(domainName, ZMSConsts.ADMIN_ROLE_NAME,
                null, ctx.principal().getFullName(), "user.user2");
        zmsImpl.putRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME, auditRef, false, null, adminRole);

        try {
            zmsImpl.putDomainTemplate(ctx, domainName, auditRef,
                    createAdminTrustTemplate(zmsImpl, trustDomain));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("requester must be the sole admin member"));
        }

        assertAdminTrustTemplateNotApplied(zmsImpl, ctx, domainName);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateReplaceAdminRejectsPendingAdminMember() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-pending-member";
        final String trustDomain = "template-admin-pending-member-trust";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);

        Role adminRole = zmsTestInitializer.createRoleObject(domainName, ZMSConsts.ADMIN_ROLE_NAME,
                null, ctx.principal().getFullName(), "user.user2").setReviewEnabled(true);
        zmsImpl.putRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME, auditRef, false, null, adminRole);

        try {
            zmsImpl.putDomainTemplate(ctx, domainName, auditRef,
                    createAdminTrustTemplate(zmsImpl, trustDomain));
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("requester must be the sole admin member"));
        }

        assertAdminTrustTemplateNotApplied(zmsImpl, ctx, domainName);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainTemplateReplaceAdminRejectsInvalidTemplates() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-invalid-template";
        final String trustDomain = "template-admin-invalid-template-trust";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);

        DomainTemplate domainTemplate = createAdminTrustTemplate(zmsImpl, trustDomain);
        domainTemplate.setTemplateNames(new ArrayList<>(Arrays.asList(
                "template_admin_trust", "template_admin_trust")));
        assertAdminReplacementError(zmsImpl, ctx, domainName, auditRef, domainTemplate,
                "multiple admin roles are defined");

        Role adminWithoutTrust = zmsTestInitializer.createRoleObject("_domain_",
                ZMSConsts.ADMIN_ROLE_NAME, null, null, null);
        installTemplate(zmsImpl, "template_admin_regular", Collections.singletonList(adminWithoutTrust));
        domainTemplate.setTemplateNames(Arrays.asList("template_admin_regular", "template_admin_trust"));
        assertAdminReplacementError(zmsImpl, ctx, domainName, auditRef, domainTemplate,
                "multiple admin roles are defined");
        domainTemplate.setTemplateNames(Arrays.asList("template_admin_trust", "template_admin_regular"));
        assertAdminReplacementError(zmsImpl, ctx, domainName, auditRef, domainTemplate,
                "multiple admin roles are defined");

        Role adminWithMember = zmsTestInitializer.createRoleObject("_domain_",
                ZMSConsts.ADMIN_ROLE_NAME, trustDomain, ctx.principal().getFullName(), null);
        domainTemplate.setTemplateNames(new ArrayList<>(Collections.singletonList("admin-with-member")));
        assertAdminReplacementError(zmsImpl, ctx, domainName, domainTemplate,
                solutionTemplates("admin-with-member", adminWithMember),
                "template admin role cannot define members");

        Role adminWithLegacyMember = new Role().setName("_domain_:role.admin")
                .setTrust(trustDomain)
                .setMembers(Collections.singletonList(ctx.principal().getFullName()));
        domainTemplate.setTemplateNames(new ArrayList<>(Collections.singletonList("admin-with-legacy-member")));
        assertAdminReplacementError(zmsImpl, ctx, domainName, domainTemplate,
                solutionTemplates("admin-with-legacy-member", adminWithLegacyMember),
                "template admin role cannot define members");

        assertAdminMemberUnchanged(zmsImpl, ctx, domainName);
        assertAdminTrustTemplateNotApplied(zmsImpl, ctx, domainName);
        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testBackgroundTemplateApplicationCannotReplaceAdmin() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String domainName = "template-admin-background";
        final String trustDomain = "template-admin-background-trust";
        createDomain(zmsImpl, ctx, domainName, auditRef);
        createDomain(zmsImpl, ctx, trustDomain, auditRef);

        try {
            zmsImpl.dbService.executePutDomainTemplate(null, domainName,
                    createAdminTrustTemplate(zmsImpl, trustDomain), auditRef, "background-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("authenticated requester is required"));
        }

        assertAdminMemberUnchanged(zmsImpl, ctx, domainName);
        assertAdminTrustTemplateNotApplied(zmsImpl, ctx, domainName);

        // A background update may reapply the template after an authenticated
        // requester has already completed the handoff.

        createAdminDelegation(zmsImpl, ctx, trustDomain, domainName,
                ctx.principal().getFullName(), auditRef);
        DomainTemplate domainTemplate = createAdminTrustTemplate(zmsImpl, trustDomain);
        zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domainTemplate);
        zmsImpl.dbService.executePutDomainTemplate(null, domainName, domainTemplate,
                auditRef, "background-test");
        assertStoredAdminMembers(zmsImpl, domainName, 0);

        zmsImpl.deleteTopLevelDomain(ctx, trustDomain, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    private void createDomain(ZMSImpl zmsImpl, RsrcCtxWrapper ctx, String domainName, String auditRef) {
        TopLevelDomain domain = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Template Admin Test Domain", "testOrg", ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, domain);
    }

    private void createAdminDelegation(ZMSImpl zmsImpl, RsrcCtxWrapper ctx, String trustDomain,
            String targetDomain, String roleMember, String auditRef) {

        final String roleName = "delegated-admins";
        Role role = zmsTestInitializer.createRoleObject(trustDomain, roleName, null, roleMember, null);
        zmsImpl.putRole(ctx, trustDomain, roleName, auditRef, false, null, role);
        Policy policy = zmsTestInitializer.createPolicyObject(trustDomain, "delegated-admin-policy",
                roleName, "assume_role", ResourceUtils.roleResourceName(targetDomain,
                        ZMSConsts.ADMIN_ROLE_NAME), AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, trustDomain, "delegated-admin-policy", auditRef, false, null, policy);
    }

    private DomainTemplate createAdminTrustTemplate(ZMSImpl zmsImpl, String trustDomain) {
        installAdminTrustTemplate(zmsImpl);
        return new DomainTemplate()
                .setTemplateNames(new ArrayList<>(Collections.singletonList("template_admin_trust")))
                .setParams(new ArrayList<>(Collections.singletonList(new TemplateParam()
                        .setName("trust-domain").setValue(trustDomain))));
    }

    private void installAdminTrustTemplate(ZMSImpl zmsImpl) {
        Role createdRole = new Role().setName("_domain_:role.template-created-role")
                .setRoleMembers(Collections.emptyList());
        Role adminRole = new Role().setName("_domain_:role.admin").setTrust("_trust-domain_");
        installTemplate(zmsImpl, "template_admin_trust",
                Arrays.asList(createdRole, adminRole));
    }

    private void installTemplate(ZMSImpl zmsImpl, String templateName, List<Role> roles) {
        SolutionTemplatesSnapshot snapshot = zmsImpl.getSolutionTemplatesSnapshot();
        HashMap<String, Template> templates = new HashMap<>(snapshot.templates.getTemplates());
        TemplateMetaData metadata = new TemplateMetaData().setLatestVersion(1);
        Template template = new Template()
                .setRoles(roles)
                .setPolicies(Collections.emptyList())
                .setMetadata(metadata);
        templates.put(templateName, template);
        SolutionTemplates solutionTemplates = new SolutionTemplates();
        solutionTemplates.setTemplates(templates);
        zmsImpl.solutionTemplatesManager().setServerSolutionTemplates(solutionTemplates,
                snapshot.path, snapshot.modifiedMillis);
    }

    private SolutionTemplates solutionTemplates(String templateName, Role role) {
        Template template = new Template()
                .setRoles(Collections.singletonList(role))
                .setPolicies(Collections.emptyList())
                .setMetadata(new TemplateMetaData());
        HashMap<String, Template> templates = new HashMap<>();
        templates.put(templateName, template);
        SolutionTemplates solutionTemplates = new SolutionTemplates();
        solutionTemplates.setTemplates(templates);
        return solutionTemplates;
    }

    private void assertAdminReplacementError(ZMSImpl zmsImpl, RsrcCtxWrapper ctx, String domainName,
            String auditRef, DomainTemplate domainTemplate, String errorMessage) {
        try {
            zmsImpl.putDomainTemplate(ctx, domainName, auditRef, domainTemplate);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains(errorMessage));
        }
    }

    private void assertAdminReplacementError(ZMSImpl zmsImpl, RsrcCtxWrapper ctx, String domainName,
            DomainTemplate domainTemplate, SolutionTemplates solutionTemplates, String errorMessage) {
        try {
            zmsImpl.dbService.validateAdminTrustReplacement(domainName, domainTemplate,
                    ctx.principal().getFullName(), "test", solutionTemplates);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains(errorMessage));
        }
    }

    private void assertAdminMemberUnchanged(ZMSImpl zmsImpl, RsrcCtxWrapper ctx, String domainName) {
        Role adminRole = zmsImpl.getRole(ctx, domainName, ZMSConsts.ADMIN_ROLE_NAME,
                false, false, false);
        assertNull(adminRole.getTrust());
        assertEquals(adminRole.getRoleMembers().size(), 1);
        assertEquals(adminRole.getRoleMembers().get(0).getMemberName(), ctx.principal().getFullName());
    }

    private void assertAdminTrustTemplateNotApplied(ZMSImpl zmsImpl, RsrcCtxWrapper ctx, String domainName) {
        try {
            zmsImpl.getRole(ctx, domainName, "template-created-role", false, false, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        assertFalse(zmsImpl.getDomainTemplateList(ctx, domainName).getTemplateNames()
                .contains("template_admin_trust"));
    }

    private void assertStoredAdminMembers(ZMSImpl zmsImpl, String domainName, int expected)
            throws ServerResourceException {
        try (ObjectStoreConnection con = zmsImpl.dbService.store.getConnection(true, false)) {
            assertEquals(con.countRoleMembers(domainName, ZMSConsts.ADMIN_ROLE_NAME), expected);
        }
    }
}
