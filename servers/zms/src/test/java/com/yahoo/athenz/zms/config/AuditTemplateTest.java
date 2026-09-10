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
package com.yahoo.athenz.zms.config;

import com.yahoo.athenz.zms.Domain;
import com.yahoo.athenz.zms.DomainMeta;
import com.yahoo.athenz.zms.Group;
import com.yahoo.athenz.zms.GroupMeta;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMeta;
import com.yahoo.rdl.JSON;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.testng.Assert.*;

public class AuditTemplateTest {

    private AuditTemplate loadTemplate() throws IOException {
        AuditTemplate template = JSON.fromBytes(Files.readAllBytes(
                Paths.get("src/test/resources/audit_template.json")), AuditTemplate.class);
        assertNotNull(template);
        return template;
    }

    @Test
    public void testLoadAuditTemplate() throws IOException {

        AuditTemplate template = loadTemplate();
        template.validate();

        assertNotNull(template.getDomain());
        assertEquals(template.getDomain().getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(template.getDomain().getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(template.getDomain().getGroupExpiryDays(), Integer.valueOf(60));

        assertNotNull(template.getRole());
        assertEquals(template.getRole().getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(template.getRole().getServiceExpiryDays(), Integer.valueOf(120));
        assertEquals(template.getRole().getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(template.getRole().getMemberReviewDays(), Integer.valueOf(45));
        assertEquals(template.getRole().getServiceReviewDays(), Integer.valueOf(30));
        assertEquals(template.getRole().getGroupReviewDays(), Integer.valueOf(15));

        assertNotNull(template.getGroup());
        assertEquals(template.getGroup().getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(template.getGroup().getServiceExpiryDays(), Integer.valueOf(120));
    }

    @Test
    public void testSetters() {

        AuditTemplate template = new AuditTemplate();
        assertNull(template.getDomain());
        assertNull(template.getRole());
        assertNull(template.getGroup());

        DomainMeta domainMeta = new DomainMeta().setMemberExpiryDays(10);
        RoleMeta roleMeta = new RoleMeta().setMemberExpiryDays(20);
        GroupMeta groupMeta = new GroupMeta().setMemberExpiryDays(30);

        template.setDomain(domainMeta);
        template.setRole(roleMeta);
        template.setGroup(groupMeta);

        assertSame(template.getDomain(), domainMeta);
        assertSame(template.getRole(), roleMeta);
        assertSame(template.getGroup(), groupMeta);
    }

    @Test
    public void testValidateEmptyTemplate() {

        // an empty template or one with empty sections is valid

        AuditTemplate template = new AuditTemplate();
        template.validate();

        template.setDomain(new DomainMeta());
        template.setRole(new RoleMeta());
        template.setGroup(new GroupMeta());
        template.validate();

        // zero values are also valid

        template.setDomain(new DomainMeta().setMemberExpiryDays(0).setServiceExpiryDays(0).setGroupExpiryDays(0));
        template.setRole(new RoleMeta().setMemberExpiryDays(0).setServiceExpiryDays(0).setGroupExpiryDays(0)
                .setMemberReviewDays(0).setServiceReviewDays(0).setGroupReviewDays(0));
        template.setGroup(new GroupMeta().setMemberExpiryDays(0).setServiceExpiryDays(0));
        template.validate();
    }

    private void assertValidateFailure(AuditTemplate template, final String field) {
        try {
            template.validate();
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains(field), ex.getMessage());
        }
    }

    @Test
    public void testValidateNegativeDomainValues() {

        AuditTemplate template = new AuditTemplate();

        template.setDomain(new DomainMeta().setMemberExpiryDays(-1));
        assertValidateFailure(template, "domain.memberExpiryDays");

        template.setDomain(new DomainMeta().setServiceExpiryDays(-1));
        assertValidateFailure(template, "domain.serviceExpiryDays");

        template.setDomain(new DomainMeta().setGroupExpiryDays(-1));
        assertValidateFailure(template, "domain.groupExpiryDays");
    }

    @Test
    public void testValidateNegativeRoleValues() {

        AuditTemplate template = new AuditTemplate();

        template.setRole(new RoleMeta().setMemberExpiryDays(-1));
        assertValidateFailure(template, "role.memberExpiryDays");

        template.setRole(new RoleMeta().setServiceExpiryDays(-1));
        assertValidateFailure(template, "role.serviceExpiryDays");

        template.setRole(new RoleMeta().setGroupExpiryDays(-1));
        assertValidateFailure(template, "role.groupExpiryDays");

        template.setRole(new RoleMeta().setMemberReviewDays(-1));
        assertValidateFailure(template, "role.memberReviewDays");

        template.setRole(new RoleMeta().setServiceReviewDays(-1));
        assertValidateFailure(template, "role.serviceReviewDays");

        template.setRole(new RoleMeta().setGroupReviewDays(-1));
        assertValidateFailure(template, "role.groupReviewDays");
    }

    @Test
    public void testValidateNegativeGroupValues() {

        AuditTemplate template = new AuditTemplate();

        template.setGroup(new GroupMeta().setMemberExpiryDays(-1));
        assertValidateFailure(template, "group.memberExpiryDays");

        template.setGroup(new GroupMeta().setServiceExpiryDays(-1));
        assertValidateFailure(template, "group.serviceExpiryDays");
    }

    @Test
    public void testApplyLimit() {

        // no limit configured - value returned unchanged

        assertNull(AuditTemplate.applyLimit(null, null));
        assertEquals(AuditTemplate.applyLimit(null, 0), Integer.valueOf(0));
        assertEquals(AuditTemplate.applyLimit(null, 100), Integer.valueOf(100));
        assertNull(AuditTemplate.applyLimit(0, null));
        assertEquals(AuditTemplate.applyLimit(0, 0), Integer.valueOf(0));
        assertEquals(AuditTemplate.applyLimit(0, 100), Integer.valueOf(100));

        // limit configured - not specified, 0 or bigger values are limited

        assertEquals(AuditTemplate.applyLimit(90, null), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyLimit(90, 0), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyLimit(90, 91), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyLimit(90, 1000), Integer.valueOf(90));

        // limit configured - equal or smaller values are kept

        assertEquals(AuditTemplate.applyLimit(90, 90), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyLimit(90, 89), Integer.valueOf(89));
        assertEquals(AuditTemplate.applyLimit(90, 1), Integer.valueOf(1));
    }

    @Test
    public void testApplyMetaLimit() {

        // no limit configured - meta value returned unchanged

        assertNull(AuditTemplate.applyMetaLimit(null, null, null));
        assertNull(AuditTemplate.applyMetaLimit(null, null, 100));
        assertEquals(AuditTemplate.applyMetaLimit(null, 200, 100), Integer.valueOf(200));
        assertNull(AuditTemplate.applyMetaLimit(0, null, 100));
        assertEquals(AuditTemplate.applyMetaLimit(0, 200, 100), Integer.valueOf(200));

        // meta value not specified - current value is checked

        assertEquals(AuditTemplate.applyMetaLimit(90, null, null), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyMetaLimit(90, null, 0), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyMetaLimit(90, null, 100), Integer.valueOf(90));
        assertNull(AuditTemplate.applyMetaLimit(90, null, 90));
        assertNull(AuditTemplate.applyMetaLimit(90, null, 30));

        // meta value specified - meta value is checked regardless of current value

        assertEquals(AuditTemplate.applyMetaLimit(90, 0, 30), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyMetaLimit(90, 100, 30), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyMetaLimit(90, 100, null), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyMetaLimit(90, 90, 100), Integer.valueOf(90));
        assertEquals(AuditTemplate.applyMetaLimit(90, 30, 100), Integer.valueOf(30));
        assertEquals(AuditTemplate.applyMetaLimit(90, 30, null), Integer.valueOf(30));
    }

    @Test
    public void testApplyDomainSettings() throws IOException {

        AuditTemplate template = loadTemplate();

        Domain domain = new Domain().setName("athenz").setMemberExpiryDays(100)
                .setServiceExpiryDays(100).setGroupExpiryDays(null);
        template.applyDomainSettings(domain);
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(100));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(60));

        // no domain section - no changes

        template.setDomain(null);
        domain = new Domain().setName("athenz").setMemberExpiryDays(100);
        template.applyDomainSettings(domain);
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(100));
        assertNull(domain.getServiceExpiryDays());
        assertNull(domain.getGroupExpiryDays());
    }

    @Test
    public void testApplyDomainMetaSettings() throws IOException {

        AuditTemplate template = loadTemplate();

        // member expiry - meta bigger than limit, service expiry - meta smaller
        // than limit and group expiry - meta not specified but domain bigger

        Domain domain = new Domain().setName("athenz").setMemberExpiryDays(30)
                .setServiceExpiryDays(200).setGroupExpiryDays(100);
        DomainMeta meta = new DomainMeta().setMemberExpiryDays(100).setServiceExpiryDays(50);
        template.applyDomainMetaSettings(meta, domain);
        assertEquals(meta.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(meta.getServiceExpiryDays(), Integer.valueOf(50));
        assertEquals(meta.getGroupExpiryDays(), Integer.valueOf(60));

        // meta not specified and domain within limits - no changes

        domain = new Domain().setName("athenz").setMemberExpiryDays(30)
                .setServiceExpiryDays(120).setGroupExpiryDays(10);
        meta = new DomainMeta();
        template.applyDomainMetaSettings(meta, domain);
        assertNull(meta.getMemberExpiryDays());
        assertNull(meta.getServiceExpiryDays());
        assertNull(meta.getGroupExpiryDays());

        // no domain section - no changes

        template.setDomain(null);
        meta = new DomainMeta().setMemberExpiryDays(100);
        template.applyDomainMetaSettings(meta, domain);
        assertEquals(meta.getMemberExpiryDays(), Integer.valueOf(100));
        assertNull(meta.getServiceExpiryDays());
        assertNull(meta.getGroupExpiryDays());
    }

    @Test
    public void testApplyRoleSettings() throws IOException {

        AuditTemplate template = loadTemplate();

        Role role = new Role().setName("athenz:role.role1").setMemberExpiryDays(100)
                .setServiceExpiryDays(100).setGroupExpiryDays(0).setMemberReviewDays(null)
                .setServiceReviewDays(30).setGroupReviewDays(10);
        template.applyRoleSettings(role);
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(role.getServiceExpiryDays(), Integer.valueOf(100));
        assertEquals(role.getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(role.getMemberReviewDays(), Integer.valueOf(45));
        assertEquals(role.getServiceReviewDays(), Integer.valueOf(30));
        assertEquals(role.getGroupReviewDays(), Integer.valueOf(10));

        // no role section - no changes

        template.setRole(null);
        role = new Role().setName("athenz:role.role1").setMemberExpiryDays(100);
        template.applyRoleSettings(role);
        assertEquals(role.getMemberExpiryDays(), Integer.valueOf(100));
        assertNull(role.getServiceExpiryDays());
        assertNull(role.getGroupExpiryDays());
        assertNull(role.getMemberReviewDays());
        assertNull(role.getServiceReviewDays());
        assertNull(role.getGroupReviewDays());
    }

    @Test
    public void testApplyRoleMetaSettings() throws IOException {

        AuditTemplate template = loadTemplate();

        Role role = new Role().setName("athenz:role.role1").setMemberExpiryDays(30)
                .setServiceExpiryDays(200).setGroupExpiryDays(100).setMemberReviewDays(0)
                .setServiceReviewDays(30).setGroupReviewDays(100);
        RoleMeta meta = new RoleMeta().setMemberExpiryDays(100).setServiceExpiryDays(50)
                .setGroupReviewDays(10);
        template.applyRoleMetaSettings(meta, role);
        assertEquals(meta.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(meta.getServiceExpiryDays(), Integer.valueOf(50));
        assertEquals(meta.getGroupExpiryDays(), Integer.valueOf(60));
        assertEquals(meta.getMemberReviewDays(), Integer.valueOf(45));
        assertNull(meta.getServiceReviewDays());
        assertEquals(meta.getGroupReviewDays(), Integer.valueOf(10));

        // meta not specified and role within limits - no changes

        role = new Role().setName("athenz:role.role1").setMemberExpiryDays(30)
                .setServiceExpiryDays(120).setGroupExpiryDays(10).setMemberReviewDays(45)
                .setServiceReviewDays(30).setGroupReviewDays(15);
        meta = new RoleMeta();
        template.applyRoleMetaSettings(meta, role);
        assertNull(meta.getMemberExpiryDays());
        assertNull(meta.getServiceExpiryDays());
        assertNull(meta.getGroupExpiryDays());
        assertNull(meta.getMemberReviewDays());
        assertNull(meta.getServiceReviewDays());
        assertNull(meta.getGroupReviewDays());

        // no role section - no changes

        template.setRole(null);
        meta = new RoleMeta().setMemberExpiryDays(100);
        template.applyRoleMetaSettings(meta, role);
        assertEquals(meta.getMemberExpiryDays(), Integer.valueOf(100));
        assertNull(meta.getServiceExpiryDays());
        assertNull(meta.getGroupExpiryDays());
        assertNull(meta.getMemberReviewDays());
        assertNull(meta.getServiceReviewDays());
        assertNull(meta.getGroupReviewDays());
    }

    @Test
    public void testApplyGroupSettings() throws IOException {

        AuditTemplate template = loadTemplate();

        Group group = new Group().setName("athenz:group.group1").setMemberExpiryDays(100)
                .setServiceExpiryDays(100);
        template.applyGroupSettings(group);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(group.getServiceExpiryDays(), Integer.valueOf(100));

        group = new Group().setName("athenz:group.group1");
        template.applyGroupSettings(group);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(group.getServiceExpiryDays(), Integer.valueOf(120));

        // no group section - no changes

        template.setGroup(null);
        group = new Group().setName("athenz:group.group1").setMemberExpiryDays(100);
        template.applyGroupSettings(group);
        assertEquals(group.getMemberExpiryDays(), Integer.valueOf(100));
        assertNull(group.getServiceExpiryDays());
    }

    @Test
    public void testApplyGroupMetaSettings() throws IOException {

        AuditTemplate template = loadTemplate();

        Group group = new Group().setName("athenz:group.group1").setMemberExpiryDays(30)
                .setServiceExpiryDays(200);
        GroupMeta meta = new GroupMeta().setMemberExpiryDays(100);
        template.applyGroupMetaSettings(meta, group);
        assertEquals(meta.getMemberExpiryDays(), Integer.valueOf(90));
        assertEquals(meta.getServiceExpiryDays(), Integer.valueOf(120));

        // meta not specified and group within limits - no changes

        group = new Group().setName("athenz:group.group1").setMemberExpiryDays(30)
                .setServiceExpiryDays(120);
        meta = new GroupMeta();
        template.applyGroupMetaSettings(meta, group);
        assertNull(meta.getMemberExpiryDays());
        assertNull(meta.getServiceExpiryDays());

        // no group section - no changes

        template.setGroup(null);
        meta = new GroupMeta().setMemberExpiryDays(100);
        template.applyGroupMetaSettings(meta, group);
        assertEquals(meta.getMemberExpiryDays(), Integer.valueOf(100));
        assertNull(meta.getServiceExpiryDays());
    }
}
