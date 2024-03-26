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

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class RoleTest {

    @Test
    public void testRoleMetaMethod() {

        RoleMeta rm1 = new RoleMeta()
                .setMemberExpiryDays(30)
                .setSelfServe(false)
                .setTokenExpiryMins(300)
                .setCertExpiryMins(120)
                .setSignAlgorithm("rsa")
                .setServiceExpiryDays(40)
                .setGroupExpiryDays(50)
                .setGroupReviewDays(55)
                .setNotifyRoles("role1,domain:role.role2")
                .setMemberReviewDays(70)
                .setServiceReviewDays(80)
                .setReviewEnabled(false)
                .setAuditEnabled(false)
                .setDeleteProtection(false)
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3")
                .setDescription("test role")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setLastReviewedDate(Timestamp.fromMillis(100))
                .setSelfRenew(true)
                .setSelfRenewMins(180)
                .setMaxMembers(5)
                .setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF"));

        assertFalse(rm1.getSelfServe());
        assertEquals(rm1.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(rm1.getServiceExpiryDays(), Integer.valueOf(40));
        assertEquals(rm1.getGroupExpiryDays(), Integer.valueOf(50));
        assertEquals(rm1.getGroupReviewDays(), Integer.valueOf(55));
        assertEquals(rm1.getTokenExpiryMins(), Integer.valueOf(300));
        assertEquals(rm1.getCertExpiryMins(), Integer.valueOf(120));
        assertEquals(rm1.getSignAlgorithm(), "rsa");
        assertEquals(rm1.getNotifyRoles(), "role1,domain:role.role2");
        assertEquals(rm1.getMemberReviewDays(), Integer.valueOf(70));
        assertEquals(rm1.getServiceReviewDays(), Integer.valueOf(80));
        assertFalse(rm1.getReviewEnabled());
        assertFalse(rm1.getAuditEnabled());
        assertFalse(rm1.getDeleteProtection());
        assertEquals(rm1.getUserAuthorityExpiration(), "attr1");
        assertEquals(rm1.getUserAuthorityFilter(), "attr2,attr3");
        assertEquals(rm1.getTags().get("tagKey").getList().get(0), "tagValue");
        assertEquals(rm1.getDescription(), "test role");
        assertEquals(rm1.getLastReviewedDate(), Timestamp.fromMillis(100));
        assertEquals(rm1.getSelfRenewMins(), 180);
        assertEquals(rm1.getSelfRenew(), Boolean.TRUE);
        assertEquals(rm1.getMaxMembers(), 5);
        assertEquals(rm1.getResourceOwnership(), new ResourceRoleOwnership().setMetaOwner("TF"));

        RoleMeta rm2 = new RoleMeta()
                .setMemberExpiryDays(30)
                .setSelfServe(false)
                .setTokenExpiryMins(300)
                .setCertExpiryMins(120)
                .setSignAlgorithm("rsa")
                .setServiceExpiryDays(40)
                .setGroupExpiryDays(50)
                .setGroupReviewDays(55)
                .setNotifyRoles("role1,domain:role.role2")
                .setMemberReviewDays(70)
                .setServiceReviewDays(80)
                .setReviewEnabled(false)
                .setAuditEnabled(false)
                .setDeleteProtection(false)
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3")
                .setDescription("test role")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setLastReviewedDate(Timestamp.fromMillis(100))
                .setSelfRenew(true)
                .setSelfRenewMins(180)
                .setMaxMembers(5)
                .setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF"));

        assertEquals(rm1, rm2);
        assertEquals(rm1, rm1);
        assertNotEquals(null, rm1);
        assertNotEquals("role-meta", rm1);

        rm2.setMaxMembers(15);
        assertNotEquals(rm1, rm2);
        rm2.setMaxMembers(null);
        assertNotEquals(rm1, rm2);
        rm2.setMaxMembers(5);
        assertEquals(rm1, rm2);

        rm2.setSelfRenew(false);
        assertNotEquals(rm1, rm2);
        rm2.setSelfRenew(null);
        assertNotEquals(rm1, rm2);
        rm2.setSelfRenew(true);
        assertEquals(rm1, rm2);

        rm2.setSelfRenewMins(15);
        assertNotEquals(rm1, rm2);
        rm2.setSelfRenewMins(null);
        assertNotEquals(rm1, rm2);
        rm2.setSelfRenewMins(180);
        assertEquals(rm1, rm2);

        rm2.setNotifyRoles("role1");
        assertNotEquals(rm2, rm1);
        rm2.setNotifyRoles(null);
        assertNotEquals(rm2, rm1);
        rm2.setNotifyRoles("role1,domain:role.role2");
        assertEquals(rm2, rm1);

        rm2.setReviewEnabled(true);
        assertNotEquals(rm2, rm1);
        rm2.setReviewEnabled(null);
        assertNotEquals(rm2, rm1);
        rm2.setReviewEnabled(false);
        assertEquals(rm2, rm1);

        rm2.setAuditEnabled(true);
        assertNotEquals(rm2, rm1);
        rm2.setAuditEnabled(null);
        assertNotEquals(rm2, rm1);
        rm2.setAuditEnabled(false);
        assertEquals(rm2, rm1);

        rm2.setDeleteProtection(true);
        assertNotEquals(rm2, rm1);
        rm2.setDeleteProtection(null);
        assertNotEquals(rm2, rm1);
        rm2.setDeleteProtection(false);
        assertEquals(rm2, rm1);

        rm2.setSignAlgorithm("ec");
        assertNotEquals(rm2, rm1);
        rm2.setSignAlgorithm(null);
        assertNotEquals(rm2, rm1);
        rm2.setSignAlgorithm("rsa");
        assertEquals(rm2, rm1);

        rm2.setDescription("test role1");
        assertNotEquals(rm2, rm1);
        rm2.setDescription(null);
        assertNotEquals(rm2, rm1);
        rm2.setDescription("test role");
        assertEquals(rm2, rm1);

        rm2.setMemberExpiryDays(45);
        assertNotEquals(rm2, rm1);
        rm2.setMemberExpiryDays(null);
        assertNotEquals(rm2, rm1);
        rm2.setMemberExpiryDays(30);
        assertEquals(rm2, rm1);

        rm2.setServiceExpiryDays(45);
        assertNotEquals(rm2, rm1);
        rm2.setServiceExpiryDays(null);
        assertNotEquals(rm2, rm1);
        rm2.setServiceExpiryDays(40);
        assertEquals(rm2, rm1);

        rm2.setGroupExpiryDays(55);
        assertNotEquals(rm2, rm1);
        rm2.setGroupExpiryDays(null);
        assertNotEquals(rm2, rm1);
        rm2.setGroupExpiryDays(50);
        assertEquals(rm2, rm1);

        rm2.setGroupReviewDays(60);
        assertNotEquals(rm2, rm1);
        rm2.setGroupReviewDays(null);
        assertNotEquals(rm2, rm1);
        rm2.setGroupReviewDays(55);
        assertEquals(rm2, rm1);

        rm2.setTokenExpiryMins(450);
        assertNotEquals(rm2, rm1);
        rm2.setTokenExpiryMins(null);
        assertNotEquals(rm2, rm1);
        rm2.setTokenExpiryMins(300);
        assertEquals(rm2, rm1);

        rm2.setCertExpiryMins(150);
        assertNotEquals(rm2, rm1);
        rm2.setCertExpiryMins(null);
        assertNotEquals(rm2, rm1);
        rm2.setCertExpiryMins(120);
        assertEquals(rm2, rm1);

        rm2.setMemberReviewDays(75);
        assertNotEquals(rm2, rm1);
        rm2.setMemberReviewDays(null);
        assertNotEquals(rm2, rm1);
        rm2.setMemberReviewDays(70);
        assertEquals(rm2, rm1);

        rm2.setServiceReviewDays(85);
        assertNotEquals(rm2, rm1);
        rm2.setServiceReviewDays(null);
        assertNotEquals(rm2, rm1);
        rm2.setServiceReviewDays(80);
        assertEquals(rm2, rm1);

        rm2.setSelfServe(true);
        assertNotEquals(rm2, rm1);
        rm2.setSelfServe(null);
        assertNotEquals(rm2, rm1);
        rm2.setSelfServe(false);
        assertEquals(rm2, rm1);

        rm2.setUserAuthorityExpiration("attr11");
        assertNotEquals(rm2, rm1);
        rm2.setUserAuthorityExpiration(null);
        assertNotEquals(rm2, rm1);
        rm2.setUserAuthorityExpiration("attr1");
        assertEquals(rm2, rm1);

        rm2.setUserAuthorityFilter("attr2");
        assertNotEquals(rm2, rm1);
        rm2.setUserAuthorityFilter(null);
        assertNotEquals(rm2, rm1);
        rm2.setUserAuthorityFilter("attr2,attr3");
        assertEquals(rm2, rm1);

        rm2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue1"))));
        assertNotEquals(rm2, rm1);
        rm2.setTags(null);
        assertNotEquals(rm2, rm1);
        rm2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))));
        assertEquals(rm2, rm1);

        rm2.setLastReviewedDate(Timestamp.fromMillis(200));
        assertNotEquals(rm2, rm1);
        rm2.setLastReviewedDate(null);
        assertNotEquals(rm2, rm1);
        rm2.setLastReviewedDate(Timestamp.fromMillis(100));
        assertEquals(rm2, rm1);

        rm2.setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("ZTS"));
        assertNotEquals(rm2, rm1);
        rm2.setResourceOwnership(null);
        assertNotEquals(rm2, rm1);
        rm2.setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF"));
        assertEquals(rm2, rm1);

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Validator.Result result = validator.validate(rm1, "RoleMeta");
        assertTrue(result.valid);
    }

    @Test
    public void testRolesMethod() {
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        RoleAuditLog ral = new RoleAuditLog().setMember("user.test").setAdmin("user.admin")
                .setCreated(Timestamp.fromMillis(123456789123L)).setAction("add").setAuditRef("zmstest");

        List<RoleAuditLog> rall = Collections.singletonList(ral);

        // Role test
        List<String> members = List.of("user.boynton");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("member1"));

        Role r = new Role()
                .setName("sys.auth:role.admin")
                .setMembers(members)
                .setRoleMembers(roleMembers)
                .setAuditEnabled(true)
                .setModified(Timestamp.fromMillis(123456789123L))
                .setTrust("domain.admin")
                .setAuditLog(rall)
                .setSelfServe(false)
                .setMemberExpiryDays(30)
                .setServiceExpiryDays(40)
                .setGroupExpiryDays(50)
                .setGroupReviewDays(55)
                .setTokenExpiryMins(300)
                .setCertExpiryMins(120)
                .setMemberReviewDays(70)
                .setServiceReviewDays(80)
                .setSignAlgorithm("ec")
                .setReviewEnabled(false)
                .setDeleteProtection(false)
                .setNotifyRoles("role1,domain:role.role2")
                .setLastReviewedDate(Timestamp.fromMillis(123456789123L))
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3")
                .setDescription("test role")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setSelfRenew(true)
                .setSelfRenewMins(180)
                .setMaxMembers(5)
                .setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF"));

        assertEquals(r.getName(), "sys.auth:role.admin");
        assertEquals(r.getModified(), Timestamp.fromMillis(123456789123L));
        assertEquals(r.getMembers(), members);
        assertEquals(r.getTrust(), "domain.admin");
        assertEquals(r.getAuditLog(), rall);
        assertEquals(r.getRoleMembers(), roleMembers);
        assertTrue(r.getAuditEnabled());
        assertFalse(r.getSelfServe());
        assertEquals(r.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(r.getServiceExpiryDays(), Integer.valueOf(40));
        assertEquals(r.getGroupExpiryDays(), Integer.valueOf(50));
        assertEquals(r.getGroupReviewDays(), Integer.valueOf(55));
        assertEquals(r.getTokenExpiryMins(), Integer.valueOf(300));
        assertEquals(r.getCertExpiryMins(), Integer.valueOf(120));
        assertEquals(r.getMemberReviewDays(), Integer.valueOf(70));
        assertEquals(r.getServiceReviewDays(), Integer.valueOf(80));
        assertEquals(r.getSignAlgorithm(), "ec");
        assertFalse(r.getReviewEnabled());
        assertFalse(r.getDeleteProtection());
        assertEquals(r.getLastReviewedDate(), Timestamp.fromMillis(123456789123L));
        assertEquals(r.getNotifyRoles(), "role1,domain:role.role2");
        assertEquals(r.getUserAuthorityExpiration(), "attr1");
        assertEquals(r.getUserAuthorityFilter(), "attr2,attr3");
        assertEquals(r.getTags().get("tagKey").getList().get(0), "tagValue");
        assertEquals(r.getDescription(), "test role");
        assertEquals(r.getSelfRenew(), Boolean.TRUE);
        assertEquals(r.getSelfRenewMins(), 180);
        assertEquals(r.getMaxMembers(), 5);
        assertEquals(r.getResourceOwnership(), new ResourceRoleOwnership().setMetaOwner("TF"));

        Role r2 = new Role()
                .setName("sys.auth:role.admin")
                .setMembers(members)
                .setRoleMembers(roleMembers)
                .setAuditEnabled(true)
                .setModified(Timestamp.fromMillis(123456789123L))
                .setTrust("domain.admin")
                .setAuditLog(rall)
                .setSelfServe(false)
                .setMemberExpiryDays(30)
                .setServiceExpiryDays(40)
                .setGroupExpiryDays(50)
                .setGroupReviewDays(55)
                .setTokenExpiryMins(300)
                .setCertExpiryMins(120)
                .setMemberReviewDays(70)
                .setServiceReviewDays(80)
                .setSignAlgorithm("ec")
                .setReviewEnabled(false)
                .setDeleteProtection(false)
                .setNotifyRoles("role1,domain:role.role2")
                .setLastReviewedDate(Timestamp.fromMillis(123456789123L))
                .setUserAuthorityExpiration("attr1")
                .setUserAuthorityFilter("attr2,attr3")
                .setDescription("test role")
                .setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue"))))
                .setSelfRenew(true)
                .setSelfRenewMins(180)
                .setMaxMembers(5)
                .setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF"));

        assertEquals(r, r2);
        assertEquals(r, r);

        r2.setLastReviewedDate(Timestamp.fromMillis(123456789124L));
        assertNotEquals(r, r2);
        r2.setLastReviewedDate(null);
        assertNotEquals(r, r2);
        r2.setLastReviewedDate(Timestamp.fromMillis(123456789123L));
        assertEquals(r, r2);

        r2.setNotifyRoles("role1");
        assertNotEquals(r, r2);
        r2.setNotifyRoles(null);
        assertNotEquals(r, r2);
        r2.setNotifyRoles("role1,domain:role.role2");
        assertEquals(r, r2);

        r2.setMaxMembers(15);
        assertNotEquals(r, r2);
        r2.setMaxMembers(null);
        assertNotEquals(r, r2);
        r2.setMaxMembers(5);
        assertEquals(r, r2);

        r2.setSelfRenew(false);
        assertNotEquals(r, r2);
        r2.setSelfRenew(null);
        assertNotEquals(r, r2);
        r2.setSelfRenew(true);
        assertEquals(r, r2);

        r2.setSelfRenewMins(15);
        assertNotEquals(r, r2);
        r2.setSelfRenewMins(null);
        assertNotEquals(r, r2);
        r2.setSelfRenewMins(180);
        assertEquals(r, r2);

        r2.setReviewEnabled(true);
        assertNotEquals(r, r2);
        r2.setReviewEnabled(null);
        assertNotEquals(r, r2);
        r2.setReviewEnabled(false);
        assertEquals(r, r2);

        r2.setDeleteProtection(true);
        assertNotEquals(r, r2);
        r2.setDeleteProtection(null);
        assertNotEquals(r, r2);
        r2.setDeleteProtection(false);
        assertEquals(r, r2);

        r2.setDescription("test role1");
        assertNotEquals(r, r2);
        r2.setDescription(null);
        assertNotEquals(r, r2);
        r2.setDescription("test role");
        assertEquals(r, r2);

        r2.setSignAlgorithm("rsa");
        assertNotEquals(r, r2);
        r2.setSignAlgorithm(null);
        assertNotEquals(r, r2);
        r2.setSignAlgorithm("ec");
        assertEquals(r, r2);

        r2.setMemberExpiryDays(45);
        assertNotEquals(r, r2);
        r2.setMemberExpiryDays(null);
        assertNotEquals(r, r2);
        r2.setMemberExpiryDays(30);
        assertEquals(r, r2);

        r2.setServiceExpiryDays(45);
        assertNotEquals(r, r2);
        r2.setServiceExpiryDays(null);
        assertNotEquals(r, r2);
        r2.setServiceExpiryDays(40);
        assertEquals(r, r2);

        r2.setGroupExpiryDays(55);
        assertNotEquals(r, r2);
        r2.setGroupExpiryDays(null);
        assertNotEquals(r, r2);
        r2.setGroupExpiryDays(50);
        assertEquals(r, r2);

        r2.setGroupReviewDays(60);
        assertNotEquals(r, r2);
        r2.setGroupReviewDays(null);
        assertNotEquals(r, r2);
        r2.setGroupReviewDays(55);
        assertEquals(r, r2);

        r2.setTokenExpiryMins(450);
        assertNotEquals(r, r2);
        r2.setTokenExpiryMins(null);
        assertNotEquals(r, r2);
        r2.setTokenExpiryMins(300);
        assertEquals(r, r2);

        r2.setCertExpiryMins(150);
        assertNotEquals(r, r2);
        r2.setCertExpiryMins(null);
        assertNotEquals(r, r2);
        r2.setCertExpiryMins(120);
        assertEquals(r, r2);

        r2.setAuditEnabled(false);
        assertNotEquals(r, r2);
        r2.setAuditEnabled(null);
        assertNotEquals(r, r2);
        r2.setAuditEnabled(true);
        assertEquals(r, r2);

        r2.setSelfServe(true);
        assertNotEquals(r, r2);
        r2.setSelfServe(null);
        assertNotEquals(r, r2);
        r2.setSelfServe(false);
        assertEquals(r, r2);

        r2.setMemberReviewDays(75);
        assertNotEquals(r, r2);
        r2.setMemberReviewDays(null);
        assertNotEquals(r, r2);
        r2.setMemberReviewDays(70);
        assertEquals(r, r2);

        r2.setServiceReviewDays(85);
        assertNotEquals(r, r2);
        r2.setServiceReviewDays(null);
        assertNotEquals(r, r2);
        r2.setServiceReviewDays(80);
        assertEquals(r, r2);

        r2.setUserAuthorityExpiration("attr11");
        assertNotEquals(r, r2);
        r2.setUserAuthorityExpiration(null);
        assertNotEquals(r, r2);
        r2.setUserAuthorityExpiration("attr1");
        assertEquals(r, r2);

        r2.setUserAuthorityFilter("attr2");
        assertNotEquals(r, r2);
        r2.setUserAuthorityFilter(null);
        assertNotEquals(r, r2);
        r2.setUserAuthorityFilter("attr2,attr3");
        assertEquals(r, r2);

        r2.setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("ZTS"));
        assertNotEquals(r2, r);
        r2.setResourceOwnership(null);
        assertNotEquals(r2, r);
        r2.setResourceOwnership(new ResourceRoleOwnership().setMetaOwner("TF"));
        assertEquals(r2, r);

        r2.setAuditLog(null);
        assertNotEquals(r, r2);
        r2.setTrust(null);
        assertNotEquals(r, r2);
        r2.setRoleMembers(null);
        assertNotEquals(r, r2);
        r2.setMembers(null);
        assertNotEquals(r, r2);
        r2.setModified(null);
        assertNotEquals(r, r2);
        r2.setName(null);
        assertNotEquals(r, r2);
        assertNotEquals("role", r);

        r2.setTags(Collections.singletonMap("tagKey", new TagValueList().setList(Collections.singletonList("tagValue1"))));
        assertNotEquals(r, r2);
        r2.setTags(null);
        assertNotEquals(r, r2);

        Validator.Result result = validator.validate(r, "Role");
        assertTrue(result.valid);

        List<Role> rl = List.of(r);

        // Roles test
        Roles rs1 = new Roles().setList(rl);
        assertEquals(rs1, rs1);

        result = validator.validate(rs1, "Roles");
        assertTrue(result.valid);

        assertEquals(rs1.getList(), rl);

        Roles rs2 = new Roles().setList(rl);
        assertEquals(rs1, rs2);

        rs2.setList(null);
        assertNotEquals(rs1, rs2);

        assertNotEquals(rs1, null);
        assertNotEquals("role", rs1);
    }
}
