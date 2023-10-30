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

import java.util.Collections;

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
                .setLastReviewedDate(Timestamp.fromMillis(100));

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
                .setLastReviewedDate(Timestamp.fromMillis(100));

        assertEquals(rm1, rm2);
        assertEquals(rm1, rm1);
        assertNotEquals(null, rm1);
        assertNotEquals("role-meta", rm1);

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

        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);
        Validator.Result result = validator.validate(rm1, "RoleMeta");
        assertTrue(result.valid);
    }

}
