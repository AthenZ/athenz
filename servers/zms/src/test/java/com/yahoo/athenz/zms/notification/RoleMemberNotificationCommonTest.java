/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.DomainRoleMember;
import com.yahoo.athenz.zms.MemberRole;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

public class RoleMemberNotificationCommonTest {

    @Test
    public void testExpiryPrincipalGetNotificationDetails() {
        DBService dbsvc = Mockito.mock(DBService.class);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);

        // Verify no details for member without member roles
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("user.joe", roleMember);
        List<Notification> notification = roleMemberNotificationCommon.getNotificationDetails(
                members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());

        assertEquals(1, notification.size());
        assertTrue(notification.get(0).getDetails().isEmpty());

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        notification = roleMemberNotificationCommon.getNotificationDetails(
                members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());

        assertEquals(1, notification.size());
        assertTrue(notification.get(0).getDetails().isEmpty());

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        roleMember.setMemberRoles(memberRoles);

        notification = roleMemberNotificationCommon.getNotificationDetails(
                members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());

        assertEquals(1, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;" + expirationTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));

        notification = roleMemberNotificationCommon.getNotificationDetails(
                members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());

        assertEquals(1, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;" + expirationTs + "|athenz2;role1;" + expirationTs + "|athenz2;role2;" + expirationTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;" + expirationTs + "|athenz2;role1;" + expirationTs + "|athenz2;role2;" + expirationTs);
    }

    @Test
    public void testReviewPrincipalGetNotificationDetails() {
        DBService dbsvc = Mockito.mock(DBService.class);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);

        // Verify no details for member without member roles
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("user.joe", roleMember);
        List<Notification> notification = roleMemberNotificationCommon.getNotificationDetails(
                members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter());

        assertEquals(1, notification.size());
        assertTrue(notification.get(0).getDetails().isEmpty());

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        notification = roleMemberNotificationCommon.getNotificationDetails(
                members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter());
        assertEquals(1, notification.size());
        assertTrue(notification.get(0).getDetails().isEmpty());

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        roleMember.setMemberRoles(memberRoles);

        notification = roleMemberNotificationCommon.getNotificationDetails(
                members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter());

        assertEquals(1, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;" + reviewTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));

        notification = roleMemberNotificationCommon.getNotificationDetails(
                members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter());

        assertEquals(1, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());
        String expectedRolesList = "athenz1;role1;" + reviewTs +
                "|athenz2;role1;" + reviewTs +
                "|athenz2;role2;" + reviewTs;
        assertEquals(expectedRolesList,
                notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST));
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(expectedRolesList,
                notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST));
    }
}
