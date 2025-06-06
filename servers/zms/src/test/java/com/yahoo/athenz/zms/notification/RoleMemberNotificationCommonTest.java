/*
 *  Copyright The Athenz Authors
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

import com.yahoo.athenz.auth.impl.UserAuthority;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationConverterCommon;
import com.yahoo.athenz.common.server.notification.NotificationObjectStore;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.*;
import java.util.stream.Collectors;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.zms.ResourceException.NOT_FOUND;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.testng.Assert.*;

public class RoleMemberNotificationCommonTest {

    @Test
    public void testExpiryPrincipalGetNotificationDetails() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getRolesByDomain(eq("test.domain:group"))).thenThrow(new ResourceException(NOT_FOUND));
        Role group1Admin = new Role().setName("groupdomain1:role.admin")
                .setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRole("groupdomain1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(group1Admin);
        Role athenzAdmin = new Role().setName("athenz1:role.admin")
                .setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(athenzAdmin);
        Mockito.when(dbsvc.getGroup("test.domain", "testgroup", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(new Group().setName("test.domain:group.testgroup"));
        Mockito.when(dbsvc.getRole("test.domain", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(new Role().setName("test.domain:role.admin"));

        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc,
                USER_DOMAIN_PREFIX);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

        // Verify no notification for member without member roles
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("user.joe", roleMember);
        DomainRoleMember groupMember = new DomainRoleMember();
        groupMember.setMemberName("test.domain:group.testgroup");
        members.put("test.domain:group.testgroup", groupMember);
        List<Notification> notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.PRINCIPAL, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToSlackConverter(notificationConverterCommon),
                null);

        assertEquals(notifications.size(), 0);

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        groupMember.setMemberRoles(Collections.emptyList());
        notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notifications.size(), 0);

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs).setNotifyDetails("notify details"));
        roleMember.setMemberRoles(memberRoles);
        List<MemberRole> groupMemberRoles = new ArrayList<>();
        groupMemberRoles.add(new MemberRole().setRoleName("grouprole1").setDomainName("groupdomain1")
                .setMemberName("test.domain:group.testgroup")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        groupMember.setMemberRoles(groupMemberRoles);
        notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notifications.size(), 2);
        assertEquals(notifications.get(0).getDetails().size(), 2);
        assertEquals(notifications.get(1).getDetails().size(), 1);

        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details");
        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(notifications.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));

        notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notifications.size(), 2);
        assertEquals(notifications.get(0).getDetails().size(), 2);
        assertEquals(notifications.get(1).getDetails().size(), 1);
        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details|athenz2;role1;user.joe;" + expirationTs
                        + ";|athenz2;role2;user.joe;" + expirationTs + ";");
        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details|athenz2;role1;user.joe;" + expirationTs
                        + ";|athenz2;role2;user.joe;" + expirationTs + ";");
    }

    @Test
    public void testExpiryPrincipalGetNotificationDetailsWithGroups() {

        DBService dbsvc = Mockito.mock(DBService.class);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc,
                USER_DOMAIN_PREFIX);
        NotificationConverterCommon notificationConverterCommon =
                new NotificationConverterCommon(null);

        // our dev-team group has no notify roles set up so the admin notification
        // must go the domain admins

        Group devGroup = new Group().setName("athenz:group.dev-team");
        Mockito.when(dbsvc.getGroup("athenz", "dev-team", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(devGroup);

        Role adminRole = new Role().setName("athenz:role.admin");
        adminRole.setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.user1")));
        Mockito.when(dbsvc.getRole("athenz", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);

        List<MemberRole> memberRoles1 = new ArrayList<>();
        memberRoles1.add(new MemberRole().setRoleName("role1").setDomainName("athenz")
                .setMemberName("athenz:group.dev-team"));
        DomainRoleMember groupMember1 = new DomainRoleMember();
        groupMember1.setMemberName("athenz:group.dev-team");
        groupMember1.setMemberRoles(memberRoles1);

        // our qa-team group has a notify role set up so the admin notification
        // must go to the configured role members

        Group qaGroup = new Group().setName("sports:group.qa-team").setNotifyRoles("ops:role.qa-admin");
        Mockito.when(dbsvc.getGroup("sports", "qa-team", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(qaGroup);

        Role sportsRole = new Role().setName("sports:role.admin");
        sportsRole.setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.user2")));
        Mockito.when(dbsvc.getRole("sports", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(sportsRole);

        Role notifyRole = new Role().setName("ops:role.qa-admin");
        notifyRole.setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.user3")));
        Mockito.when(dbsvc.getRole("ops", "qa-admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(notifyRole);

        List<MemberRole> memberRoles2 = new ArrayList<>();
        memberRoles2.add(new MemberRole().setRoleName("role2").setDomainName("sports")
                .setMemberName("sports:group.qa-team"));
        DomainRoleMember groupMember2 = new DomainRoleMember();
        groupMember2.setMemberName("sports:group.qa-team");
        groupMember2.setMemberRoles(memberRoles2);

        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("athenz:group.dev-team", groupMember1);
        members.put("sports:group.qa-team", groupMember2);

        List<Notification> notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notifications.size(), 4);
        for (Notification notification : notifications) {
            assertEquals(notification.getRecipients().size(), 1);
            final String principal = notification.getRecipients().iterator().next();
            switch (principal) {
                case "user.user1":
                    if (notification.getDetails().size() == 1) {
                        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                                "athenz;role1;athenz:group.dev-team;null;");
                    } else if (notification.getDetails().size() == 2) {
                        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                                "athenz;role1;athenz:group.dev-team;null;");
                        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.user1");
                    } else {
                        fail();
                    }
                    break;
                case "user.user2":
                    assertEquals(notification.getDetails().size(), 1);
                    assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                            "sports;role2;sports:group.qa-team;null;");
                    break;
                case "user.user3":
                    assertEquals(notification.getDetails().size(), 2);
                    assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                            "sports;role2;sports:group.qa-team;null;");
                    assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.user3");
                    break;
                default:
                    fail("unexpected principal: " + principal);
                    break;
            }
        }
    }

    @Test
    public void testReviewPrincipalGetNotificationDetails() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Role adminRole = new Role().setName("athenz1:role.admin").setRoleMembers(Collections.singletonList(
                new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRolesByDomain(eq("athenz1"))).thenReturn(Collections.singletonList(adminRole));
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

        // Verify no notification for member without member roles
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("user.joe", roleMember);
        List<Notification> notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notification.size(), 0);

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);
        assertEquals(notification.size(), 0);

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        roleMember.setMemberRoles(memberRoles);

        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notification.size(), 2);
        assertEquals(notification.get(0).getDetails().size(), 2);
        assertEquals(notification.get(1).getDetails().size(), 1);

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + reviewTs + ";");
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "athenz1;role1;user.joe;" + reviewTs + ";");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));

        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notification.size(), 2);
        assertEquals(notification.get(0).getDetails().size(), 2);
        String expectedRolesList = "athenz1;role1;user.joe;" + reviewTs +
                ";|athenz2;role1;user.joe;" + reviewTs +
                ";|athenz2;role2;user.joe;" + reviewTs + ";";
        assertEquals(expectedRolesList,
                notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST));
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(expectedRolesList,
                notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST));

        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "athenz1;role1;user.joe;" + reviewTs + ";");
    }


    @Test
    public void testReviewGetNotificationDetailsFilterTag() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Role adminRole = new Role().setName("athenz1:role.admin").setRoleMembers(Collections.singletonList(
                new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRolesByDomain(eq("athenz1"))).thenReturn(Collections.singletonList(adminRole));
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("user.joe", roleMember);

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        roleMember.setMemberRoles(memberRoles);

        // Verify disable notification for users
        List<Notification> notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(1),
                null);

        assertEquals(notification.size(), 1);
        assertEquals(notification.get(0).getDetails().size(), 1);

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "athenz1;role1;user.joe;" + reviewTs + ";");

        // Verify disable notification for admins
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(2),
                null);

        assertEquals(notification.size(), 1);
        assertEquals(notification.get(0).getDetails().size(), 2);

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + reviewTs + ";");
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        // Verify disable all notifications
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(3),
                null);

        assertEquals(notification.size(), 0);
    }

    @Test
    public void testConsolidatedExpiryPrincipalGetNotificationDetails() {

        DBService dbsvc = Mockito.mock(DBService.class);

        Mockito.when(dbsvc.getRolesByDomain(eq("test.domain"))).thenThrow(new ResourceException(NOT_FOUND));

        List<Role> adminMembers = new ArrayList<>();
        Role admin = new Role();
        admin.setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.testadmin")));
        admin.setName("groupdomain1:role.admin");
        adminMembers.add(admin);
        Mockito.when(dbsvc.getRolesByDomain(eq("groupdomain1"))).thenReturn(adminMembers);
        Mockito.when(dbsvc.getRole("groupdomain1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(admin);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc,
                USER_DOMAIN_PREFIX);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

        // Verify no notification for member without member roles
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("user.joe", roleMember);
        DomainRoleMember groupMember = new DomainRoleMember();
        groupMember.setMemberName("test.domain:group.testgroup");
        members.put("test.domain:group.testgroup", groupMember);
        List<Notification> notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notification.size(), 0);

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        groupMember.setMemberRoles(Collections.emptyList());
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notification.size(), 0);

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        members = new HashMap<>();

        roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs).setNotifyDetails("notify details"));
        memberRoles.add(new MemberRole().setRoleName("grouprole1").setDomainName("groupdomain1")
                .setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        roleMember.setMemberRoles(memberRoles);
        members.put("user.joe", roleMember);

        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notification.size(), 2);
        assertEquals(notification.get(0).getDetails().size(), 2);
        assertEquals(notification.get(1).getDetails().size(), 1);

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details|groupdomain1;grouprole1;user.joe;" + expirationTs + ";");
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "groupdomain1;grouprole1;user.joe;" + expirationTs + ";");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));

        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                null);

        assertEquals(notification.size(), 2);
        assertEquals(notification.get(0).getDetails().size(), 2);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details|groupdomain1;grouprole1;user.joe;" + expirationTs
                        + ";|athenz2;role1;user.joe;" + expirationTs + ";|athenz2;role2;user.joe;" + expirationTs + ";");
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "groupdomain1;grouprole1;user.joe;" + expirationTs + ";");
    }

    @Test
    public void testConsolidateRoleMembers() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<Role> athenzRoles = new ArrayList<>();
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        Role role = new Role().setName("athenz:role.admin").setRoleMembers(roleMembers);
        athenzRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("athenz")).thenReturn(athenzRoles);
        Mockito.when(dbsvc.getRole("athenz", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        List<Role> sportsRoles = new ArrayList<>();
        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("sports.api"));
        roleMembers.add(new RoleMember().setMemberName("sports:group.dev-team"));
        role = new Role().setName("sports:role.admin").setRoleMembers(roleMembers);
        sportsRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("sports")).thenReturn(sportsRoles);
        Mockito.when(dbsvc.getRole("sports", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        List<Role> weatherRoles = new ArrayList<>();
        role = new Role().setName("weather:role.admin").setRoleMembers(new ArrayList<>());
        weatherRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("weather")).thenReturn(weatherRoles);
        Mockito.when(dbsvc.getRole("weather", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX);

        Map<String, DomainRoleMember> members = new HashMap<>();

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("user.joe").setDomainName("athenz").setRoleName("dev-team"));
        memberRoles.add(new MemberRole().setMemberName("user.joe").setDomainName("sports").setRoleName("qa-team"));
        DomainRoleMember domainRoleMember = new DomainRoleMember().setMemberName("user.joe")
                .setMemberRoles(memberRoles);
        members.put("user.joe", domainRoleMember);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("athenz.api").setDomainName("athenz").setRoleName("dev-team"));
        memberRoles.add(new MemberRole().setMemberName("athenz.api").setDomainName("coretech").setRoleName("qa-team"));
        domainRoleMember = new DomainRoleMember().setMemberName("athenz.api")
                .setMemberRoles(memberRoles);
        members.put("athenz.api", domainRoleMember);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("sports.api").setDomainName("sports").setRoleName("dev-team"));
        domainRoleMember = new DomainRoleMember().setMemberName("sports.api")
                .setMemberRoles(memberRoles);
        members.put("sports.api", domainRoleMember);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("weather.api").setDomainName("weather").setRoleName("dev-team"));
        domainRoleMember = new DomainRoleMember().setMemberName("weather.api")
                .setMemberRoles(memberRoles);
        members.put("weather.api", domainRoleMember);

        Map<String, DomainRoleMember> consolidatedMembers = task.consolidateRoleMembers(members);
        assertEquals(consolidatedMembers.size(), 1);
        assertNotNull(consolidatedMembers.get("user.joe"));
    }

    @Test
    public void testConsolidateRoleMembersByDomain() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<Role> athenzRoles = new ArrayList<>();
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        Role role = new Role().setName("athenz:role.admin").setRoleMembers(roleMembers);
        athenzRoles.add(role);
        Mockito.when(dbsvc.getRole("athenz", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);
        Mockito.when(dbsvc.getRolesByDomain("athenz")).thenReturn(athenzRoles);

        List<Role> sportsRoles = new ArrayList<>();
        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("sports.api"));
        roleMembers.add(new RoleMember().setMemberName("sports:group.dev-team"));
        role = new Role().setName("sports:role.admin").setRoleMembers(roleMembers);
        sportsRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("sports")).thenReturn(sportsRoles);

        List<Role> weatherRoles = new ArrayList<>();
        role = new Role().setName("weather:role.admin").setRoleMembers(new ArrayList<>());
        weatherRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("weather")).thenReturn(weatherRoles);

        Group weatherGroup = new Group().setName("weather:group.api-grp").setNotifyRoles("weather:role.admin");
        Mockito.when(dbsvc.getGroup("weather", "api-grp", Boolean.FALSE, Boolean.FALSE)).thenReturn(weatherGroup);

        Group athenzGroup = new Group().setName("athenz:group.api-grp").setNotifyRoles("athenz:role.admin");
        Mockito.when(dbsvc.getGroup("athenz", "api-grp", Boolean.FALSE, Boolean.FALSE)).thenReturn(athenzGroup);
        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX);

        Map<String, DomainRoleMember> members = new HashMap<>();

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("weather:group.api-grp").setDomainName("weather").setRoleName("dev-team"));
        DomainRoleMember domainRoleMember = new DomainRoleMember().setMemberName("weather:group.api-grp")
                .setMemberRoles(memberRoles);
        members.put("weather:group.api-grp", domainRoleMember);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("athenz:group.api-grp").setDomainName("athenz").setRoleName("dev-team"));
        domainRoleMember = new DomainRoleMember().setMemberName("athenz:group.api-grp")
                .setMemberRoles(memberRoles);
        members.put("athenz:group.api-grp", domainRoleMember);

        memberRoles.add(new MemberRole().setMemberName("user.joe").setDomainName("athenz").setRoleName("dev-team"));
        memberRoles.add(new MemberRole().setMemberName("user.joe").setDomainName("sports").setRoleName("qa-team"));
        domainRoleMember = new DomainRoleMember().setMemberName("user.joe")
                .setMemberRoles(memberRoles);
        members.put("user.joe", domainRoleMember);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("athenz.api").setDomainName("athenz").setRoleName("dev-team"));
        memberRoles.add(new MemberRole().setMemberName("athenz.api").setDomainName("coretech").setRoleName("qa-team"));
        domainRoleMember = new DomainRoleMember().setMemberName("athenz.api")
                .setMemberRoles(memberRoles);
        members.put("athenz.api", domainRoleMember);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("sports.api").setDomainName("sports").setRoleName("dev-team"));
        domainRoleMember = new DomainRoleMember().setMemberName("sports.api")
                .setMemberRoles(memberRoles);
        members.put("sports.api", domainRoleMember);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("weather.api").setDomainName("weather").setRoleName("dev-team"));
        domainRoleMember = new DomainRoleMember().setMemberName("weather.api")
                .setMemberRoles(memberRoles);
        members.put("weather.api", domainRoleMember);

        Map<String, DomainRoleMember> consolidatedMembers = task.consolidateRoleMembersByDomain(members);
        assertEquals(consolidatedMembers.size(), 4);
        assertNotNull(consolidatedMembers.get("weather"));
        assertNotNull(consolidatedMembers.get("sports"));
        assertNotNull(consolidatedMembers.get("athenz"));
        assertNotNull(consolidatedMembers.get("user.joe"));
    }

    @Test
    public void testConsolidateDomainMembers() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<Role> athenzRoles = new ArrayList<>();
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        Role role = new Role().setName("athenz:role.admin").setRoleMembers(roleMembers);
        athenzRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("athenz")).thenReturn(athenzRoles);
        Mockito.when(dbsvc.getRole("athenz", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        List<Role> sportsRoles = new ArrayList<>();
        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("sports.api"));
        roleMembers.add(new RoleMember().setMemberName("sports:group.dev-team"));
        role = new Role().setName("sports:role.admin").setRoleMembers(roleMembers);
        sportsRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("sports")).thenReturn(sportsRoles);
        Mockito.when(dbsvc.getRole("sports", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        List<Role> weatherRoles = new ArrayList<>();
        role = new Role().setName("weather:role.admin").setRoleMembers(new ArrayList<>());
        weatherRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("weather")).thenReturn(weatherRoles);
        Mockito.when(dbsvc.getRole("weather", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);

        Map<String, List<MemberRole>> domainRoleMembers = new HashMap<>();

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("athenz.api").setDomainName("athenz").setRoleName("dev-team"));
        memberRoles.add(new MemberRole().setMemberName("athenz.api").setDomainName("coretech").setRoleName("qa-team"));
        domainRoleMembers.put("athenz", memberRoles);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("sports.api").setDomainName("sports").setRoleName("dev-team"));
        domainRoleMembers.put("sports", memberRoles);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("weather.api").setDomainName("weather").setRoleName("dev-team"));
        domainRoleMembers.put("weather", memberRoles);

        Map<String, DomainRoleMember> consolidatedMembers = task.consolidateDomainAdmins(domainRoleMembers);
        assertEquals(consolidatedMembers.size(), 1);
        assertNotNull(consolidatedMembers.get("user.joe"));

        // empty list should give us empty map

        consolidatedMembers = task.consolidateDomainAdmins(Collections.emptyMap());
        assertTrue(consolidatedMembers.isEmpty());

        // list with null member should give us empty map

        domainRoleMembers = new HashMap<>();
        domainRoleMembers.put("athenz", null);
        consolidatedMembers = task.consolidateDomainAdmins(domainRoleMembers);
        assertTrue(consolidatedMembers.isEmpty());

        // list with empty list as member should give us empty map

        domainRoleMembers = new HashMap<>();
        domainRoleMembers.put("athenz", new ArrayList<>());
        consolidatedMembers = task.consolidateDomainAdmins(domainRoleMembers);
        assertTrue(consolidatedMembers.isEmpty());
    }

    @Test
    public void testConsolidateDomainMembersByDomain() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<Role> athenzRoles = new ArrayList<>();
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        Role role = new Role().setName("athenz:role.admin").setRoleMembers(roleMembers);
        athenzRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("athenz")).thenReturn(athenzRoles);
        Mockito.when(dbsvc.getRole("athenz", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        List<Role> sportsRoles = new ArrayList<>();
        roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("sports.api"));
        roleMembers.add(new RoleMember().setMemberName("sports:group.dev-team"));
        role = new Role().setName("sports:role.admin").setRoleMembers(roleMembers);
        sportsRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("sports")).thenReturn(sportsRoles);
        Mockito.when(dbsvc.getRole("sports", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        List<Role> weatherRoles = new ArrayList<>();
        role = new Role().setName("weather:role.admin").setRoleMembers(new ArrayList<>());
        weatherRoles.add(role);
        Mockito.when(dbsvc.getRolesByDomain("weather")).thenReturn(weatherRoles);
        Mockito.when(dbsvc.getRole("weather", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);

        Map<String, List<MemberRole>> domainRoleMembers = new HashMap<>();

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("athenz.api").setDomainName("athenz").setRoleName("dev-team"));
        memberRoles.add(new MemberRole().setMemberName("athenz.api").setDomainName("coretech").setRoleName("qa-team"));
        domainRoleMembers.put("athenz", memberRoles);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("sports.api").setDomainName("sports").setRoleName("dev-team"));
        domainRoleMembers.put("sports", memberRoles);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("weather.api").setDomainName("weather").setRoleName("dev-team"));
        domainRoleMembers.put("weather", memberRoles);

        Map<String, DomainRoleMember> consolidatedMembers = task.consolidateDomains(domainRoleMembers);
        assertEquals(consolidatedMembers.size(), 4);
        assertNotNull(consolidatedMembers.get("sports"));
        assertNotNull(consolidatedMembers.get("weather"));
        assertNotNull(consolidatedMembers.get("athenz"));
        assertNotNull(consolidatedMembers.get("coretech"));

        // empty list should give us empty map

        consolidatedMembers = task.consolidateDomains(Collections.emptyMap());
        assertTrue(consolidatedMembers.isEmpty());

        // list with null member should give us empty map

        domainRoleMembers = new HashMap<>();
        domainRoleMembers.put("athenz", null);
        consolidatedMembers = task.consolidateDomains(domainRoleMembers);
        assertTrue(consolidatedMembers.isEmpty());

        // list with empty list as member should give us empty map

        domainRoleMembers = new HashMap<>();
        domainRoleMembers.put("athenz", new ArrayList<>());
        consolidatedMembers = task.consolidateDomains(domainRoleMembers);
        assertTrue(consolidatedMembers.isEmpty());
    }

    @Test
    public void testConsolidateDomainMembersWithNotifyRoles() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<Role> athenzRoles = new ArrayList<>();

        List<RoleMember> roleMembers1 = new ArrayList<>();
        roleMembers1.add(new RoleMember().setMemberName("user.joe"));
        Role role1 = new Role().setName("athenz:role.admin").setRoleMembers(roleMembers1);
        athenzRoles.add(role1);

        List<RoleMember> roleMembers2 = new ArrayList<>();
        roleMembers2.add(new RoleMember().setMemberName("user.dave"));
        Role role2 = new Role().setName("athenz:role.notify1").setRoleMembers(roleMembers2);
        athenzRoles.add(role2);

        Mockito.when(dbsvc.getRolesByDomain("athenz")).thenReturn(athenzRoles);
        Mockito.when(dbsvc.getRole("athenz", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role1);
        Mockito.when(dbsvc.getRole("athenz", "notify1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role2);

        List<Role> opsRoles = new ArrayList<>();

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        Role role = new Role().setName("ops:role.notify2").setRoleMembers(roleMembers);
        opsRoles.add(role);

        Mockito.when(dbsvc.getRolesByDomain("ops")).thenReturn(opsRoles);
        Mockito.when(dbsvc.getRole("ops", "notify2", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);

        Map<String, List<MemberRole>> domainRoleMembers = new HashMap<>();

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("user.user1").setDomainName("athenz").setRoleName("dev-team"));
        memberRoles.add(new MemberRole().setMemberName("user.user2").setDomainName("athenz").setRoleName("qa-team")
                .setNotifyRoles("notify1"));
        domainRoleMembers.put("athenz", memberRoles);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("user.user3").setDomainName("sports").setRoleName("dev-team")
                .setNotifyRoles("athenz:role.notify1"));
        domainRoleMembers.put("sports", memberRoles);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("user.user4").setDomainName("weather").setRoleName("dev-team")
                .setNotifyRoles("ops:role.notify2"));
        domainRoleMembers.put("weather", memberRoles);

        Map<String, DomainRoleMember> consolidatedMembers = task.consolidateDomainAdmins(domainRoleMembers);
        Assert.assertEquals(consolidatedMembers.size(), 3);

        DomainRoleMember domainRoleMember = consolidatedMembers.get("user.joe");
        assertNotNull(domainRoleMember);
        Assert.assertEquals(domainRoleMember.getMemberRoles().size(), 1);
        Assert.assertEquals(domainRoleMember.getMemberRoles().get(0).getMemberName(), "user.user1");

        domainRoleMember = consolidatedMembers.get("user.dave");
        assertNotNull(domainRoleMember);
        Assert.assertEquals(domainRoleMember.getMemberRoles().size(), 2);
        List<String> expectedValues = Arrays.asList("user.user2", "user.user3");
        List<String> actualValues = domainRoleMember.getMemberRoles().stream().map(MemberRole::getMemberName)
                .collect(Collectors.toList());
        assertEqualsNoOrder(expectedValues, actualValues);

        domainRoleMember = consolidatedMembers.get("user.jane");
        assertNotNull(domainRoleMember);
        Assert.assertEquals(domainRoleMember.getMemberRoles().size(), 1);
        Assert.assertEquals(domainRoleMember.getMemberRoles().get(0).getMemberName(), "user.user4");
    }

    @Test
    public void testConsolidateDomainMembersByDomainWithNotifyRoles() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<Role> athenzRoles = new ArrayList<>();

        List<RoleMember> roleMembers1 = new ArrayList<>();
        roleMembers1.add(new RoleMember().setMemberName("user.joe"));
        Role role1 = new Role().setName("athenz:role.admin").setRoleMembers(roleMembers1);
        athenzRoles.add(role1);

        List<RoleMember> roleMembers2 = new ArrayList<>();
        roleMembers2.add(new RoleMember().setMemberName("user.dave"));
        Role role2 = new Role().setName("athenz:role.notify1").setRoleMembers(roleMembers2);
        athenzRoles.add(role2);

        Mockito.when(dbsvc.getRolesByDomain("athenz")).thenReturn(athenzRoles);
        Mockito.when(dbsvc.getRole("athenz", "notify1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role2);

        List<Role> opsRoles = new ArrayList<>();

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        Role role = new Role().setName("ops:role.notify2").setRoleMembers(roleMembers);
        opsRoles.add(role);

        Mockito.when(dbsvc.getRolesByDomain("ops")).thenReturn(opsRoles);
        Mockito.when(dbsvc.getRole("ops", "notify2", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(role);

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);

        Map<String, List<MemberRole>> domainRoleMembers = new HashMap<>();

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("user.user1").setDomainName("athenz").setRoleName("dev-team"));
        memberRoles.add(new MemberRole().setMemberName("user.user2").setDomainName("athenz").setRoleName("qa-team")
                .setNotifyRoles("notify1"));
        domainRoleMembers.put("athenz", memberRoles);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("user.user3").setDomainName("sports").setRoleName("dev-team")
                .setNotifyRoles("athenz:role.notify1"));
        domainRoleMembers.put("sports", memberRoles);

        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setMemberName("user.user4").setDomainName("weather").setRoleName("dev-team")
                .setNotifyRoles("ops:role.notify2"));
        domainRoleMembers.put("weather", memberRoles);

        Map<String, DomainRoleMember> consolidatedMembers = task.consolidateDomains(domainRoleMembers);
        Assert.assertEquals(consolidatedMembers.size(), 3);

        DomainRoleMember domainRoleMember = consolidatedMembers.get("user.jane");
        assertNotNull(domainRoleMember);
        Assert.assertEquals(domainRoleMember.getMemberRoles().size(), 1);
        Assert.assertEquals(domainRoleMember.getMemberRoles().get(0).getMemberName(), "user.user4");

        domainRoleMember = consolidatedMembers.get("user.dave");
        assertNotNull(domainRoleMember);
        Assert.assertEquals(domainRoleMember.getMemberRoles().size(), 2);
        List<String> expectedValues = Arrays.asList("user.user2", "user.user3");
        List<String> actualValues = domainRoleMember.getMemberRoles().stream().map(MemberRole::getMemberName)
                .collect(Collectors.toList());
        assertEqualsNoOrder(expectedValues, actualValues);

        domainRoleMember = consolidatedMembers.get("athenz");
        assertNotNull(domainRoleMember);
        Assert.assertEquals(domainRoleMember.getMemberRoles().size(), 1);
        Assert.assertEquals(domainRoleMember.getMemberRoles().get(0).getMemberName(), "user.user1");
    }

    @Test
    public void testProcessMemberReminderEmptyRoles() {

        DBService dbsvc = Mockito.mock(DBService.class);

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);
        assertTrue(task.processMemberReminder(null, null).isEmpty());
        assertTrue(task.processMemberReminder(Collections.emptyList(), null).isEmpty());
    }

    @Test
    public void testGetConsolidatedNotificationDetails() {

        // generate our data set

        Map<String, DomainRoleMember> members = new HashMap<>();
        Timestamp currentTime = Timestamp.fromCurrentTime();

        DomainRoleMember domainRoleMember = new DomainRoleMember().setMemberName("home.joe.openhouse");
        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("deployment").setDomainName("home.joe")
                .setMemberName("home.joe.openhouse").setReviewReminder(currentTime));
        domainRoleMember.setMemberRoles(memberRoles);
        members.put("home.joe.openhouse", domainRoleMember);

        domainRoleMember = new DomainRoleMember().setMemberName("athenz.backend");
        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("deployment").setDomainName("home.joe")
                .setMemberName("athenz.backend").setReviewReminder(currentTime));
        domainRoleMember.setMemberRoles(memberRoles);
        members.put("athenz.backend", domainRoleMember);

        domainRoleMember = new DomainRoleMember().setMemberName("athenz.api");
        memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("deployment").setDomainName("home.joe")
                .setMemberName("athenz.api").setReviewReminder(currentTime));
        domainRoleMember.setMemberRoles(memberRoles);
        members.put("athenz.api", domainRoleMember);

        DBService dbsvc = Mockito.mock(DBService.class);
        Role roleHome = new Role().setName("home.joe:role.admin");
        roleHome.setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.joe")));
        Mockito.when(dbsvc.getRole("home.joe", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(roleHome);
        Role roleAthenz = new Role().setName("athenz:role.admin");
        roleAthenz.setRoleMembers(Arrays.asList(new RoleMember().setMemberName("user.joe"),
                new RoleMember().setMemberName("user.jane")));
        Mockito.when(dbsvc.getRole("athenz", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(roleAthenz);

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX);

        UserAuthority userAuthority = Mockito.mock(UserAuthority.class);

        NotificationConverterCommon notificationConverterCommon
                = new NotificationConverterCommon(userAuthority);

        RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter =
                Mockito.mock(RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter.class);
        Mockito.when(disableRoleMemberNotificationFilter.getDisabledNotificationState(any()))
                .thenReturn(DisableNotificationEnum.getEnumSet(0));

        List<Notification> notifications = task.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_REVIEW, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                disableRoleMemberNotificationFilter,
                null);

        // we're supposed to get 3 notifications back - one for user.joe as the
        // owner of the principals, one for user.joe as the domain admin and another
        // for user.jane as domain admin

        assertEquals(notifications.size(), 3);

        // get the notification for user.joe as the admin of the domains

        Notification notification = getNotification(notifications, "user.joe", NOTIFICATION_DETAILS_ROLES_LIST);
        assertNotNull(notification);

        assertEquals(notification.getRecipients().size(), 1);
        assertEquals(notification.getDetails().size(), 2);
        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "home.joe;deployment;athenz.api;" + currentTime +
                        ";|home.joe;deployment;home.joe.openhouse;" + currentTime +
                        ";|home.joe;deployment;athenz.backend;" + currentTime + ";"
        );

        // get the notification for user.jane as the admin of the domains

        notification = getNotification(notifications, "user.jane", NOTIFICATION_DETAILS_ROLES_LIST);
        assertNotNull(notification);

        assertEquals(notification.getRecipients().size(), 1);
        assertEquals(notification.getDetails().size(), 2);
        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.jane");
        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "home.joe;deployment;athenz.api;" + currentTime +
                        ";|home.joe;deployment;athenz.backend;" + currentTime + ";"
        );

        // get the notification for user.joe as the owner of the principals

        notification = getNotification(notifications, "user.joe", NOTIFICATION_DETAILS_MEMBERS_LIST);
        assertNotNull(notification);

        assertEquals(notification.getRecipients().size(), 1);
        assertEquals(notification.getDetails().size(), 1);
        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "home.joe;deployment;athenz.api;" + currentTime +
                        ";|home.joe;deployment;home.joe.openhouse;" + currentTime +
                        ";|home.joe;deployment;athenz.backend;" + currentTime + ";"
        );
    }

    private Notification getNotification(List<Notification> notifications, String recipient, String detailsKey) {
        for (Notification notification : notifications) {
            if (notification.getRecipients().contains(recipient) && notification.getDetails().containsKey(detailsKey)) {
                return notification;
            }
        }
        return null;
    }

    @Test
    public void testExpiryPrincipalGetNotificationDetailsWithNotificationObjectStore() throws ServerResourceException {

        NotificationObjectStore notificationObjectStore = new ZMSObjectReviewTest.NotificationObjectStoreImpl(null);

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getRolesByDomain(eq("test.domain:group"))).thenThrow(new ResourceException(NOT_FOUND));
        Role group1Admin = new Role().setName("groupdomain1:role.admin")
                .setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRole("groupdomain1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(group1Admin);
        Role athenzAdmin = new Role().setName("athenz1:role.admin")
                .setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(athenzAdmin);
        Mockito.when(dbsvc.getGroup("test.domain", "testgroup", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(new Group().setName("test.domain:group.testgroup"));
        Mockito.when(dbsvc.getRole("test.domain", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(new Role().setName("test.domain:role.admin"));

        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc,
                USER_DOMAIN_PREFIX);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

        // Verify no notification for member without member roles
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("user.joe", roleMember);
        DomainRoleMember groupMember = new DomainRoleMember();
        groupMember.setMemberName("test.domain:group.testgroup");
        members.put("test.domain:group.testgroup", groupMember);
        List<Notification> notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.PRINCIPAL, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToSlackConverter(notificationConverterCommon),
                notificationObjectStore);

        assertEquals(notifications.size(), 0);
        assertTrue(ZMSUtils.isCollectionEmpty(notificationObjectStore.getReviewObjects("user.joe")));

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        groupMember.setMemberRoles(Collections.emptyList());
        notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                notificationObjectStore);

        assertEquals(notifications.size(), 0);
        assertTrue(ZMSUtils.isCollectionEmpty(notificationObjectStore.getReviewObjects("user.joe")));

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs).setNotifyDetails("notify details"));
        roleMember.setMemberRoles(memberRoles);
        List<MemberRole> groupMemberRoles = new ArrayList<>();
        groupMemberRoles.add(new MemberRole().setRoleName("grouprole1").setDomainName("groupdomain1")
                .setMemberName("test.domain:group.testgroup")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        groupMember.setMemberRoles(groupMemberRoles);
        notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                notificationObjectStore);

        assertEquals(notifications.size(), 2);
        assertEquals(notifications.get(0).getDetails().size(), 2);
        assertEquals(notifications.get(1).getDetails().size(), 1);
        List<String> objects = notificationObjectStore.getReviewObjects("user.testadmin");
        assertEquals(objects.size(), 1);
        assertTrue(objects.contains("athenz1:role.role1"));

        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details");
        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(notifications.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));

        notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                notificationObjectStore);
        objects = notificationObjectStore.getReviewObjects("user.testadmin");
        assertEquals(objects.size(), 1);
        assertTrue(objects.contains("athenz1:role.role1"));

        assertEquals(notifications.size(), 2);
        assertEquals(notifications.get(0).getDetails().size(), 2);
        assertEquals(notifications.get(1).getDetails().size(), 1);
        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details|athenz2;role1;user.joe;" + expirationTs
                        + ";|athenz2;role2;user.joe;" + expirationTs + ";");
        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details|athenz2;role1;user.joe;" + expirationTs
                        + ";|athenz2;role2;user.joe;" + expirationTs + ";");
    }

    @Test
    public void testExpiryPrincipalGetNotificationDetailsWithNotificationObjectStoreException() throws ServerResourceException {

        // make sure the commands are completed without any errors

        NotificationObjectStore notificationObjectStore = Mockito.mock(NotificationObjectStore.class);
        Mockito.doThrow(new ServerResourceException(500)).when(notificationObjectStore)
                .registerReviewObjects(Mockito.anyString(), Mockito.anyList());

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getRolesByDomain(eq("test.domain:group"))).thenThrow(new ResourceException(NOT_FOUND));
        Role group1Admin = new Role().setName("groupdomain1:role.admin")
                .setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRole("groupdomain1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(group1Admin);
        Role athenzAdmin = new Role().setName("athenz1:role.admin")
                .setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(athenzAdmin);
        Mockito.when(dbsvc.getGroup("test.domain", "testgroup", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(new Group().setName("test.domain:group.testgroup"));
        Mockito.when(dbsvc.getRole("test.domain", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(new Role().setName("test.domain:role.admin"));

        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc,
                USER_DOMAIN_PREFIX);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

        // Verify no notification for member without member roles
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("user.joe", roleMember);
        DomainRoleMember groupMember = new DomainRoleMember();
        groupMember.setMemberName("test.domain:group.testgroup");
        members.put("test.domain:group.testgroup", groupMember);
        List<Notification> notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.PRINCIPAL, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToSlackConverter(notificationConverterCommon),
                notificationObjectStore);

        assertEquals(notifications.size(), 0);

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        groupMember.setMemberRoles(Collections.emptyList());
        notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                notificationObjectStore);

        assertEquals(notifications.size(), 0);

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs).setNotifyDetails("notify details"));
        roleMember.setMemberRoles(memberRoles);
        List<MemberRole> groupMemberRoles = new ArrayList<>();
        groupMemberRoles.add(new MemberRole().setRoleName("grouprole1").setDomainName("groupdomain1")
                .setMemberName("test.domain:group.testgroup")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        groupMember.setMemberRoles(groupMemberRoles);
        notifications = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0),
                notificationObjectStore);

        assertEquals(notifications.size(), 2);
        assertEquals(notifications.get(0).getDetails().size(), 2);
        assertEquals(notifications.get(1).getDetails().size(), 1);

        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details");
        assertEquals(notifications.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(notifications.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "athenz1;role1;user.joe;" + expirationTs + ";notify+details");
    }

    @Test
    public void testRegisterNotificationObjects() throws ServerResourceException {

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(null, USER_DOMAIN_PREFIX);
        NotificationObjectStore notificationObjectStore = Mockito.mock(NotificationObjectStore.class);
        Mockito.doThrow(new ServerResourceException(500)).when(notificationObjectStore)
                .registerReviewObjects(Mockito.anyString(), Mockito.anyList());

        // make sure all our methods complete without any exceptions
        // when the consolidated by is not set to principal

        MemberRole memberRole = new MemberRole().setRoleName("role1").setDomainName("athenz1");

        task.registerNotificationObjects(notificationObjectStore, Notification.ConsolidatedBy.DOMAIN,
                "user.joe", List.of(memberRole));

        // verify that the registerReviewObjects method for the notificationObjectStore
        // was not called

        Mockito.verify(notificationObjectStore, Mockito.never()).registerReviewObjects(Mockito.anyString(), Mockito.anyList());

        // now let's set the consolidated by to principal but only include
        // not human principal which should also be ignored

        task.registerNotificationObjects(notificationObjectStore, Notification.ConsolidatedBy.PRINCIPAL,
                "athenz.api", List.of(memberRole));

        // verify that the registerReviewObjects method for the notificationObjectStore
        // was not called

        Mockito.verify(notificationObjectStore, Mockito.never()).registerReviewObjects(Mockito.anyString(), Mockito.anyList());

        // finally just verify that with a user type we'll get our exception

        task.registerNotificationObjects(notificationObjectStore, Notification.ConsolidatedBy.PRINCIPAL,
                    "user.joe", List.of(memberRole));

        // verify that the registerReviewObjects method for the notificationObjectStore was called once

        Mockito.verify(notificationObjectStore, Mockito.times(1)).registerReviewObjects(Mockito.eq("user.joe"),
                Mockito.anyList());
    }
}
