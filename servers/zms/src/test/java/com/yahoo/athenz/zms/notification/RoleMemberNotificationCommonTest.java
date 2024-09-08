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
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationToEmailConverterCommon;
import com.yahoo.athenz.zms.*;
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
import static org.testng.AssertJUnit.assertEquals;

public class RoleMemberNotificationCommonTest {

    @Test
    public void testExpiryPrincipalGetNotificationDetails() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getRolesByDomain(eq("test.domain:group"))).thenThrow(new ResourceException(NOT_FOUND));
        List<Role> adminMembers = new ArrayList<>();
        Role admin = new Role();
        admin.setRoleMembers(Collections.singletonList(new RoleMember().setMemberName("user.testadmin")));
        admin.setName("groupdomain1:role.admin");
        adminMembers.add(admin);
        Mockito.when(dbsvc.getRolesByDomain(eq("groupdomain1"))).thenReturn(adminMembers);
        Mockito.when(dbsvc.getRole("groupdomain1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(admin);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc,
                USER_DOMAIN_PREFIX, false);
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

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
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(0, notification.size());

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        groupMember.setMemberRoles(Collections.emptyList());
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(0, notification.size());

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        roleMember.setMemberRoles(memberRoles);
        List<MemberRole> groupMemberRoles = new ArrayList<>();
        groupMemberRoles.add(new MemberRole().setRoleName("grouprole1").setDomainName("groupdomain1")
                .setMemberName("test.domain:group.testgroup")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        groupMember.setMemberRoles(groupMemberRoles);
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(2, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());
        assertEquals(2, notification.get(1).getDetails().size());

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_DOMAIN),
                "groupdomain1");
        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "groupdomain1;grouprole1;test.domain:group.testgroup;" + expirationTs);

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));

        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(2, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());
        assertEquals(2, notification.get(1).getDetails().size());
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + "|athenz2;role1;user.joe;" + expirationTs
                        + "|athenz2;role2;user.joe;" + expirationTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + "|athenz2;role1;user.joe;" + expirationTs
                        + "|athenz2;role2;user.joe;" + expirationTs);
    }

    @Test
    public void testExpiryPrincipalGetNotificationDetailsWithGroups() {

        DBService dbsvc = Mockito.mock(DBService.class);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbsvc,
                USER_DOMAIN_PREFIX, true);
        NotificationToEmailConverterCommon notificationToEmailConverterCommon =
                new NotificationToEmailConverterCommon(null);

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
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(4, notifications.size());
        for (Notification notification : notifications) {
            assertEquals(notification.getRecipients().size(), 1);
            final String principal = notification.getRecipients().iterator().next();
            switch (principal) {
                case "user.user1":
                    if (notification.getDetails().size() == 1) {
                        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                                "athenz;role1;athenz:group.dev-team;null");
                    } else if (notification.getDetails().size() == 2) {
                        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                                "athenz;role1;athenz:group.dev-team;null");
                        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.user1");
                    } else {
                        fail();
                    }
                    break;
                case "user.user2":
                    assertEquals(notification.getDetails().size(), 1);
                    assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                            "sports;role2;sports:group.qa-team;null");
                    break;
                case "user.user3":
                    assertEquals(notification.getDetails().size(), 2);
                    assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                            "sports;role2;sports:group.qa-team;null");
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
        Role adminRole = new Role().setName("athenz1:role.admin").setRoleMembers(Arrays.asList(
                new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRolesByDomain(eq("athenz1"))).thenReturn(Arrays.asList(adminRole));
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX, false);
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

        // Verify no notification for member without member roles
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        Map<String, DomainRoleMember> members = new HashMap<>();
        members.put("user.joe", roleMember);
        List<Notification> notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(0, notification.size());

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));
        assertEquals(0, notification.size());

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        roleMember.setMemberRoles(memberRoles);

        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(2, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());
        assertEquals(2, notification.get(1).getDetails().size());

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + reviewTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "athenz1;role1;user.joe;" + reviewTs);
        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_DOMAIN), "athenz1");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));

        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(2, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());
        String expectedRolesList = "athenz1;role1;user.joe;" + reviewTs +
                "|athenz2;role1;user.joe;" + reviewTs +
                "|athenz2;role2;user.joe;" + reviewTs;
        assertEquals(expectedRolesList,
                notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST));
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(expectedRolesList,
                notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST));

        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "athenz1;role1;user.joe;" + reviewTs);
        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_DOMAIN), "athenz1");
    }


    @Test
    public void testReviewGetNotificationDetailsFilterTag() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Role adminRole = new Role().setName("athenz1:role.admin").setRoleMembers(Arrays.asList(
                new RoleMember().setMemberName("user.testadmin")));
        Mockito.when(dbsvc.getRolesByDomain(eq("athenz1"))).thenReturn(Arrays.asList(adminRole));
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);
        RoleMemberNotificationCommon roleMemberNotificationCommon = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX, false);
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

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
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(1));

        assertEquals(1, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "athenz1;role1;user.joe;" + reviewTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_DOMAIN), "athenz1");

        // Verify disable notification for admins
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(2));

        assertEquals(1, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + reviewTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        // Verify disable all notifications
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(3));

        assertEquals(0, notification.size());
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
                USER_DOMAIN_PREFIX, true);
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

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
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(0, notification.size());

        // Verify the same result when setting the memberRoles to an empty collection
        roleMember.setMemberRoles(Collections.emptyList());
        groupMember.setMemberRoles(Collections.emptyList());
        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(0, notification.size());

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);

        members = new HashMap<>();

        roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");
        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("grouprole1").setDomainName("groupdomain1")
                .setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        roleMember.setMemberRoles(memberRoles);
        members.put("user.joe", roleMember);

        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(2, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());
        assertEquals(1, notification.get(1).getDetails().size());

        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + "|groupdomain1;grouprole1;user.joe;" + expirationTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "groupdomain1;grouprole1;user.joe;" + expirationTs);

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(expirationTs).setReviewReminder(reviewTs));

        notification = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY, members,
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer(),
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter(),
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter(),
                memberRole -> DisableNotificationEnum.getEnumSet(0));

        assertEquals(2, notification.size());
        assertEquals(2, notification.get(0).getDetails().size());
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "athenz1;role1;user.joe;" + expirationTs + "|groupdomain1;grouprole1;user.joe;" + expirationTs
                    + "|athenz2;role1;user.joe;" + expirationTs + "|athenz2;role2;user.joe;" + expirationTs);
        assertEquals(notification.get(0).getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        assertEquals(notification.get(1).getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "groupdomain1;grouprole1;user.joe;" + expirationTs);
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
                dbsvc, USER_DOMAIN_PREFIX, true);

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
        assertEquals(1, consolidatedMembers.size());
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

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX, true);

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
        assertEquals(1, consolidatedMembers.size());
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

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX, true);

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
        Assert.assertEquals(3, consolidatedMembers.size());

        DomainRoleMember domainRoleMember = consolidatedMembers.get("user.joe");
        assertNotNull(domainRoleMember);
        Assert.assertEquals(1, domainRoleMember.getMemberRoles().size());
        Assert.assertEquals("user.user1", domainRoleMember.getMemberRoles().get(0).getMemberName());

        domainRoleMember = consolidatedMembers.get("user.dave");
        assertNotNull(domainRoleMember);
        Assert.assertEquals(2, domainRoleMember.getMemberRoles().size());
        List<String> expectedValues = Arrays.asList("user.user2", "user.user3");
        List<String> actualValues = domainRoleMember.getMemberRoles().stream().map(MemberRole::getMemberName)
                .collect(Collectors.toList());
        assertEqualsNoOrder(expectedValues, actualValues);

        domainRoleMember = consolidatedMembers.get("user.jane");
        assertNotNull(domainRoleMember);
        Assert.assertEquals(1, domainRoleMember.getMemberRoles().size());
        Assert.assertEquals("user.user4", domainRoleMember.getMemberRoles().get(0).getMemberName());
    }

    @Test
    public void testProcessMemberReminderEmptyRoles() {

        DBService dbsvc = Mockito.mock(DBService.class);

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX, true);
        assertTrue(task.processMemberReminder("athenz", null, null).isEmpty());
        assertTrue(task.processMemberReminder("athenz", Collections.emptyList(), null).isEmpty());
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

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(dbsvc, USER_DOMAIN_PREFIX, true);

        UserAuthority userAuthority = Mockito.mock(UserAuthority.class);

        NotificationToEmailConverterCommon notificationToEmailConverterCommon
                = new NotificationToEmailConverterCommon(userAuthority);

        RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter =
                Mockito.mock(RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter.class);
        Mockito.when(disableRoleMemberNotificationFilter.getDisabledNotificationState(any()))
                .thenReturn(DisableNotificationEnum.getEnumSet(0));

        List<Notification> notifications = task.getConsolidatedNotificationDetails(
                Notification.Type.ROLE_MEMBER_REVIEW, members,
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationToEmailConverterCommon),
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer(),
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter(),
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter(),
                disableRoleMemberNotificationFilter);

        // we're supposed to get 3 notifications back - one for user.joe as the
        // owner of the principals, one for user.joe as the domain admin and another
        // for user.jane as domain admin

        assertEquals(3, notifications.size());

        // get the notification for user.joe as the admin of the domains

        Notification notification = getNotification(notifications, "user.joe", NOTIFICATION_DETAILS_ROLES_LIST);
        assertNotNull(notification);

        assertEquals(1, notification.getRecipients().size());
        assertEquals(2, notification.getDetails().size());
        assertEquals("user.joe", notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER));
        assertEquals("home.joe;deployment;athenz.api;" + currentTime +
                        "|home.joe;deployment;home.joe.openhouse;" + currentTime +
                        "|home.joe;deployment;athenz.backend;" + currentTime,
                notification.getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST));

        // get the notification for user.jane as the admin of the domains

        notification = getNotification(notifications, "user.jane", NOTIFICATION_DETAILS_ROLES_LIST);
        assertNotNull(notification);

        assertEquals(1, notification.getRecipients().size());
        assertEquals(2, notification.getDetails().size());
        assertEquals("user.jane", notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER));
        assertEquals("home.joe;deployment;athenz.api;" + currentTime +
                        "|home.joe;deployment;athenz.backend;" + currentTime,
                notification.getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST));

        // get the notification for user.joe as the owner of the principals

        notification = getNotification(notifications, "user.joe", NOTIFICATION_DETAILS_MEMBERS_LIST);
        assertNotNull(notification);

        assertEquals(1, notification.getRecipients().size());
        assertEquals(1, notification.getDetails().size());
        assertEquals("home.joe;deployment;athenz.api;" + currentTime +
                        "|home.joe;deployment;home.joe.openhouse;" + currentTime +
                        "|home.joe;deployment;athenz.backend;" + currentTime,
                notification.getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST));
    }

    private Notification getNotification(List<Notification> notifications, String recipient, String detailsKey) {
        for (Notification notification : notifications) {
            if (notification.getRecipients().contains(recipient) && notification.getDetails().containsKey(detailsKey)) {
                return notification;
            }
        }
        return null;
    }
}
