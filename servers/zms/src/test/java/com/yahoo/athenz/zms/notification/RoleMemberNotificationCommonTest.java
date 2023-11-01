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

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationToEmailConverterCommon;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.zms.ResourceException.NOT_FOUND;
import static org.mockito.ArgumentMatchers.eq;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
                members,
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
    }

    @Test
    public void testProcessMemberReminderEmptyRoles() {

        DBService dbsvc = Mockito.mock(DBService.class);

        RoleMemberNotificationCommon task = new RoleMemberNotificationCommon(
                dbsvc, USER_DOMAIN_PREFIX, true);
        assertTrue(task.processMemberReminder("athenz", null, null).isEmpty());
        assertTrue(task.processMemberReminder("athenz", Collections.emptyList(), null).isEmpty());
    }
}
