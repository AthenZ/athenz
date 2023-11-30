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

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static com.yahoo.athenz.zms.notification.ZMSNotificationManagerTest.getNotificationManager;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertEquals;

public class RoleMemberExpiryNotificationTaskTest {
    final NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

    @Test
    public void testSendRoleMemberExpiryRemindersException() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        // we're going to throw an exception when called

        Mockito.when(dbsvc.getRoleExpiryMembers(1)).thenThrow(new IllegalArgumentException());
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask = new RoleMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationToEmailConverterCommon(null), false);
        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        try {
            roleMemberExpiryNotificationTask.getNotifications();
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }
        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryRemindersEmptySet() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask = new RoleMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationToEmailConverterCommon(null), false);
        assertEquals(roleMemberExpiryNotificationTask.getNotifications(), new ArrayList<>());

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryReminders() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        DomainRoleMember domainRoleMember = new DomainRoleMember()
                .setMemberName("user.joe")
                .setMemberRoles(memberRoles);
        Map<String, DomainRoleMember> expiryMembers = new HashMap<>();
        expiryMembers.put("user.joe", domainRoleMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleExpiryMembers(1))
                .thenReturn(null)
                .thenReturn(expiryMembers);

        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        ZMSTestUtils.sleep(1000);

        AthenzDomain domain = new AthenzDomain("athenz1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        Role adminRole = new Role()
                .setName("athenz1:role.admin")
                .setRoleMembers(roleMembers);
        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        domain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("athenz1")).thenReturn(domain.getRoles());
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenThrow(new UnsupportedOperationException());

        List<Notification> notifications = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                new NotificationToEmailConverterCommon(null), false).getNotifications();


        // we should get 2 notifications - one for user and one for domain
        assertEquals(notifications.size(), 2);

        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification();
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z");
        expectedFirstNotification.addDetails("member", "user.joe");
        expectedFirstNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(
                        new NotificationToEmailConverterCommon(null)));
        expectedFirstNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter());

        Notification expectedSecondNotification = new Notification();
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z");
        expectedSecondNotification.addDetails("domain", "athenz1");
        expectedSecondNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationToEmailConverterCommon(null)));
        expectedSecondNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());

        assertEquals(notifications.get(0), expectedFirstNotification);
        assertEquals(notifications.get(1), expectedSecondNotification);

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryRemindersDisabledOverOneWeek() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        Timestamp twoWeekExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(14, TimeUnit.DAYS));
        Timestamp oneDayExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS));

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(twoWeekExpiry));
        memberRoles.add(new MemberRole().setRoleName("role2")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(oneDayExpiry));
        DomainRoleMember domainRoleMember = new DomainRoleMember()
                .setMemberName("user.joe")
                .setMemberRoles(memberRoles);
        Map<String, DomainRoleMember> expiryMembers = new HashMap<>();
        expiryMembers.put("user.joe", domainRoleMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleExpiryMembers(1))
                .thenReturn(null)
                .thenReturn(expiryMembers);

        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        ZMSTestUtils.sleep(1000);

        AthenzDomain domain = new AthenzDomain("athenz1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        Role adminRole = new Role()
                .setName("athenz1:role.admin")
                .setRoleMembers(roleMembers);
        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        domain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("athenz1")).thenReturn(domain.getRoles());
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenThrow(new UnsupportedOperationException());

        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList().setList(Collections.singletonList("4"));
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, tagValueList);
        Role role = new Role().setTags(tags);
        Mockito.when(dbsvc.getRole("athenz1", "role1", false, false, false)).thenReturn(role);
        Mockito.when(dbsvc.getRole("athenz1", "role2", false, false, false)).thenReturn(role);

        List<Notification> notifications = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                new NotificationToEmailConverterCommon(null), false).getNotifications();

        // we should get 2 notifications - one for user and one for domain
        // role1 should be excluded and role2 should be included

        assertEquals(notifications.size(), 2);

        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification();
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role2;user.joe;" + oneDayExpiry);
        expectedFirstNotification.addDetails("member", "user.joe");
        expectedFirstNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(
                        new NotificationToEmailConverterCommon(null)));
        expectedFirstNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter());

        Notification expectedSecondNotification = new Notification();
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role2;user.joe;" + oneDayExpiry);
        expectedSecondNotification.addDetails("domain", "athenz1");
        expectedSecondNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationToEmailConverterCommon(null)));
        expectedSecondNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());

        assertEquals(notifications.get(0), expectedFirstNotification);
        assertEquals(notifications.get(1), expectedSecondNotification);

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryRemindersNoValidDomain() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        DomainRoleMember domainRoleMember = new DomainRoleMember()
                .setMemberRoles(memberRoles);
        Map<String, DomainRoleMember> expiryMembers = new HashMap<>();
        expiryMembers.put("user.joe", domainRoleMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleExpiryMembers(1))
                .thenReturn(null)
                .thenReturn(expiryMembers);

        ZMSTestUtils.sleep(1000);

        // we're going to return not found domain always

        Mockito.when(dbsvc.getAthenzDomain("athenz1", false)).thenReturn(null);

        List<Notification> notifications = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                new NotificationToEmailConverterCommon(null), false).getNotifications();

        // we should get 0 notifications
        assertEquals(notifications, new ArrayList<>());
    }

    @Test
    public void testGetEmailBody() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");

        Notification notification = new Notification();
        notification.setDetails(details);
        RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter converter =
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationToEmailConverterCommon(null));
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertFalse(body.contains("user.member1"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        // now set the correct expiry members details
        // with one bad entry that should be skipped

        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST,
                "athenz;role1;user.joe;2020-12-01T12:00:00.000Z|athenz;role1;user.jane;2020-12-01T12:00:00.000Z|athenz;role3;user.bad");

        NotificationEmail notificationAsEmailWithMembers = converter.getNotificationAsEmail(notification);
        body = notificationAsEmailWithMembers.getBody();
        assertNotNull(body);
        assertTrue(body.contains("user.joe"));
        assertTrue(body.contains("user.jane"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("2020-12-01T12:00:00.000Z"));

        // make sure the bad entries are not included

        assertFalse(body.contains("user.bad"));
        assertFalse(body.contains("role3"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        // now try the expiry roles reminder
        notification = new Notification();
        notification.setDetails(details);
        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;role1;user.joe;2020-12-01T12:00:00.000Z|athenz2;role2;user.joe;2020-12-01T12:00:00.000Z");
        RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter principalConverter =
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(
                        new NotificationToEmailConverterCommon(null));
        NotificationEmail principalNotificationAsEmail = principalConverter.getNotificationAsEmail(notification);

        body = principalNotificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("athenz1"));
        assertTrue(body.contains("athenz2"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("role2"));
        assertTrue(body.contains("2020-12-01T12:00:00.000Z"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
    }

    @Test
    public void testGetEmailSubject() {
        Notification notification = new Notification();
        RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter converter =
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationToEmailConverterCommon(null));
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Domain Role Member Expiration Notification");

        notification = new Notification();
        RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter principalConverter =
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(
                        new NotificationToEmailConverterCommon(null));
        notificationAsEmail = principalConverter.getNotificationAsEmail(notification);
        subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Role Member Expiration Notification");
    }

    @Test
    public void testExpiryRoleMemberDetailStringer() {
        RoleMemberNotificationCommon.RoleMemberDetailStringer stringer =
                new RoleMemberExpiryNotificationTask.ExpiryRoleMemberDetailStringer();

        final Timestamp expirationTs = Timestamp.fromMillis(100);
        final Timestamp reviewTs = Timestamp.fromMillis(50);
        final Timestamp requestTs = Timestamp.fromMillis(200);

        MemberRole memberRole = new MemberRole();
        memberRole.setExpiration(expirationTs);
        memberRole.setReviewReminder(reviewTs);
        memberRole.setRoleName("testRoleName");
        memberRole.setDomainName("testDomainName");
        memberRole.setMemberName("testMemberName");
        memberRole.setActive(true);
        memberRole.setRequestPrincipal("testReqPrincipal");
        memberRole.setRequestTime(requestTs);
        memberRole.setAuditRef("testAuditRef");

        StringBuilder detailStringBuilder = stringer.getDetailString(memberRole);
        String expectedStringBuilder = "testDomainName;testRoleName;testMemberName;1970-01-01T00:00:00.100Z";
        assertEquals(detailStringBuilder.toString(), expectedStringBuilder);
    }

    @Test
    public void testGetNotificationAsMetric() {
        Timestamp currentTimeStamp = Timestamp.fromCurrentTime();
        Timestamp twentyDaysFromNow = ZMSTestUtils.addDays(currentTimeStamp, 20);
        Timestamp twentyFiveDaysFromNow = ZMSTestUtils.addDays(currentTimeStamp, 25);

        Map<String, String> details = new HashMap<>();
        details.put(NOTIFICATION_DETAILS_DOMAIN, "dom1");
        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST,
                "dom1;role1;user.joe;" + twentyFiveDaysFromNow + "|dom1;role1;user.jane;" + twentyDaysFromNow + "|dom1;role1;user.bad");

        Notification notification = new Notification();
        notification.setDetails(details);

        RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter domainConverter =
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter();

        final NotificationMetric notificationAsMetrics = domainConverter.getNotificationAsMetrics(notification,
                currentTimeStamp);

        final String[] expectedRecord1 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_expiry",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "25"
        };

        final String[] expectedRecord2 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_expiry",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.jane",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "20"
        };

        final List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(expectedRecord1);
        expectedAttributes.add(expectedRecord2);

        assertEquals(new NotificationMetric(expectedAttributes), notificationAsMetrics);

        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;role1;user.joe;" + twentyFiveDaysFromNow + "|athenz2;role2;user.joe;" + twentyDaysFromNow);
        details.put(NOTIFICATION_DETAILS_MEMBER, "user.joe");

        notification = new Notification();
        notification.setDetails(details);

        RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter principalConverter =
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter();

        final NotificationMetric notificationAsMetricsPrincipal = principalConverter.getNotificationAsMetrics(
                notification, currentTimeStamp);

        final String[] expectedRecord3 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "principal_role_membership_expiry",
                METRIC_NOTIFICATION_DOMAIN_KEY, "athenz1",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "25"
        };

        final String[] expectedRecord4 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "principal_role_membership_expiry",
                METRIC_NOTIFICATION_DOMAIN_KEY, "athenz2",
                METRIC_NOTIFICATION_ROLE_KEY, "role2",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "20"
        };

        final List<String[]> expectedAttributesPrincipal = new ArrayList<>();
        expectedAttributesPrincipal.add(expectedRecord3);
        expectedAttributesPrincipal.add(expectedRecord4);

        assertEquals(new NotificationMetric(expectedAttributesPrincipal), notificationAsMetricsPrincipal);
    }

    @Test
    public void testExpiryDisableRoleMemberNotificationFilter() {
        DBService dbsvc = Mockito.mock(DBService.class);

        Role adminRole = new Role().setName("athenz1:role.admin");

        // Role where user review notifications disabled
        Map<String, TagValueList> tags = new HashMap<>();
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, new TagValueList().setList(Arrays.asList("1")));
        Role noUserNotif = new Role()
                .setName("athenz1:role.no-user-notif")
                .setTags(tags);

        // Role where user admin review notifications disabled
        tags = new HashMap<>();
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, new TagValueList().setList(Arrays.asList("2")));
        Role noAdminNotif = new Role()
                .setName("athenz1:role.no-admin-notif")
                .setTags(tags);

        // Role where all review notifications disabled
        tags = new HashMap<>();
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, new TagValueList().setList(Arrays.asList("3")));
        Role noNotifs = new Role()
                .setName("athenz1:role.no-notifs")
                .setTags(tags);

        // Role with invalid tags - all notifications enabled
        tags = new HashMap<>();
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, new TagValueList().setList(Arrays.asList("notANumber")));
        Role invalid = new Role()
                .setName("athenz1:role.invalid")
                .setTags(tags);

        Mockito.when(dbsvc.getRole(eq("athenz1"), eq("admin"), eq(false), eq(false), eq(false))).thenReturn(adminRole);
        Mockito.when(dbsvc.getRole(eq("athenz1"), eq("no-user-notif"), eq(false), eq(false), eq(false))).thenReturn(noUserNotif);
        Mockito.when(dbsvc.getRole(eq("athenz1"), eq("no-admin-notif"), eq(false), eq(false), eq(false))).thenReturn(noAdminNotif);
        Mockito.when(dbsvc.getRole(eq("athenz1"), eq("no-notifs"), eq(false), eq(false), eq(false))).thenReturn(noNotifs);
        Mockito.when(dbsvc.getRole(eq("athenz1"), eq("invalid"), eq(false), eq(false), eq(false))).thenReturn(invalid);

        MemberRole memberRole = new MemberRole().setRoleName("admin")
                .setDomainName("athenz1")
                .setMemberName("user.user1");

        MemberRole memberRoleDisabledUserNotif = new MemberRole().setRoleName("no-user-notif")
                .setDomainName("athenz1")
                .setMemberName("user.user2");

        MemberRole memberRoleDisabledAdminNotif = new MemberRole().setRoleName("no-admin-notif")
                .setDomainName("athenz1")
                .setMemberName("user.user3");

        MemberRole memberRoleDisabledNotifs = new MemberRole().setRoleName("no-notifs")
                .setDomainName("athenz1")
                .setMemberName("user.user4");

        MemberRole memberRoleInvalid = new MemberRole().setRoleName("invalid")
                .setDomainName("athenz1")
                .setMemberName("user.user5");

        RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask = new RoleMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon, false);
        RoleMemberExpiryNotificationTask.ReviewDisableRoleMemberNotificationFilter notificationFilter =
                roleMemberExpiryNotificationTask.new ReviewDisableRoleMemberNotificationFilter();
        EnumSet<DisableNotificationEnum> disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRole);
        assertTrue(disabledNotificationState.isEmpty());

        disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRoleDisabledUserNotif);
        assertEquals(1, disabledNotificationState.size());
        assertTrue(disabledNotificationState.contains(DisableNotificationEnum.USER));

        disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRoleDisabledAdminNotif);
        assertEquals(1, disabledNotificationState.size());
        assertTrue(disabledNotificationState.contains(DisableNotificationEnum.ADMIN));

        disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRoleDisabledNotifs);
        assertEquals(2, disabledNotificationState.size());
        assertTrue(disabledNotificationState.containsAll(Arrays.asList(DisableNotificationEnum.ADMIN,
                DisableNotificationEnum.USER)));

        disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRoleInvalid);
        assertTrue(disabledNotificationState.isEmpty());
    }
}
