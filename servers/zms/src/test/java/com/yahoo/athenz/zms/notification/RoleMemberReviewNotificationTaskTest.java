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

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.common.server.store.AthenzDomain;
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

public class RoleMemberReviewNotificationTaskTest {
    final NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

    @Test
    public void testSendRoleMemberRemindersException() throws ServerResourceException {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);

        // we're going to throw an exception when called

        Mockito.when(dbsvc.getRoleReviewMembers(1)).thenThrow(new IllegalArgumentException());
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        RoleMemberReviewNotificationTask roleMemberReviewNotificationTask = new RoleMemberReviewNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, notificationConverterCommon);

        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        try {
            roleMemberReviewNotificationTask.getNotifications();
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }
        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberReviewRemindersEmptySet() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        RoleMemberReviewNotificationTask roleMemberReviewNotificationTask = new RoleMemberReviewNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, notificationConverterCommon);
        assertEquals(roleMemberReviewNotificationTask.getNotifications(), new ArrayList<>());

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberReviewReminders() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setReviewReminder(Timestamp.fromMillis(100)));
        DomainRoleMember domainRoleMember = new DomainRoleMember()
                .setMemberName("user.joe")
                .setMemberRoles(memberRoles);
        Map<String, DomainRoleMember> reviewMembers = new HashMap<>();
        reviewMembers.put("user.joe", domainRoleMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleReviewMembers(1))
                .thenReturn(null)
                .thenReturn(reviewMembers);

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
                .thenReturn(adminRole);
        Domain athenz1Domain = new Domain().setName("athenz1").setSlackChannel("channel-1");
        Mockito.when(dbsvc.getDomain("athenz1", false)).thenReturn(athenz1Domain);

        List<Notification> notifications = new RoleMemberReviewNotificationTask(dbsvc,
                USER_DOMAIN_PREFIX, notificationConverterCommon).getNotifications();

        // we should get 2 notifications - one for user and one for domain
        assertEquals(notifications.size(), 4);

        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedFirstNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedFirstNotification.addDetails("member", "user.joe");
        expectedFirstNotification.setNotificationToEmailConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon));
        expectedFirstNotification.setNotificationToMetricConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter());
        expectedFirstNotification.setNotificationToSlackMessageConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedSecondNotification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedSecondNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedSecondNotification.setNotificationToEmailConverter(
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon));
        expectedSecondNotification.setNotificationToMetricConverter(
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter());
        expectedSecondNotification.setNotificationToSlackMessageConverter(new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToSlackConverter(notificationConverterCommon));


        Notification expectedThirdNotification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        expectedThirdNotification.addRecipient("user.joe");
        expectedThirdNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedThirdNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedThirdNotification.addDetails("member", "user.joe");
        expectedThirdNotification.setNotificationToEmailConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon));
        expectedThirdNotification.setNotificationToMetricConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter());
        expectedThirdNotification.setNotificationToSlackMessageConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedFourthNotification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        expectedFourthNotification.addRecipient("athenz1");
        expectedFourthNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedFourthNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedFourthNotification.setNotificationToEmailConverter(
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon));
        expectedFourthNotification.setNotificationToMetricConverter(
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter());
        expectedFourthNotification.setNotificationToSlackMessageConverter(new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToSlackConverter(notificationConverterCommon));
        Map<String, NotificationDomainMeta> notificationDomainMetaMap = new HashMap<>();
        notificationDomainMetaMap.put("athenz1", new NotificationDomainMeta("athenz1").setSlackChannel("channel-1"));
        expectedFourthNotification.setNotificationDomainMeta(notificationDomainMetaMap);

        assertEquals(notifications.get(0), expectedFirstNotification);
        assertEquals(notifications.get(1), expectedSecondNotification);
        assertEquals(notifications.get(2), expectedThirdNotification);
        assertEquals(notifications.get(3), expectedFourthNotification);

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberReviewRemindersDisabledOverOneWeek() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);

        Timestamp twoWeekExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(14, TimeUnit.DAYS));
        Timestamp oneDayExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS));

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setReviewReminder(twoWeekExpiry));
        memberRoles.add(new MemberRole().setRoleName("role2")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setReviewReminder(oneDayExpiry));
        DomainRoleMember domainRoleMember = new DomainRoleMember()
                .setMemberName("user.joe")
                .setMemberRoles(memberRoles);
        Map<String, DomainRoleMember> reviewMembers = new HashMap<>();
        reviewMembers.put("user.joe", domainRoleMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleReviewMembers(1))
                .thenReturn(null)
                .thenReturn(reviewMembers);

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
                .thenReturn(adminRole);

        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList().setList(Collections.singletonList("4"));
        tags.put(ZMSConsts.DISABLE_REMINDER_NOTIFICATIONS_TAG, tagValueList);
        Role role = new Role().setTags(tags);
        Mockito.when(dbsvc.getRole("athenz1", "role1", false, false, false)).thenReturn(role);
        Mockito.when(dbsvc.getRole("athenz1", "role2", false, false, false)).thenReturn(role);
        Domain athenz1Domain = new Domain().setName("athenz1").setSlackChannel("channel-1");
        Mockito.when(dbsvc.getDomain("athenz1", false)).thenReturn(athenz1Domain);
        List<Notification> notifications = new RoleMemberReviewNotificationTask(dbsvc,
                USER_DOMAIN_PREFIX, notificationConverterCommon).getNotifications();

        // we should get 2 notifications - one for user and one for domain
        // role1 should be excluded and role2 should be included

        assertEquals(notifications.size(), 4);

        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedFirstNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role2;user.joe;" + oneDayExpiry + ";");
        expectedFirstNotification.addDetails("member", "user.joe");
        expectedFirstNotification.setNotificationToEmailConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon));
        expectedFirstNotification.setNotificationToMetricConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter());
        expectedFirstNotification.setNotificationToSlackMessageConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedSecondNotification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedSecondNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role2;user.joe;" + oneDayExpiry + ";");
        expectedSecondNotification.setNotificationToEmailConverter(
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon));
        expectedSecondNotification.setNotificationToMetricConverter(
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter());
        expectedSecondNotification.setNotificationToSlackMessageConverter(new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedThirdNotification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        expectedThirdNotification.addRecipient("user.joe");
        expectedThirdNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedThirdNotification.setNotificationDomainMeta(new HashMap<>());
        expectedThirdNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role2;user.joe;" + oneDayExpiry + ";");
        expectedThirdNotification.addDetails("member", "user.joe");
        expectedThirdNotification.setNotificationToEmailConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon));
        expectedThirdNotification.setNotificationToMetricConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter());
        expectedThirdNotification.setNotificationToSlackMessageConverter(new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedFourthNotification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        expectedFourthNotification.addRecipient("athenz1");
        expectedFourthNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedFourthNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role2;user.joe;" + oneDayExpiry + ";");
        expectedFourthNotification.setNotificationToEmailConverter(
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon));
        expectedFourthNotification.setNotificationToMetricConverter(
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter());
        expectedFourthNotification.setNotificationToSlackMessageConverter(new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToSlackConverter(notificationConverterCommon));
        Map<String, NotificationDomainMeta> notificationDomainMetaMap = new HashMap<>();
        notificationDomainMetaMap.put("athenz1", new NotificationDomainMeta("athenz1").setSlackChannel("channel-1"));
        expectedFourthNotification.setNotificationDomainMeta(notificationDomainMetaMap);

        assertEquals(notifications.get(0), expectedFirstNotification);
        assertEquals(notifications.get(1), expectedSecondNotification);
        assertEquals(notifications.get(2), expectedThirdNotification);
        assertEquals(notifications.get(3), expectedFourthNotification);

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberReviewRemindersNoValidDomain() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        DomainRoleMember domainRoleMember = new DomainRoleMember()
                .setMemberRoles(memberRoles);
        Map<String, DomainRoleMember> reviewMembers = new HashMap<>();
        reviewMembers.put("user.joe", domainRoleMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleReviewMembers(1))
                .thenReturn(null)
                .thenReturn(reviewMembers);

        ZMSTestUtils.sleep(1000);

        // we're going to return not found domain always

        Mockito.when(dbsvc.getAthenzDomain("athenz1", false)).thenReturn(null);

        List<Notification> notifications = new RoleMemberReviewNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                notificationConverterCommon).getNotifications();

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

        // First try the review admin reminder

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        notification.setDetails(details);
        RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter converter = new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertFalse(body.contains("user.member1"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        // now set the correct review members details
        // with one bad entry that should be skipped

        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST,
                "athenz;role1;user.joe;2020-12-01T12:00:00.000Z;notify+details%20test|athenz;role1;user.jane;2020-12-01T12:00:00.000Z;|athenz;role3;user.bad");

        NotificationEmail notificationAsEmailWithMembers = converter.getNotificationAsEmail(notification);
        body = notificationAsEmailWithMembers.getBody();
        assertNotNull(body);
        assertTrue(body.contains("user.joe"));
        assertTrue(body.contains("user.jane"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(body.contains("notify details test"));

        // make sure the bad entries are not included

        assertFalse(body.contains("user.bad"));
        assertFalse(body.contains("role3"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        // now try the review principal reminder

        notification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        notification.setDetails(details);
        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;role1;user.joe;2020-12-01T12:00:00.000Z;notify+details|athenz2;role2;user.joe;2020-12-01T12:00:00.000Z;");
        RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter principalConverter =
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon);
        NotificationEmail principalNotificationAsEmail = principalConverter.getNotificationAsEmail(notification);

        body = principalNotificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("athenz1"));
        assertTrue(body.contains("athenz2"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("role2"));
        assertTrue(body.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(body.contains("notify details"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
    }

    @Test
    public void testGetEmailSubject() {
        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter converter =
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Domain Role Member Review Notification");

        notification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter principalConverter =
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon);
        notificationAsEmail = principalConverter.getNotificationAsEmail(notification);
        subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Role Member Review Notification");
    }

    @Test
    public void testReviewRoleMemberDetailStringer() {
        RoleMemberNotificationCommon.RoleMemberDetailStringer stringer =
                new RoleMemberReviewNotificationTask.ReviewRoleMemberDetailStringer();

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
        String expectedStringBuilder = "testDomainName;testRoleName;testMemberName;1970-01-01T00:00:00.050Z;";
        assertEquals(detailStringBuilder.toString(), expectedStringBuilder);

        memberRole.setExpiration(null);
        detailStringBuilder = stringer.getDetailString(memberRole);
        expectedStringBuilder = "testDomainName;testRoleName;testMemberName;1970-01-01T00:00:00.050Z;";
        assertEquals(detailStringBuilder.toString(), expectedStringBuilder);
    }

    @Test
    public void testReviewDisableRoleMemberNotificationFilter() {
        DBService dbsvc = Mockito.mock(DBService.class);

        Role adminRole = new Role().setName("athenz1:role.admin");

        // Role where user review notifications disabled
        Map<String, TagValueList> tags = new HashMap<>();
        tags.put("zms.DisableReminderNotifications", new TagValueList().setList(List.of("1")));
        Role noUserNotif = new Role()
                .setName("athenz1:role.no-user-notif")
                .setTags(tags);

        // Role where user admin review notifications disabled
        tags = new HashMap<>();
        tags.put("zms.DisableReminderNotifications", new TagValueList().setList(List.of("2")));
        Role noAdminNotif = new Role()
                .setName("athenz1:role.no-admin-notif")
                .setTags(tags);

        // Role where all review notifications disabled
        tags = new HashMap<>();
        tags.put("zms.DisableReminderNotifications", new TagValueList().setList(List.of("3")));
        Role noNotifs = new Role()
                .setName("athenz1:role.no-notifs")
                .setTags(tags);

        // Role with invalid tags - all notifications enabled
        tags = new HashMap<>();
        tags.put("zms.DisableReminderNotifications", new TagValueList().setList(List.of("notANumber")));
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

        RoleMemberReviewNotificationTask roleMemberReviewNotificationTask =
                new RoleMemberReviewNotificationTask(dbsvc, USER_DOMAIN_PREFIX, notificationConverterCommon);
        RoleMemberReviewNotificationTask.ReviewDisableRoleMemberNotificationFilter notificationFilter =
                roleMemberReviewNotificationTask.new ReviewDisableRoleMemberNotificationFilter();
        EnumSet<DisableNotificationEnum> disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRole);
        assertTrue(disabledNotificationState.isEmpty());

        disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRoleDisabledUserNotif);
        assertEquals(disabledNotificationState.size(), 1);
        assertTrue(disabledNotificationState.contains(DisableNotificationEnum.USER));

        disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRoleDisabledAdminNotif);
        assertEquals(disabledNotificationState.size(), 1);
        assertTrue(disabledNotificationState.contains(DisableNotificationEnum.ADMIN));

        disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRoleDisabledNotifs);
        assertEquals(disabledNotificationState.size(), 2);
        assertTrue(disabledNotificationState.containsAll(Arrays.asList(DisableNotificationEnum.ADMIN, DisableNotificationEnum.USER)));

        disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRoleInvalid);
        assertTrue(disabledNotificationState.isEmpty());
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

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        notification.setDetails(details);

        RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter domainConverter =
                new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToMetricConverter();

        final NotificationMetric notificationAsMetrics = domainConverter.getNotificationAsMetrics(notification, currentTimeStamp);

        final String[] expectedRecord1 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "25"
        };

        final String[] expectedRecord2 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.jane",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "20"
        };

        final List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(expectedRecord1);
        expectedAttributes.add(expectedRecord2);

        assertEquals(new NotificationMetric(expectedAttributes), notificationAsMetrics);

        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;role1;user.joe;" + twentyFiveDaysFromNow + "|athenz2;role2;user.joe;" + twentyDaysFromNow);
        details.put(NOTIFICATION_DETAILS_MEMBER, "user.joe");

        notification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        notification.setDetails(details);

        RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter principalConverter =
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToMetricConverter();

        final NotificationMetric notificationAsMetricsPrincipal = principalConverter.getNotificationAsMetrics(notification, currentTimeStamp);

        String[] expectedRecord3 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "principal_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "athenz1",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "25"
        };

        String[] expectedRecord4 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "principal_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "athenz2",
                METRIC_NOTIFICATION_ROLE_KEY, "role2",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "20"
        };

        List<String[]> expectedAttributesPrincipal = new ArrayList<>();
        expectedAttributesPrincipal.add(expectedRecord3);
        expectedAttributesPrincipal.add(expectedRecord4);

        assertEquals(new NotificationMetric(expectedAttributesPrincipal), notificationAsMetricsPrincipal);
    }

    @Test
    public void testGetSlackMessage() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");

        // First try the review admin reminder

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToSlackConverter converter = new RoleMemberReviewNotificationTask.RoleReviewDomainNotificationToSlackConverter(notificationConverterCommon);
        NotificationSlackMessage notificationAsSlackMessage = converter.getNotificationAsSlackMessage(notification);
        assertNull(notificationAsSlackMessage);

        notification.setDetails(details);
        notificationAsSlackMessage = converter.getNotificationAsSlackMessage(notification);

        assertNull(notificationAsSlackMessage);

        // now set the correct review members details
        // with one bad entry that should be skipped

        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST,
                "athenz;role1;user.joe;2020-12-01T12:00:00.000Z;notify+details%20test|athenz;role1;user.jane;2020-12-01T12:00:00.000Z;|athenz;role3;user.bad");

        NotificationSlackMessage notificationSlackMessage = converter.getNotificationAsSlackMessage(notification);
        String message = notificationSlackMessage.getMessage();
        assertNotNull(message);
        assertTrue(message.contains("user.joe"));
        assertTrue(message.contains("user.jane"));
        assertTrue(message.contains("role1"));
        assertTrue(message.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(message.contains("notify details test"));

        // make sure the bad entries are not included

        assertFalse(message.contains("user.bad"));
        assertFalse(message.contains("role3"));

        // Make sure support text and url do not appear

        assertFalse(message.contains("slack"));
        assertFalse(message.contains("link.to.athenz.channel.com"));

        // now try the review principal reminder

        notification = new Notification(Notification.Type.ROLE_MEMBER_REVIEW);
        RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToSlackConverter principalConverter =
                new RoleMemberReviewNotificationTask.RoleReviewPrincipalNotificationToSlackConverter(notificationConverterCommon);
        NotificationSlackMessage principalConverterNotificationAsSlackMessage = principalConverter.getNotificationAsSlackMessage(notification);
        assertNull(principalConverterNotificationAsSlackMessage);

        notification.setDetails(details);
        principalConverterNotificationAsSlackMessage = principalConverter.getNotificationAsSlackMessage(notification);
        assertNull(principalConverterNotificationAsSlackMessage);

        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;role1;user.joe;2020-12-01T12:00:00.000Z;notify+details|athenz2;role2;user.joe;2020-12-01T12:00:00.000Z;");
        notification.setDetails(details);
        principalConverterNotificationAsSlackMessage = principalConverter.getNotificationAsSlackMessage(notification);
        message = principalConverterNotificationAsSlackMessage.getMessage();
        assertNotNull(message);
        assertTrue(message.contains("athenz1"));
        assertTrue(message.contains("athenz2"));
        assertTrue(message.contains("role1"));
        assertTrue(message.contains("role2"));
        assertTrue(message.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(message.contains("notify details"));

        // Make sure support text and url do not appear

        assertFalse(message.contains("slack"));
        assertFalse(message.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
    }
}
