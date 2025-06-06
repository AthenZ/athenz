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

import com.yahoo.athenz.auth.impl.UserAuthority;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.common.server.store.AthenzDomain;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static com.yahoo.athenz.zms.notification.ZMSNotificationManagerTest.getNotificationManager;
import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.*;

public class GroupMemberExpiryNotificationTaskTest {
    @Test
    public void testSendGroupMemberExpiryRemindersException() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);

        // we're going to throw an exception when called

        Mockito.when(dbsvc.getGroupExpiryMembers(1)).thenThrow(new IllegalArgumentException());
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        GroupMemberExpiryNotificationTask groupMemberExpiryNotificationTask = new GroupMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));

        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        try {
            groupMemberExpiryNotificationTask.getNotifications(null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }
        notificationManager.shutdown();
    }

    @Test
    public void testSendGroupMemberExpiryRemindersEmptySet() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        GroupMemberExpiryNotificationTask groupMemberExpiryNotificationTask = new GroupMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));
        assertEquals(groupMemberExpiryNotificationTask.getNotifications(), new ArrayList<>());
        assertEquals(groupMemberExpiryNotificationTask.getNotifications(null), new ArrayList<>());

        notificationManager.shutdown();
    }

    @Test
    public void testSendGroupMemberExpiryReminders() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);

        List<GroupMember> memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("group1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        DomainGroupMember domainGroupMember = new DomainGroupMember()
                .setMemberName("user.joe")
                .setMemberGroups(memberGroups);
        Map<String, DomainGroupMember> expiryMembers = new HashMap<>();
        expiryMembers.put("user.joe", domainGroupMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getGroupExpiryMembers(1))
                .thenReturn(null)
                .thenReturn(expiryMembers);

        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        ZMSTestUtils.sleep(1000);

        AthenzDomain domain = new AthenzDomain("athenz1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        Role adminRole = new Role().setName("athenz1:role.admin").setRoleMembers(roleMembers);
        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        domain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("athenz1")).thenReturn(domain.getRoles());
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);
        Domain athenz1Domain = new Domain().setName("athenz1").setSlackChannel("channel-1");
        Mockito.when(dbsvc.getDomain("athenz1", false)).thenReturn(athenz1Domain);

        List<Notification> notifications = new GroupMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                notificationConverterCommon).getNotifications(null);

        // we should get 4 notifications - 2 for user and 2 for domain(consolidated by principal and domain)
        assertEquals(notifications.size(), 4);

        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedFirstNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;group1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedFirstNotification.addDetails("member", "user.joe");
        expectedFirstNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedFirstNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter());
        expectedFirstNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedSecondNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedSecondNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;group1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedSecondNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedSecondNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter());
        expectedSecondNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedThirdNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedThirdNotification.addRecipient("user.joe");
        expectedThirdNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedThirdNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;group1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedThirdNotification.addDetails("member", "user.joe");
        expectedThirdNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedThirdNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter());
        expectedThirdNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedFourthNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedFourthNotification.addRecipient("athenz1");
        expectedFourthNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedFourthNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;group1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedFourthNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedFourthNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter());
        expectedFourthNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(notificationConverterCommon));
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
    public void testSendGroupMemberExpiryRemindersDisabledOverOneWeek() throws ServerResourceException {
        testSendGroupMemberExpiryRemindersDisabledOverOneWeekWithTag(ZMSConsts.DISABLE_REMINDER_NOTIFICATIONS_TAG);
        testSendGroupMemberExpiryRemindersDisabledOverOneWeekWithTag(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG);
    }

    void testSendGroupMemberExpiryRemindersDisabledOverOneWeekWithTag(final String tag) throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);

        Timestamp twoWeekExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(14, TimeUnit.DAYS));
        Timestamp oneDayExpiry = Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS));

        List<GroupMember> memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("group1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(twoWeekExpiry));
        memberGroups.add(new GroupMember().setGroupName("group2")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(oneDayExpiry));
        DomainGroupMember domainGroupMember = new DomainGroupMember()
                .setMemberName("user.joe")
                .setMemberGroups(memberGroups);
        Map<String, DomainGroupMember> expiryMembers = new HashMap<>();
        expiryMembers.put("user.joe", domainGroupMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getGroupExpiryMembers(1))
                .thenReturn(null)
                .thenReturn(expiryMembers);

        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        ZMSTestUtils.sleep(1000);

        AthenzDomain domain = new AthenzDomain("athenz1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        Role adminRole = new Role().setName("athenz1:role.admin").setRoleMembers(roleMembers);
        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        domain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("athenz1")).thenReturn(domain.getRoles());
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);

        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList().setList(Collections.singletonList("4"));
        tags.put(tag, tagValueList);
        Group group = new Group().setTags(tags);
        Mockito.when(dbsvc.getGroup("athenz1", "group1", false, false)).thenReturn(group);
        Mockito.when(dbsvc.getGroup("athenz1", "group2", false, false)).thenReturn(group);
        Domain athenz1Domain = new Domain().setName("athenz1").setSlackChannel("channel-1");
        Mockito.when(dbsvc.getDomain("athenz1", false)).thenReturn(athenz1Domain);
        List<Notification> notifications = new GroupMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                notificationConverterCommon).getNotifications(null);

        // we should get 4 notifications - one for user and one for domain (consolidated by principal and domain)
        // group1 should be excluded and group2 should be included

        assertEquals(notifications.size(), 4);

        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedFirstNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;group2;user.joe;" + oneDayExpiry + ";");
        expectedFirstNotification.addDetails("member", "user.joe");
        expectedFirstNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedFirstNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter());
        expectedFirstNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedSecondNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedSecondNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;group2;user.joe;" + oneDayExpiry + ";");
        expectedSecondNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedSecondNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter());
        expectedSecondNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedThirdNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedThirdNotification.addRecipient("user.joe");
        expectedThirdNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedThirdNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;group2;user.joe;" + oneDayExpiry + ";");
        expectedThirdNotification.addDetails("member", "user.joe");
        expectedThirdNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedThirdNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter());
        expectedThirdNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedFourthNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedFourthNotification.addRecipient("athenz1");
        expectedFourthNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedFourthNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;group2;user.joe;" + oneDayExpiry + ";");
        expectedFourthNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedFourthNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter());
        expectedFourthNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(notificationConverterCommon));
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
    public void testSendGroupMemberExpiryRemindersNoValidDomain() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<GroupMember> memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("group1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        DomainGroupMember domainGroupMember = new DomainGroupMember()
                .setMemberGroups(memberGroups);
        Map<String, DomainGroupMember> expiryMembers = new HashMap<>();
        expiryMembers.put("user.joe", domainGroupMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getGroupExpiryMembers(1))
                .thenReturn(null)
                .thenReturn(expiryMembers);

        ZMSTestUtils.sleep(1000);

        // we're going to return not found domain always

        Mockito.when(dbsvc.getAthenzDomain("athenz1", false)).thenReturn(null);

        List<Notification> notifications = new GroupMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                new NotificationConverterCommon(null)).getNotifications(null);

        // we should get 0 notifications
        assertEquals(notifications, new ArrayList<>());
    }

    @Test
    public void testGetEmailBody() {
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("group", "group1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");

        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        notification.setDetails(details);
        GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter converter =
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(
                        notificationConverterCommon);
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
                "athenz;group1;user.joe;2020-12-01T12:00:00.000Z;notify+details|athenz;group1;user.jane;2020-12-01T12:00:00.000Z;|athenz;group3;user.bad");

        NotificationEmail notificationAsEmailWithMembers = converter.getNotificationAsEmail(notification);
        body = notificationAsEmailWithMembers.getBody();
        assertNotNull(body);
        assertTrue(body.contains("user.joe"));
        assertTrue(body.contains("user.jane"));
        assertTrue(body.contains("group1"));
        assertTrue(body.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(body.contains("notify details"));

        // make sure the bad entries are not included

        assertFalse(body.contains("user.bad"));
        assertFalse(body.contains("group3"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        // now try the expiry groups reminder
        notification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        notification.setDetails(details);
        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;group1;user.joe;2020-12-01T12:00:00.000Z;notify%20details|athenz2;group2;user.joe;2020-12-01T12:00:00.000Z;");
        GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter principalConverter =
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(
                        notificationConverterCommon);
        NotificationEmail principalNotificationAsEmail = principalConverter.getNotificationAsEmail(notification);

        body = principalNotificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("athenz1"));
        assertTrue(body.contains("athenz2"));
        assertTrue(body.contains("group1"));
        assertTrue(body.contains("group2"));
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
        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter converter =
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(
                        notificationConverterCommon);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Domain Group Member Expiration Notification");

        notification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter principalConverter =
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(
                        notificationConverterCommon);
        notificationAsEmail = principalConverter.getNotificationAsEmail(notification);
        subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Group Member Expiration Notification");
    }

    @Test
    public void testGetNotificationAsMetric() {
        Timestamp currentTimeStamp = Timestamp.fromCurrentTime();
        Timestamp twentyDaysFromNow = ZMSTestUtils.addDays(currentTimeStamp, 20);
        Timestamp twentyFiveDaysFromNow = ZMSTestUtils.addDays(currentTimeStamp, 25);

        Map<String, String> details = new HashMap<>();
        details.put(NOTIFICATION_DETAILS_DOMAIN, "dom1");
        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST,
                "dom1;group1;user.joe;" + twentyFiveDaysFromNow + "|dom1;group1;user.jane;" + twentyDaysFromNow + "|dom1;group3;user.bad");

        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        notification.setDetails(details);

        GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter domainConverter =
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter();

        final NotificationMetric notificationAsMetrics = domainConverter.getNotificationAsMetrics(notification,
                currentTimeStamp);

        final String[] expectedRecord1 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_group_membership_expiry",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_GROUP_KEY, "group1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "25"
        };

        final String[] expectedRecord2 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_group_membership_expiry",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_GROUP_KEY, "group1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.jane",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "20"
        };

        final List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(expectedRecord1);
        expectedAttributes.add(expectedRecord2);

        assertEquals(new NotificationMetric(expectedAttributes), notificationAsMetrics);

        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;group1;user.joe;" + twentyFiveDaysFromNow + "|athenz2;group2;user.joe;" + twentyDaysFromNow);
        details.put(NOTIFICATION_DETAILS_MEMBER, "user.joe");

        notification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        notification.setDetails(details);

        GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter principalConverter =
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter();

        final NotificationMetric notificationAsMetricsPrincipal =
                principalConverter.getNotificationAsMetrics(notification, currentTimeStamp);

        final String[] expectedRecord3 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "principal_group_membership_expiry",
                METRIC_NOTIFICATION_DOMAIN_KEY, "athenz1",
                METRIC_NOTIFICATION_GROUP_KEY, "group1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "25"
        };

        final String[] expectedRecord4 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "principal_group_membership_expiry",
                METRIC_NOTIFICATION_DOMAIN_KEY, "athenz2",
                METRIC_NOTIFICATION_GROUP_KEY, "group2",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "20"
        };

        final List<String[]> expectedAttributesPrincipal = new ArrayList<>();
        expectedAttributesPrincipal.add(expectedRecord3);
        expectedAttributesPrincipal.add(expectedRecord4);

        assertEquals(new NotificationMetric(expectedAttributesPrincipal), notificationAsMetricsPrincipal);
    }

    @Test
    public void testSendConsolidatedGroupMemberExpiryReminders() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);

        List<GroupMember> memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("group1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        memberGroups.add(new GroupMember().setGroupName("group2")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        DomainGroupMember domainGroupMember = new DomainGroupMember()
                .setMemberName("user.joe")
                .setMemberGroups(memberGroups);
        Map<String, DomainGroupMember> expiryMembers = new HashMap<>();
        expiryMembers.put("user.joe", domainGroupMember);

        //include an empty set for jane

        expiryMembers.put("user.jane", new DomainGroupMember().setMemberName("user.jane")
                .setMemberGroups(Collections.emptyList()));

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getGroupExpiryMembers(1))
                .thenReturn(null)
                .thenReturn(expiryMembers);

        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        ZMSTestUtils.sleep(1000);

        AthenzDomain domain = new AthenzDomain("athenz1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        Role adminRole = new Role().setName("athenz1:role.admin").setRoleMembers(roleMembers);
        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        domain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("athenz1")).thenReturn(domain.getRoles());
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);
        Domain athenz1Domain = new Domain().setName("athenz1").setSlackChannel("channel-1");
        Mockito.when(dbsvc.getDomain("athenz1", false)).thenReturn(athenz1Domain);

        List<Notification> notifications = new GroupMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                notificationConverterCommon).getNotifications(null);

        // we should get 4 notifications - 2 for user and 2 for domain (2 consolidated by principal and 2 by domain)
        assertEquals(notifications.size(), 4);

        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedFirstNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;group1;user.joe;1970-01-01T00:00:00.100Z;|athenz1;group2;user.joe;1970-01-01T00:00:00.100Z;");
        expectedFirstNotification.addDetails("member", "user.joe");
        expectedFirstNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedFirstNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter());
        expectedFirstNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedSecondNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedSecondNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST,
                "athenz1;group1;user.joe;1970-01-01T00:00:00.100Z;|athenz1;group2;user.joe;1970-01-01T00:00:00.100Z;");
        expectedSecondNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedSecondNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter());
        expectedSecondNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedThirdNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedThirdNotification.addRecipient("user.joe");
        expectedThirdNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedThirdNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;group1;user.joe;1970-01-01T00:00:00.100Z;|athenz1;group2;user.joe;1970-01-01T00:00:00.100Z;");
        expectedThirdNotification.addDetails("member", "user.joe");
        expectedThirdNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedThirdNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter());
        expectedThirdNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon));

        Notification expectedFourthNotification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        expectedFourthNotification.addRecipient("athenz1");
        expectedFourthNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedFourthNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST,
                "athenz1;group1;user.joe;1970-01-01T00:00:00.100Z;|athenz1;group2;user.joe;1970-01-01T00:00:00.100Z;");
        expectedFourthNotification.setNotificationToEmailConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedFourthNotification.setNotificationToMetricConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter());
        expectedFourthNotification.setNotificationToSlackMessageConverter(
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(notificationConverterCommon));
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
    public void testConsolidateGroupMembers() {

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

        GroupMemberExpiryNotificationTask task = new GroupMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));

        Map<String, DomainGroupMember> members = new HashMap<>();

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe").setDomainName("athenz").setGroupName("dev-team"));
        groupMembers.add(new GroupMember().setMemberName("user.joe").setDomainName("sports").setGroupName("qa-team"));
        DomainGroupMember domainGroupMember = new DomainGroupMember().setMemberName("user.joe")
                .setMemberGroups(groupMembers);
        members.put("user.joe", domainGroupMember);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("athenz.api").setDomainName("athenz").setGroupName("dev-team"));
        groupMembers.add(new GroupMember().setMemberName("athenz.api").setDomainName("coretech").setGroupName("qa-team"));
        domainGroupMember = new DomainGroupMember().setMemberName("athenz.api")
                .setMemberGroups(groupMembers);
        members.put("athenz.api", domainGroupMember);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("sports.api").setDomainName("sports").setGroupName("dev-team"));
        domainGroupMember = new DomainGroupMember().setMemberName("sports.api")
                .setMemberGroups(groupMembers);
        members.put("sports.api", domainGroupMember);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("weather.api").setDomainName("weather").setGroupName("dev-team"));
        domainGroupMember = new DomainGroupMember().setMemberName("weather.api")
                .setMemberGroups(groupMembers);
        members.put("weather.api", domainGroupMember);

        Map<String, DomainGroupMember> consolidatedMembers = task.consolidateGroupMembers(members);
        assertEquals(consolidatedMembers.size(), 1);
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

        GroupMemberExpiryNotificationTask task = new GroupMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));

        Map<String, List<GroupMember>> domainGroupMembers = new HashMap<>();

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("athenz.api").setDomainName("athenz").setGroupName("dev-team"));
        groupMembers.add(new GroupMember().setMemberName("athenz.api").setDomainName("coretech").setGroupName("qa-team"));
        domainGroupMembers.put("athenz", groupMembers);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("sports.api").setDomainName("sports").setGroupName("dev-team"));
        domainGroupMembers.put("sports", groupMembers);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("weather.api").setDomainName("weather").setGroupName("dev-team"));
        domainGroupMembers.put("weather", groupMembers);

        Map<String, DomainGroupMember> consolidatedMembers = task.consolidateDomainAdmins(domainGroupMembers);
        assertEquals(consolidatedMembers.size(), 1);
        assertNotNull(consolidatedMembers.get("user.joe"));

        // empty list should give us empty map

        consolidatedMembers = task.consolidateDomainAdmins(Collections.emptyMap());
        assertTrue(consolidatedMembers.isEmpty());

        // list with null member should give us empty map

        domainGroupMembers = new HashMap<>();
        domainGroupMembers.put("athenz", null);
        consolidatedMembers = task.consolidateDomainAdmins(domainGroupMembers);
        assertTrue(consolidatedMembers.isEmpty());

        // list with empty list as member should give us empty map

        domainGroupMembers = new HashMap<>();
        domainGroupMembers.put("athenz", new ArrayList<>());
        consolidatedMembers = task.consolidateDomainAdmins(domainGroupMembers);
        assertTrue(consolidatedMembers.isEmpty());

        domainGroupMembers = new HashMap<>();

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("athenz.api").setDomainName("athenz").setGroupName("dev-team"));
        groupMembers.add(new GroupMember().setMemberName("athenz.api").setDomainName("coretech").setGroupName("qa-team"));
        domainGroupMembers.put("athenz", groupMembers);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("sports.api").setDomainName("sports").setGroupName("dev-team"));
        domainGroupMembers.put("sports", groupMembers);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("weather.api").setDomainName("weather").setGroupName("dev-team"));
        domainGroupMembers.put("weather", groupMembers);

        Map<String, DomainGroupMember> consolidatedMembersByDomain = task.consolidateDomainAdminsByDomain(domainGroupMembers);
        assertEquals(consolidatedMembersByDomain.size(), 3);
        assertNotNull(consolidatedMembersByDomain.get("sports"));
        assertNotNull(consolidatedMembersByDomain.get("athenz"));
        assertNotNull(consolidatedMembersByDomain.get("weather"));

        // empty list should give us empty map

        consolidatedMembersByDomain = task.consolidateDomainAdminsByDomain(Collections.emptyMap());
        assertTrue(consolidatedMembersByDomain.isEmpty());

        // list with null member should give us empty map

        domainGroupMembers = new HashMap<>();
        domainGroupMembers.put("athenz", null);
        consolidatedMembersByDomain = task.consolidateDomainAdminsByDomain(domainGroupMembers);
        assertTrue(consolidatedMembersByDomain.isEmpty());

        // list with empty list as member should give us empty map

        domainGroupMembers = new HashMap<>();
        domainGroupMembers.put("athenz", new ArrayList<>());
        consolidatedMembersByDomain = task.consolidateDomainAdminsByDomain(domainGroupMembers);
        assertTrue(consolidatedMembersByDomain.isEmpty());
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

        GroupMemberExpiryNotificationTask task = new GroupMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));

        Map<String, List<GroupMember>> domainGroupMembers = new HashMap<>();

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user1").setDomainName("athenz").setGroupName("dev-team"));
        groupMembers.add(new GroupMember().setMemberName("user.user2").setDomainName("athenz").setGroupName("qa-team")
                .setNotifyRoles("notify1"));
        domainGroupMembers.put("athenz", groupMembers);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user3").setDomainName("sports").setGroupName("dev-team")
                .setNotifyRoles("athenz:role.notify1"));
        domainGroupMembers.put("sports", groupMembers);

        groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.user4").setDomainName("weather").setGroupName("dev-team")
                .setNotifyRoles("ops:role.notify2"));
        domainGroupMembers.put("weather", groupMembers);

        Map<String, DomainGroupMember> consolidatedMembers = task.consolidateDomainAdmins(domainGroupMembers);
        Assert.assertEquals(consolidatedMembers.size(), 3);

        DomainGroupMember domainGroupMember = consolidatedMembers.get("user.joe");
        assertNotNull(domainGroupMember);
        Assert.assertEquals(domainGroupMember.getMemberGroups().size(), 1);
        Assert.assertEquals(domainGroupMember.getMemberGroups().get(0).getMemberName(), "user.user1");

        domainGroupMember = consolidatedMembers.get("user.dave");
        assertNotNull(domainGroupMember);
        Assert.assertEquals(domainGroupMember.getMemberGroups().size(), 2);
        List<String> expectedValues = Arrays.asList("user.user2", "user.user3");
        List<String> actualValues = domainGroupMember.getMemberGroups().stream().map(GroupMember::getMemberName)
                .collect(Collectors.toList());
        assertEqualsNoOrder(expectedValues, actualValues);

        domainGroupMember = consolidatedMembers.get("user.jane");
        assertNotNull(domainGroupMember);
        Assert.assertEquals(domainGroupMember.getMemberGroups().size(), 1);
        Assert.assertEquals(domainGroupMember.getMemberGroups().get(0).getMemberName(), "user.user4");

        Map<String, DomainGroupMember> consolidatedMembersByDomain = task.consolidateDomainAdminsByDomain(domainGroupMembers);
        Assert.assertEquals(consolidatedMembersByDomain.size(), 3);

        domainGroupMember = consolidatedMembersByDomain.get("athenz");
        assertNotNull(domainGroupMember);
        Assert.assertEquals(domainGroupMember.getMemberGroups().size(), 1);
        Assert.assertEquals(domainGroupMember.getMemberGroups().get(0).getMemberName(), "user.user1");

        domainGroupMember = consolidatedMembersByDomain.get("user.dave");
        assertNotNull(domainGroupMember);
        Assert.assertEquals(domainGroupMember.getMemberGroups().size(), 2);
        expectedValues = Arrays.asList("user.user2", "user.user3");
        actualValues = domainGroupMember.getMemberGroups().stream().map(GroupMember::getMemberName)
                .collect(Collectors.toList());
        assertEqualsNoOrder(expectedValues, actualValues);

        domainGroupMember = consolidatedMembersByDomain.get("user.jane");
        assertNotNull(domainGroupMember);
        Assert.assertEquals(domainGroupMember.getMemberGroups().size(), 1);
        Assert.assertEquals(domainGroupMember.getMemberGroups().get(0).getMemberName(), "user.user4");
    }

    @Test
    public void testGetDisabledNotificationState() {
        testGetDisabledNotificationStateWithTag(ZMSConsts.DISABLE_REMINDER_NOTIFICATIONS_TAG);
        testGetDisabledNotificationStateWithTag(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG);
    }

    void testGetDisabledNotificationStateWithTag(final String tag) {
        DBService dbsvc = Mockito.mock(DBService.class);

        Map<String, TagValueList> tags1 = new HashMap<>();
        tags1.put(tag, new TagValueList().setList(Collections.singletonList("2")));
        Group group1 = new Group().setName("athenz:group.dev-team").setTags(tags1);

        Map<String, TagValueList> tags2 = new HashMap<>();
        tags2.put(tag, new TagValueList().setList(Collections.singletonList("abc")));
        Group group2 = new Group().setName("athenz:group.qa-team").setTags(tags2);

        Mockito.when(dbsvc.getGroup("athenz", "dev-team", false, false)).thenReturn(group1);
        Mockito.when(dbsvc.getGroup("athenz", "qa-team", false, false)).thenReturn(group2);

        GroupMemberExpiryNotificationTask task = new GroupMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));

        GroupMember groupMember = new GroupMember().setDomainName("athenz").setGroupName("dev-team");
        EnumSet<DisableNotificationEnum> enumSet = task.getDisabledNotificationState(groupMember);
        assertEquals(enumSet.size(), 1);

        groupMember = new GroupMember().setDomainName("athenz").setGroupName("qa-team");
        enumSet = task.getDisabledNotificationState(groupMember);
        assertTrue(enumSet.isEmpty());
    }

    @Test
    public void testProcessEmptyMemberReminder() {

        DBService dbsvc = Mockito.mock(DBService.class);
        GroupMemberExpiryNotificationTask task = new GroupMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));

        Map<String, String> details = task.processMemberReminder(null);
        assertTrue(details.isEmpty());

        details = task.processMemberReminder(Collections.emptyList());
        assertTrue(details.isEmpty());
    }

    @Test
    public void testGetConsolidatedNotificationDetails() {

        // generate our data set

        Map<String, DomainGroupMember> members = new HashMap<>();
        Timestamp currentTime = Timestamp.fromCurrentTime();

        DomainGroupMember domainGroupMember = new DomainGroupMember().setMemberName("home.joe.openhouse");
        List<GroupMember> memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("deployment").setDomainName("home.joe")
                .setMemberName("home.joe.openhouse").setExpiration(currentTime));
        domainGroupMember.setMemberGroups(memberGroups);
        members.put("home.joe.openhouse", domainGroupMember);

        domainGroupMember = new DomainGroupMember().setMemberName("athenz.backend");
        memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("deployment").setDomainName("home.joe")
                .setMemberName("athenz.backend").setExpiration(currentTime));
        domainGroupMember.setMemberGroups(memberGroups);
        members.put("athenz.backend", domainGroupMember);

        domainGroupMember = new DomainGroupMember().setMemberName("athenz.api");
        memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("deployment").setDomainName("home.joe")
                .setMemberName("athenz.api").setExpiration(currentTime).setNotifyDetails("notify details"));
        domainGroupMember.setMemberGroups(memberGroups);
        members.put("athenz.api", domainGroupMember);

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

        GroupMemberExpiryNotificationTask task = new GroupMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));

        UserAuthority userAuthority = Mockito.mock(UserAuthority.class);

        NotificationConverterCommon notificationConverterCommon
                = new NotificationConverterCommon(userAuthority);

        RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter =
                Mockito.mock(RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter.class);
        Mockito.when(disableRoleMemberNotificationFilter.getDisabledNotificationState(any()))
                .thenReturn(DisableNotificationEnum.getEnumSet(0));

        List<Notification> notifications = task.getNotificationDetails(
                members, Notification.ConsolidatedBy.PRINCIPAL,
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter(),
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter(),
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon),
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(notificationConverterCommon),
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
                "home.joe;deployment;athenz.api;" + currentTime + ";notify+details" +
                        "|home.joe;deployment;home.joe.openhouse;" + currentTime + ";" +
                        "|home.joe;deployment;athenz.backend;" + currentTime + ";"
        );

        // get the notification for user.jane as the admin of the domains

        notification = getNotification(notifications, "user.jane", NOTIFICATION_DETAILS_ROLES_LIST);
        assertNotNull(notification);

        assertEquals(notification.getRecipients().size(), 1);
        assertEquals(notification.getDetails().size(), 2);
        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER), "user.jane");
        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_ROLES_LIST),
                "home.joe;deployment;athenz.api;" + currentTime + ";notify+details" +
                        "|home.joe;deployment;athenz.backend;" + currentTime + ";"
        );

        // get the notification for user.joe as the owner of the principals

        notification = getNotification(notifications, "user.joe", NOTIFICATION_DETAILS_MEMBERS_LIST);
        assertNotNull(notification);

        assertEquals(notification.getRecipients().size(), 1);
        assertEquals(notification.getDetails().size(), 1);
        assertEquals(notification.getDetails().get(NOTIFICATION_DETAILS_MEMBERS_LIST),
                "home.joe;deployment;athenz.api;" + currentTime + ";notify+details" +
                        "|home.joe;deployment;home.joe.openhouse;" + currentTime + ";" +
                        "|home.joe;deployment;athenz.backend;" + currentTime + ";"
        );
    }

    @Test
    public void testGetSlackMessage() {
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("group", "group1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");

        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY).setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter converter =
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(
                        notificationConverterCommon);
        NotificationSlackMessage notificationSlackMessage = converter.getNotificationAsSlackMessage(notification);
        assertNull(notificationSlackMessage);

        notification.setDetails(details);
        notificationSlackMessage = converter.getNotificationAsSlackMessage(notification);
        assertNull(notificationSlackMessage);

        // now set the correct expiry members details
        // with one bad entry that should be skipped

        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST,
                "athenz;group1;user.joe;2020-12-01T12:00:00.000Z;notify+details|athenz;group1;user.jane;2020-12-01T12:00:00.000Z;|athenz;group3;user.bad");

        NotificationSlackMessage notificationAsSlackMessage = converter.getNotificationAsSlackMessage(notification);
        String message = notificationAsSlackMessage.getMessage();
        assertNotNull(message);
        assertTrue(message.contains("user.joe"));
        assertTrue(message.contains("user.jane"));
        assertTrue(message.contains("group1"));
        assertTrue(message.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(message.contains("notify details"));

        // make sure the bad entries are not included

        assertFalse(message.contains("user.bad"));
        assertFalse(message.contains("group3"));

        // Make sure support text and url do not appear

        assertFalse(message.contains("slack"));
        assertFalse(message.contains("link.to.athenz.channel.com"));

        // now try the expiry groups reminder
        notification = new Notification(Notification.Type.GROUP_MEMBER_EXPIRY);
        GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter principalConverter =
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(
                        notificationConverterCommon);
        NotificationSlackMessage principalConverterNotificationAsSlackMessage = principalConverter.getNotificationAsSlackMessage(notification);
        assertNull(principalConverterNotificationAsSlackMessage.getMessage());

        notification.setDetails(details);
        principalConverterNotificationAsSlackMessage = principalConverter.getNotificationAsSlackMessage(notification);
        assertNull(principalConverterNotificationAsSlackMessage.getMessage());

        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;group1;user.joe;2020-12-01T12:00:00.000Z;notify%20details|athenz2;group2;user.joe;2020-12-01T12:00:00.000Z;");
        notification.setDetails(details);
        principalConverterNotificationAsSlackMessage = principalConverter.getNotificationAsSlackMessage(notification);

        message = principalConverterNotificationAsSlackMessage.getMessage();
        assertNotNull(message);
        assertTrue(message.contains("athenz1"));
        assertTrue(message.contains("athenz2"));
        assertTrue(message.contains("group1"));
        assertTrue(message.contains("group2"));
        assertTrue(message.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(message.contains("notify details"));

        // Make sure support text and url do not appear

        assertFalse(message.contains("slack"));
        assertFalse(message.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
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
    public void testGetConsolidatedNotificationDetailsWithNotificationObjectStore() throws ServerResourceException {

        NotificationObjectStore notificationObjectStore = new ZMSObjectReviewTest.NotificationObjectStoreImpl(null);

        // generate our data set

        Map<String, DomainGroupMember> members = new HashMap<>();
        Timestamp currentTime = Timestamp.fromCurrentTime();

        DomainGroupMember domainGroupMember = new DomainGroupMember().setMemberName("home.joe.openhouse");
        List<GroupMember> memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("deployment").setDomainName("home.joe")
                .setMemberName("home.joe.openhouse").setExpiration(currentTime));
        domainGroupMember.setMemberGroups(memberGroups);
        members.put("home.joe.openhouse", domainGroupMember);

        domainGroupMember = new DomainGroupMember().setMemberName("athenz.backend");
        memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("deployment").setDomainName("home.joe")
                .setMemberName("athenz.backend").setExpiration(currentTime));
        domainGroupMember.setMemberGroups(memberGroups);
        members.put("athenz.backend", domainGroupMember);

        domainGroupMember = new DomainGroupMember().setMemberName("athenz.api");
        memberGroups = new ArrayList<>();
        memberGroups.add(new GroupMember().setGroupName("deployment").setDomainName("home.joe")
                .setMemberName("athenz.api").setExpiration(currentTime).setNotifyDetails("notify details"));
        domainGroupMember.setMemberGroups(memberGroups);
        members.put("athenz.api", domainGroupMember);

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

        GroupMemberExpiryNotificationTask task = new GroupMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));

        UserAuthority userAuthority = Mockito.mock(UserAuthority.class);

        NotificationConverterCommon notificationConverterCommon
                = new NotificationConverterCommon(userAuthority);

        RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter =
                Mockito.mock(RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter.class);
        Mockito.when(disableRoleMemberNotificationFilter.getDisabledNotificationState(any()))
                .thenReturn(DisableNotificationEnum.getEnumSet(0));

        List<Notification> notifications = task.getNotificationDetails(
                members, Notification.ConsolidatedBy.PRINCIPAL,
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter(),
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter(),
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon),
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(notificationConverterCommon),
                notificationObjectStore);

        // we're supposed to get 3 notifications back - one for user.joe as the
        // owner of the principals, one for user.joe as the domain admin and another
        // for user.jane as domain admin

        assertEquals(notifications.size(), 3);
        List<String> objects = notificationObjectStore.getReviewObjects("user.joe");
        assertEquals(objects.size(), 1);
        assertTrue(objects.contains("home.joe:group.deployment"));

        // set up our store to throw exceptions and make sure the results are
        // returned as expected

        notificationObjectStore = Mockito.mock(NotificationObjectStore.class);
        Mockito.doThrow(new ServerResourceException(500)).when(notificationObjectStore)
                .registerReviewObjects(Mockito.anyString(), Mockito.anyList());

        notifications = task.getNotificationDetails(
                members, Notification.ConsolidatedBy.PRINCIPAL,
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon),
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToEmailConverter(notificationConverterCommon),
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToToMetricConverter(),
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToMetricConverter(),
                new GroupMemberExpiryNotificationTask.GroupExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon),
                new GroupMemberExpiryNotificationTask.GroupExpiryDomainNotificationToSlackConverter(notificationConverterCommon),
                notificationObjectStore);

        // we're supposed to get 3 notifications back - one for user.joe as the
        // owner of the principals, one for user.joe as the domain admin and another
        // for user.jane as domain admin

        assertEquals(notifications.size(), 3);
    }

    @Test
    public void testRegisterNotificationObjects() throws ServerResourceException {

        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        GroupMemberExpiryNotificationTask task = new GroupMemberExpiryNotificationTask(null, USER_DOMAIN_PREFIX,
                notificationConverterCommon);
        NotificationObjectStore notificationObjectStore = Mockito.mock(NotificationObjectStore.class);
        Mockito.doThrow(new ServerResourceException(500)).when(notificationObjectStore)
                .registerReviewObjects(Mockito.anyString(), Mockito.anyList());

        // make sure all our methods complete without any exceptions
        // when the consolidated by is not set to principal

        GroupMember groupMember = new GroupMember().setGroupName("group1").setDomainName("athenz1");

        task.registerNotificationObjects(notificationObjectStore, Notification.ConsolidatedBy.DOMAIN,
                "user.joe", List.of(groupMember));

        // verify that the registerReviewObjects method for the notificationObjectStore
        // was not called

        Mockito.verify(notificationObjectStore, Mockito.never()).registerReviewObjects(Mockito.anyString(), Mockito.anyList());

        // now let's set the consolidated by to principal but only include
        // not human principal which should also be ignored

        task.registerNotificationObjects(notificationObjectStore, Notification.ConsolidatedBy.PRINCIPAL,
                "athenz.api", List.of(groupMember));

        // verify that the registerReviewObjects method for the notificationObjectStore
        // was not called

        Mockito.verify(notificationObjectStore, Mockito.never()).registerReviewObjects(Mockito.anyString(), Mockito.anyList());

        // finally just verify that with a user type we'll get our exception

        task.registerNotificationObjects(notificationObjectStore, Notification.ConsolidatedBy.PRINCIPAL,
                "user.joe", List.of(groupMember));

        // verify that the registerReviewObjects method for the notificationObjectStore was called once

        Mockito.verify(notificationObjectStore, Mockito.times(1)).registerReviewObjects(Mockito.eq("user.joe"),
                Mockito.anyList());
    }
}
