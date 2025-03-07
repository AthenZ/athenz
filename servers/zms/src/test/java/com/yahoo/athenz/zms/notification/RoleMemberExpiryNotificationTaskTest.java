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

public class RoleMemberExpiryNotificationTaskTest {
    final NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

    @Test
    public void testSendRoleMemberExpiryRemindersException() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);

        // we're going to throw an exception when called

        Mockito.when(dbsvc.getRoleExpiryMembers(1)).thenThrow(new IllegalArgumentException());
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask = new RoleMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));

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
    public void testSendRoleMemberExpiryRemindersEmptySet() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask = new RoleMemberExpiryNotificationTask(
                dbsvc, USER_DOMAIN_PREFIX, new NotificationConverterCommon(null));
        assertEquals(roleMemberExpiryNotificationTask.getNotifications(), new ArrayList<>());

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryReminders() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);

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
        Role adminRole = new Role().setName("athenz1:role.admin").setRoleMembers(roleMembers);
        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        domain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("athenz1")).thenReturn(domain.getRoles());
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);

        Domain athenz1Domain = new Domain().setName("athenz1").setSlackChannel("channel-1");
        Mockito.when(dbsvc.getDomain("athenz1", false)).thenReturn(athenz1Domain);

        List<Notification> notifications = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                new NotificationConverterCommon(null)).getNotifications();

        // we should get 2 notifications - one for user and one for domain
        assertEquals(notifications.size(), 4);

        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedFirstNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedFirstNotification.addDetails("member", "user.joe");
        expectedFirstNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(
                        new NotificationConverterCommon(null)));
        expectedFirstNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter());
        expectedFirstNotification.setNotificationToSlackMessageConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToSlackConverter(
                        new NotificationConverterCommon(null)));

        Notification expectedSecondNotification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedSecondNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedSecondNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationConverterCommon(null)));
        expectedSecondNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());
        expectedSecondNotification.setNotificationToSlackMessageConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToSlackConverter(
                        new NotificationConverterCommon(null)));

        Notification expectedThirdNotification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        expectedThirdNotification.addRecipient("user.joe");
        expectedThirdNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedThirdNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedThirdNotification.addDetails("member", "user.joe");
        expectedThirdNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(
                        new NotificationConverterCommon(null)));
        expectedThirdNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter());
        expectedThirdNotification.setNotificationToSlackMessageConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToSlackConverter(
                        new NotificationConverterCommon(null)));

        Notification expectedFourthNotification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        expectedFourthNotification.addRecipient("athenz1");
        expectedFourthNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedFourthNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role1;user.joe;1970-01-01T00:00:00.100Z;");
        expectedFourthNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationConverterCommon(null)));
        expectedFourthNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());
        expectedFourthNotification.setNotificationToSlackMessageConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToSlackConverter(
                        new NotificationConverterCommon(null)));
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
    public void testSendRoleMemberExpiryRemindersDisabledOverOneWeek() throws ServerResourceException {

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
        Role adminRole = new Role().setName("athenz1:role.admin").setRoleMembers(roleMembers);
        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        domain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("athenz1")).thenReturn(domain.getRoles());
        Mockito.when(dbsvc.getRole("athenz1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);
        Domain athenz1Domain = new Domain().setName("athenz1").setSlackChannel("channel-1");
        Mockito.when(dbsvc.getDomain("athenz1", false)).thenReturn(athenz1Domain);

        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList().setList(Collections.singletonList("4"));
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, tagValueList);
        Role role = new Role().setTags(tags);
        Mockito.when(dbsvc.getRole("athenz1", "role1", false, false, false)).thenReturn(role);
        Mockito.when(dbsvc.getRole("athenz1", "role2", false, false, false)).thenReturn(role);

        List<Notification> notifications = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX,
                new NotificationConverterCommon(null)).getNotifications();

        // we should get 4 notifications - 2 for user and 2 for domain
        // role1 should be excluded and role2 should be included

        assertEquals(notifications.size(), 4);

        NotificationConverterCommon converterCommon = new NotificationConverterCommon(null);
        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedFirstNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role2;user.joe;" + oneDayExpiry + ";");
        expectedFirstNotification.addDetails("member", "user.joe");
        expectedFirstNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(converterCommon));
        expectedFirstNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter());
        expectedFirstNotification.setNotificationToSlackMessageConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToSlackConverter(converterCommon));

        Notification expectedSecondNotification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        expectedSecondNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role2;user.joe;" + oneDayExpiry + ";");
        expectedSecondNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationConverterCommon(null)));
        expectedSecondNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());
        expectedSecondNotification.setNotificationToSlackMessageConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToSlackConverter(converterCommon));

        Notification expectedThirdNotification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        expectedThirdNotification.addRecipient("user.joe");
        expectedThirdNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedThirdNotification.addDetails(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role2;user.joe;" + oneDayExpiry + ";");
        expectedThirdNotification.addDetails("member", "user.joe");
        expectedThirdNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(
                        notificationConverterCommon));
        expectedThirdNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToMetricConverter());
        expectedThirdNotification.setNotificationToSlackMessageConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToSlackConverter(converterCommon));

        Notification expectedFourthNotification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        expectedFourthNotification.addRecipient("athenz1");
        expectedFourthNotification.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        expectedFourthNotification.addDetails(NOTIFICATION_DETAILS_MEMBERS_LIST, "athenz1;role2;user.joe;" + oneDayExpiry + ";");
        expectedFourthNotification.setNotificationToEmailConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationConverterCommon(null)));
        expectedFourthNotification.setNotificationToMetricConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToMetricConverter());
        expectedFourthNotification.setNotificationToSlackMessageConverter(
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToSlackConverter(converterCommon));
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
                new NotificationConverterCommon(null)).getNotifications();

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

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        notification.setDetails(details);
        RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter converter =
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationConverterCommon(null));
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
                "athenz;role1;user.joe;2020-12-01T12:00:00.000Z;notify+details|athenz;role1;user.jane;2020-12-01T12:00:00.000Z;|athenz;role3;user.bad");

        NotificationEmail notificationAsEmailWithMembers = converter.getNotificationAsEmail(notification);
        body = notificationAsEmailWithMembers.getBody();
        assertNotNull(body);
        assertTrue(body.contains("user.joe"));
        assertTrue(body.contains("user.jane"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(body.contains("notify details"));

        // make sure the bad entries are not included

        assertFalse(body.contains("user.bad"));
        assertFalse(body.contains("role3"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        // now try the expiry roles reminder
        notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        notification.setDetails(details);
        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;role1;user.joe;2020-12-01T12:00:00.000Z;notify%20details|athenz2;role2;user.joe;2020-12-01T12:00:00.000Z;");
        RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter principalConverter =
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(
                        new NotificationConverterCommon(null));
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
        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter converter =
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToEmailConverter(
                        new NotificationConverterCommon(null));
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Domain Role Member Expiration Notification");

        notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter principalConverter =
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToEmailConverter(
                        new NotificationConverterCommon(null));
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
        String expectedStringBuilder = "testDomainName;testRoleName;testMemberName;1970-01-01T00:00:00.100Z;";
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

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
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

        notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
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
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, new TagValueList().setList(List.of("1")));
        Role noUserNotif = new Role()
                .setName("athenz1:role.no-user-notif")
                .setTags(tags);

        // Role where user admin review notifications disabled
        tags = new HashMap<>();
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, new TagValueList().setList(List.of("2")));
        Role noAdminNotif = new Role()
                .setName("athenz1:role.no-admin-notif")
                .setTags(tags);

        // Role where all review notifications disabled
        tags = new HashMap<>();
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, new TagValueList().setList(List.of("3")));
        Role noNotifs = new Role()
                .setName("athenz1:role.no-notifs")
                .setTags(tags);

        // Role with invalid tags - all notifications enabled
        tags = new HashMap<>();
        tags.put(ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, new TagValueList().setList(List.of("notANumber")));
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
                dbsvc, USER_DOMAIN_PREFIX, notificationConverterCommon);
        RoleMemberExpiryNotificationTask.ReviewDisableRoleMemberNotificationFilter notificationFilter =
                roleMemberExpiryNotificationTask.new ReviewDisableRoleMemberNotificationFilter();
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
        assertTrue(disabledNotificationState.containsAll(Arrays.asList(DisableNotificationEnum.ADMIN,
                DisableNotificationEnum.USER)));

        disabledNotificationState = notificationFilter.getDisabledNotificationState(memberRoleInvalid);
        assertTrue(disabledNotificationState.isEmpty());
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

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY).setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToSlackConverter converter =
                new RoleMemberExpiryNotificationTask.RoleExpiryDomainNotificationToSlackConverter(
                        new NotificationConverterCommon(null));
        NotificationSlackMessage notificationAsSlackMessage = converter.getNotificationAsSlackMessage(notification);
        assertNull(notificationAsSlackMessage);

        notification.setDetails(details);
        notificationAsSlackMessage = converter.getNotificationAsSlackMessage(notification);
        assertNull(notificationAsSlackMessage);
        // now set the correct expiry members details
        // with one bad entry that should be skipped

        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST,
                "athenz;role1;user.joe;2020-12-01T12:00:00.000Z;notify+details|athenz;role1;user.jane;2020-12-01T12:00:00.000Z;|athenz;role3;user.bad");

        notificationAsSlackMessage = converter.getNotificationAsSlackMessage(notification);
        assertNotNull(notificationAsSlackMessage);
        String slackMessage = notificationAsSlackMessage.getMessage();
        assertNotNull(slackMessage);
        assertTrue(slackMessage.contains("user.joe"));
        assertTrue(slackMessage.contains("user.jane"));
        assertTrue(slackMessage.contains("role1"));
        assertTrue(slackMessage.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(slackMessage.contains("notify details"));

        // make sure the bad entries are not included

        assertFalse(slackMessage.contains("user.bad"));
        assertFalse(slackMessage.contains("role3"));

        // Make sure support text and url do not appear

        assertFalse(slackMessage.contains("link.to.athenz.channel.com"));

        // now try the expiry roles reminder
        notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY).setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToSlackConverter principalConverter =
                new RoleMemberExpiryNotificationTask.RoleExpiryPrincipalNotificationToSlackConverter(
                        new NotificationConverterCommon(null));
        NotificationSlackMessage principalNotificationAsSlackMessage = principalConverter.getNotificationAsSlackMessage(notification);
        assertNull(principalNotificationAsSlackMessage);

        notification.setDetails(details);
        principalNotificationAsSlackMessage = principalConverter.getNotificationAsSlackMessage(notification);
        assertNull(principalNotificationAsSlackMessage);

        details.put(NOTIFICATION_DETAILS_ROLES_LIST,
                "athenz1;role1;user.joe;2020-12-01T12:00:00.000Z;notify%20details|athenz2;role2;user.joe;2020-12-01T12:00:00.000Z;|athenz;role3;user.bad");
        notification.setDetails(details);
        principalNotificationAsSlackMessage = principalConverter.getNotificationAsSlackMessage(notification);
        assertNotNull(principalNotificationAsSlackMessage);
        slackMessage = principalNotificationAsSlackMessage.getMessage();
        assertNotNull(slackMessage);
        assertTrue(slackMessage.contains("athenz1"));
        assertTrue(slackMessage.contains("athenz2"));
        assertTrue(slackMessage.contains("role1"));
        assertTrue(slackMessage.contains("role2"));
        assertTrue(slackMessage.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(slackMessage.contains("notify details"));

        // Make sure support text and url do not appear

        assertFalse(slackMessage.contains("slack"));
        assertFalse(slackMessage.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
    }
}
