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
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.rdl.Timestamp;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static com.yahoo.athenz.zms.notification.ZMSNotificationManagerTest.getNotificationManager;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class PutGroupMembershipDecisionNotificationTaskTest {
    private final NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

    @Test
    public void testGenerateAndSendPostPutMembershipDecisionNotificationUsers() throws ServerResourceException {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("group", "group1");
        details.put("actionPrincipal", "user.approver1");
        details.put("member", "user.user1");
        details.put("requester", "user.user2");

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutGroupMembershipDecisionNotificationTask(details, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_DECISION);
        notification.addRecipient("user.user1")
                .addRecipient("user.user2");
        notification.addDetails("domain", "testdomain1").addDetails("group", "group1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "user.user1")
                .addDetails("requester", "user.user2");

        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter converter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToMetricConverter metricConverter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipDecisionNotificationService() throws ServerResourceException {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("group", "group1");
        details.put("actionPrincipal", "user.approver1");
        details.put("member", "dom2.testsvc1");

        List<RoleMember>  roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.approver1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.approver2").setActive(true);
        roleMembers.add(rm);

        Role localRole = new Role().setName("dom2:role.admin").setRoleMembers(roleMembers);

        // get role call for the admin role of service getting added
        Mockito.when(dbsvc.getRole("dom2", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(localRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutGroupMembershipDecisionNotificationTask(details, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_DECISION);
        notification.addRecipient("user.approver1")
                .addRecipient("user.approver2");
        notification.addDetails("domain", "testdomain1").addDetails("group", "group1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom2.testsvc1");

        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter converter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToMetricConverter metricConverter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullNotificationSvc() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(null);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        List<Notification> notifications = new PutGroupMembershipDecisionNotificationTask(null, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);
        verify(mockNotificationService, never()).notify(any(Notification.class));
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullGroup() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("group", "group1");
        details.put("actionPrincipal", "user.approver1");
        details.put("member", "dom2:group.nullgrp");

        // get role call for the admin role of service getting added

        Mockito.when(dbsvc.getGroup("dom2", "nullgrp", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(null);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutGroupMembershipDecisionNotificationTask(details, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Mockito.verify(mockNotificationService, atMost(0)).notify(captor.capture());
    }

    @Test
    public void testDescription() {
        DBService dbsvc = Mockito.mock(DBService.class);
        PutGroupMembershipDecisionNotificationTask putgroupMembershipDecisionNotificationTask =
                new PutGroupMembershipDecisionNotificationTask(new HashMap<>(), true, dbsvc, USER_DOMAIN_PREFIX,
                        notificationToEmailConverterCommon);

        String description = putgroupMembershipDecisionNotificationTask.getDescription();
        assertEquals(description, "Pending Group Membership Decision Notification");
    }

    @Test
    public void testGetRejectEmailBody() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.example.com");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("group", "group1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        details.put("actionPrincipal", "user.actionPrincipal");
        details.put("membershipDecision", "reject");

        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_DECISION);
        notification.setDetails(details);
        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter converter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter(new NotificationToEmailConverterCommon(null), false);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("dom1"));
        assertTrue(body.contains("group1"));
        assertTrue(body.contains("user.member1"));
        assertTrue(body.contains("test reason"));
        assertTrue(body.contains("user.requester"));
        assertTrue(body.contains("user.actionPrincipal"));
        assertTrue(body.contains("https://athenz.example.com"));
        assertTrue(body.contains("Pending Group Membership Rejected Details"));
        assertTrue(body.contains("REJECTED BY"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("athenz.notification_support_text");
        System.clearProperty("athenz.notification_support_url");
        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void testGetApproveEmailBody() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.example.com");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("group", "group1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        details.put("actionPrincipal", "user.actionPrincipal");
        details.put("membershipDecision", "reject");

        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_DECISION);
        notification.setDetails(details);
        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter converter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter(new NotificationToEmailConverterCommon(null), true);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("dom1"));
        assertTrue(body.contains("group1"));
        assertTrue(body.contains("user.member1"));
        assertTrue(body.contains("test reason"));
        assertTrue(body.contains("user.requester"));
        assertTrue(body.contains("user.actionPrincipal"));
        assertTrue(body.contains("https://athenz.example.com"));
        assertTrue(body.contains("Pending Group Membership Approved Details"));
        assertTrue(body.contains("APPROVED BY"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("athenz.notification_support_text");
        System.clearProperty("athenz.notification_support_url");
        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void getRejectEmailSubject() {
        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_DECISION);
        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter converter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, false);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Pending Group Member Rejected");
    }

    @Test
    public void getApproveEmailSubject() {
        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter converter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, true);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Pending Group Member Approved");
    }

    @Test
    public void testGetApproveNotificationAsMetric() {
        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("group", "group1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        details.put("actionPrincipal", "user.actionPrincipal");
        details.put("membershipDecision", "approve");

        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_DECISION);
        notification.setDetails(details);

        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToMetricConverter converter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToMetricConverter();

        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification,
                Timestamp.fromMillis(System.currentTimeMillis()));
        String[] record = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "pending_group_membership_decision",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_GROUP_KEY, "group1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.member1",
                METRIC_NOTIFICATION_REASON_KEY, "test reason",
                METRIC_NOTIFICATION_REQUESTER_KEY, "user.requester",
                METRIC_NOTIFICATION_MEMBERSHIP_DECISION, "approve"
        };

        List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(record);

        assertEquals(new NotificationMetric(expectedAttributes), notificationAsMetrics);
    }

    @Test
    public void testGetRejectNotificationAsMetric() {
        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("group", "group1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        details.put("actionPrincipal", "user.actionPrincipal");
        details.put("membershipDecision", "reject");

        Notification notification = new Notification(Notification.Type.GROUP_MEMBER_DECISION);
        notification.setDetails(details);

        PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToMetricConverter converter =
                new PutGroupMembershipDecisionNotificationTask.PutGroupMembershipDecisionNotificationToMetricConverter();

        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification,
                Timestamp.fromMillis(System.currentTimeMillis()));
        String[] record = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "pending_group_membership_decision",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_GROUP_KEY, "group1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.member1",
                METRIC_NOTIFICATION_REASON_KEY, "test reason",
                METRIC_NOTIFICATION_REQUESTER_KEY, "user.requester",
                METRIC_NOTIFICATION_MEMBERSHIP_DECISION, "reject"
        };

        List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(record);

        assertEquals(new NotificationMetric(expectedAttributes), notificationAsMetrics);
    }
}
