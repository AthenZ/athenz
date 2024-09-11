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
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Group;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.rdl.Timestamp;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static com.yahoo.athenz.zms.notification.ZMSNotificationManagerTest.getNotificationManager;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.never;
import static org.testng.Assert.*;
import static org.testng.Assert.assertFalse;
import static org.testng.AssertJUnit.assertEquals;

public class PutRoleMembershipDecisionNotificationTaskTest {
    private final NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

    @Test
    public void testGenerateAndSendPostPutMembershipDecisionNotificationGroupAdmin() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");
        details.put("actionPrincipal", "user.approver1");
        details.put("member", "dom1:group.group1");
        details.put("requester", "user.user2");

        List<RoleMember>  roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.admin1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.admin2").setActive(true);
        roleMembers.add(rm);

        Role adminRole = new Role().setName("dom2:role.admin").setRoleMembers(roleMembers);

        Group group = new Group();

        Mockito.when(dbsvc.getGroup("dom1", "group1", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(group);
        Mockito.when(dbsvc.getRole("dom1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(details, true, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.addRecipient("user.admin1")
                .addRecipient("user.admin2")
                .addRecipient("user.user2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom1:group.group1")
                .addDetails("requester", "user.user2");

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter metricConverter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipDecisionNotificationGroupNotifyRoles() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");
        details.put("actionPrincipal", "user.approver1");
        details.put("member", "dom1:group.group1");
        details.put("requester", "user.user2");

        List<RoleMember>  roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.notifier1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.notifier2").setActive(true);
        roleMembers.add(rm);

        Role notifyRole1 = new Role().setName("dom2:role.notify1").setRoleMembers(roleMembers);

        roleMembers = new ArrayList<>();
        rm = new RoleMember().setMemberName("user.joe").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.dom").setActive(true);
        roleMembers.add(rm);

        Role notifyRole2 = new Role().setName("dom2:role.notify2").setRoleMembers(roleMembers);

        Group group = new Group().setNotifyRoles("dom2:role.notify2,dom2:role.notify1");

        Mockito.when(dbsvc.getGroup("dom1", "group1", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(group);
        Mockito.when(dbsvc.getRole("dom2", "notify1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(notifyRole1);
        Mockito.when(dbsvc.getRole("dom2", "notify2", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(notifyRole2);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(details, true, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.addRecipient("user.notifier1")
                .addRecipient("user.notifier2")
                .addRecipient("user.joe")
                .addRecipient("user.dom")
                .addRecipient("user.user2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom1:group.group1")
                .addDetails("requester", "user.user2");

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter metricConverter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipDecisionNotificationUsers() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");
        details.put("actionPrincipal", "user.approver1");
        details.put("member", "user.user1");
        details.put("requester", "user.user2");

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(details, true, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.addRecipient("user.user1")
                .addRecipient("user.user2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "user.user1")
                .addDetails("requester", "user.user2");

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter metricConverter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipDecisionNotificationService() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");
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

        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(details, true, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.addRecipient("user.approver1")
                .addRecipient("user.approver2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom2.testsvc1");

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter metricConverter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullNotificationSvc() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationServiceFactory testfact = () -> null;
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(null, true, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);
        verify(mockNotificationService, never()).notify(any(Notification.class));
    }

    @Test
    public void testDescription() {
        DBService dbsvc = Mockito.mock(DBService.class);
        PutRoleMembershipDecisionNotificationTask putRoleMembershipDecisionNotificationTask = new PutRoleMembershipDecisionNotificationTask(
                new HashMap<>(),
                true,
                dbsvc,
                USER_DOMAIN_PREFIX,
                notificationToEmailConverterCommon);

        String description = putRoleMembershipDecisionNotificationTask.getDescription();
        assertEquals("Pending Membership Decision Notification", description);
    }

    @Test
    public void testGetRejectEmailBody() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.example.com");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        details.put("actionPrincipal", "user.actionPrincipal");
        details.put("membershipDecision", "reject");

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.setDetails(details);
        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(new NotificationToEmailConverterCommon(null), false);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("dom1"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("user.member1"));
        assertTrue(body.contains("test reason"));
        assertTrue(body.contains("user.requester"));
        assertTrue(body.contains("user.actionPrincipal"));
        assertTrue(body.contains("https://athenz.example.com"));
        assertTrue(body.contains("Pending Membership Rejected Details"));
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
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        details.put("actionPrincipal", "user.actionPrincipal");
        details.put("membershipDecision", "reject");

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.setDetails(details);
        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(new NotificationToEmailConverterCommon(null), true);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("dom1"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("user.member1"));
        assertTrue(body.contains("test reason"));
        assertTrue(body.contains("user.requester"));
        assertTrue(body.contains("user.actionPrincipal"));
        assertTrue(body.contains("https://athenz.example.com"));
        assertTrue(body.contains("Pending Membership Approved Details"));
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
        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, false);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Pending Role Member Rejected");
    }

    @Test
    public void getApproveEmailSubject() {
        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter = new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, true);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Pending Role Member Approved");
    }

    @Test
    public void testGetApproveNotificationAsMetric() {
        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        details.put("actionPrincipal", "user.actionPrincipal");
        details.put("membershipDecision", "approve");

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.setDetails(details);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();

        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification, Timestamp.fromMillis(System.currentTimeMillis()));
        String[] record = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "pending_role_membership_decision",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
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
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        details.put("actionPrincipal", "user.actionPrincipal");
        details.put("membershipDecision", "reject");

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.setDetails(details);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();

        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification, Timestamp.fromMillis(System.currentTimeMillis()));
        String[] record = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "pending_role_membership_decision",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
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
