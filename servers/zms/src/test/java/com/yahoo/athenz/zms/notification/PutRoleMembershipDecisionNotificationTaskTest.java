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

public class PutRoleMembershipDecisionNotificationTaskTest {
    private final NotificationConverterCommon notificationConverterCommon =
            new NotificationConverterCommon(null);

    @Test
    public void testGenerateAndSendPostPutMembershipDecisionNotificationGroupAdmin() throws ServerResourceException {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");
        details.put("actionPrincipal", "user.approver1");
        details.put("member", "dom1:group.group1");
        details.put("requester", "user.user2");
        details.put("reason", "testing");
        details.put("pendingState", "ADD");
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

        Domain domain = new Domain().setName("dom1").setSlackChannel("channel1");
        Mockito.when(dbsvc.getDomain("dom1", false)).thenReturn(domain);
        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(details, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        notification.addRecipient("user.admin1")
                .addRecipient("user.admin2")
                .addRecipient("user.user2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom1:group.group1")
                .addDetails("requester", "user.user2").addDetails("pendingState", "ADD").addDetails("reason", "testing");

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter metricConverter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToSlackConverter slackConverter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToSlackConverter(notificationConverterCommon, true);
        notification.setNotificationToSlackMessageConverter(slackConverter);

        Notification notification2 = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification2.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        notification2.addRecipient("dom1")
                .addRecipient("user.user2");
        notification2.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom1:group.group1")
                .addDetails("requester", "user.user2").addDetails("pendingState", "ADD").addDetails("reason", "testing");
        notification2.setNotificationToEmailConverter(converter);
        notification2.setNotificationToMetricConverter(metricConverter);
        notification2.setNotificationToSlackMessageConverter(slackConverter);
        Map<String, NotificationDomainMeta> domainMetaMap = new HashMap<>();
        domainMetaMap.put("dom1", new NotificationDomainMeta("dom1").setSlackChannel("channel1"));
        notification2.setNotificationDomainMeta(domainMetaMap);
        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        List<Notification> actualNotifications = captor.getAllValues();

        assertEquals(actualNotifications.size(), 2);
        assertEquals(actualNotifications.get(0), notification);
        assertEquals(actualNotifications.get(1), notification2);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipDecisionNotificationGroupNotifyRoles() throws ServerResourceException {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(mockNotificationService);
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

        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(details, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification.setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        notification.addRecipient("user.notifier1")
                .addRecipient("user.notifier2")
                .addRecipient("user.joe")
                .addRecipient("user.dom")
                .addRecipient("user.user2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom1:group.group1")
                .addDetails("requester", "user.user2");

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter metricConverter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToSlackConverter slackConverter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToSlackConverter(notificationConverterCommon, true);
        notification.setNotificationToSlackMessageConverter(slackConverter);

        Notification notification2 = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        notification2.setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        notification2.addRecipient("user.notifier1")
                .addRecipient("user.notifier2")
                .addRecipient("user.joe")
                .addRecipient("user.dom")
                .addRecipient("user.user2");
        notification2.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom1:group.group1")
                .addDetails("requester", "user.user2");
        notification2.setNotificationToEmailConverter(converter);
        notification2.setNotificationToMetricConverter(metricConverter);
        notification2.setNotificationToSlackMessageConverter(slackConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        List<Notification> actualNotifications = captor.getAllValues();

        assertEquals(actualNotifications.size(), 2);
        assertEquals(actualNotifications.get(0), notification);
        assertEquals(actualNotifications.get(1), notification2);

    }

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
        details.put("role", "role1");
        details.put("actionPrincipal", "user.approver1");
        details.put("member", "user.user1");
        details.put("requester", "user.user2");

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(details, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION).setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        notification.addRecipient("user.user1")
                .addRecipient("user.user2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "user.user1")
                .addDetails("requester", "user.user2");

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter metricConverter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToSlackConverter slackConverter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToSlackConverter(notificationConverterCommon, true);
        notification.setNotificationToSlackMessageConverter(slackConverter);

        Notification notification2 = new Notification(Notification.Type.ROLE_MEMBER_DECISION).setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        notification2.addRecipient("user.user1")
                .addRecipient("user.user2");
        notification2.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "user.user1")
                .addDetails("requester", "user.user2");
        notification2.setNotificationToEmailConverter(converter);
        notification2.setNotificationToMetricConverter(metricConverter);
        notification2.setNotificationToSlackMessageConverter(slackConverter);

        Mockito.verify(mockNotificationService, atLeast(2)).notify(captor.capture());

        List<Notification> actualNotifications = captor.getAllValues();
        assertEquals(actualNotifications.size(), 2);
        assertEquals(actualNotifications.get(0), notification);
        assertEquals(actualNotifications.get(1), notification2);

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

        Domain domain = new Domain().setName("dom2").setSlackChannel("channel1");
        Mockito.when(dbsvc.getDomain("dom2", false)).thenReturn(domain);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(details, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION).setConsolidatedBy(Notification.ConsolidatedBy.PRINCIPAL);
        notification.addRecipient("user.approver1")
                .addRecipient("user.approver2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom2.testsvc1");

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationConverterCommon, true);
        notification.setNotificationToEmailConverter(converter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter metricConverter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToSlackConverter slackConverter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToSlackConverter(notificationConverterCommon, true);
        notification.setNotificationToSlackMessageConverter(slackConverter);

        Notification notification2 = new Notification(Notification.Type.ROLE_MEMBER_DECISION).setConsolidatedBy(Notification.ConsolidatedBy.DOMAIN);
        notification2.addRecipient("dom2");
        notification2.addDetails("domain", "testdomain1").addDetails("role", "role1")
                .addDetails("actionPrincipal", "user.approver1").addDetails("member", "dom2.testsvc1");
        notification2.setNotificationToEmailConverter(converter);
        notification2.setNotificationToMetricConverter(metricConverter);
        notification2.setNotificationToSlackMessageConverter(slackConverter);
        Map<String, NotificationDomainMeta> domainMetaMap = new HashMap<>();
        domainMetaMap.put("dom2", new NotificationDomainMeta("dom2").setSlackChannel("channel1"));
        notification2.setNotificationDomainMeta(domainMetaMap);

        Mockito.verify(mockNotificationService, atLeast(2)).notify(captor.capture());

        List<Notification> actualNotifications = captor.getAllValues();
        assertEquals(actualNotifications.size(), 2);
        assertEquals(actualNotifications.get(0), notification);
        assertEquals(actualNotifications.get(1), notification2);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullNotificationSvc() throws ServerResourceException {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(null);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(null, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationConverterCommon).getNotifications();
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
        details.put("role", "role1");
        details.put("actionPrincipal", "user.approver1");
        details.put("member", "dom2:group.nullgrp");

        // get role call for the admin role of service getting added
        Mockito.when(dbsvc.getGroup("dom2", "nullgrp", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(null);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        List<Notification> notifications = new PutRoleMembershipDecisionNotificationTask(details, true, dbsvc,
                USER_DOMAIN_PREFIX, notificationConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Mockito.verify(mockNotificationService, atMost(0)).notify(captor.capture());
    }

    @Test
    public void testDescription() {
        DBService dbsvc = Mockito.mock(DBService.class);
        PutRoleMembershipDecisionNotificationTask putRoleMembershipDecisionNotificationTask =
                new PutRoleMembershipDecisionNotificationTask(new HashMap<>(), true, dbsvc, USER_DOMAIN_PREFIX,
                        notificationConverterCommon);

        String description = putRoleMembershipDecisionNotificationTask.getDescription();
        assertEquals(description, "Pending Membership Decision Notification");
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
        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(new NotificationConverterCommon(null), false);
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
        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(new NotificationConverterCommon(null), true);
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
        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationConverterCommon, false);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Athenz Pending Role Member Rejected");
    }

    @Test
    public void getApproveEmailSubject() {
        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_DECISION);
        PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter converter =
                new PutRoleMembershipDecisionNotificationTask.PutRoleMembershipDecisionNotificationToEmailConverter(notificationConverterCommon, true);
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

        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification,
                Timestamp.fromMillis(System.currentTimeMillis()));
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

        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification,
                Timestamp.fromMillis(System.currentTimeMillis()));
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
