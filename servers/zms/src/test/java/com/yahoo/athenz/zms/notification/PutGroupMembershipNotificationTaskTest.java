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
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static com.yahoo.athenz.zms.notification.ZMSNotificationManagerTest.getNotificationManager;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertEquals;

public class PutGroupMembershipNotificationTaskTest {
    private final NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);
    
    @Test
    public void testGenerateAndSendPostPutGroupMembershipNotification() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("group", "group1");

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.domapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.domapprover2").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("dom2.testsvc1").setActive(true);
        roleMembers.add(rm);

        Role domainRole = new Role().setName("sys.auth.audit.domain:role.testdomain1").setRoleMembers(roleMembers);

        roleMembers = new ArrayList<>();
        rm = new RoleMember().setMemberName("user.orgapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.orgapprover2").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("dom2.testsvc1").setActive(true);
        roleMembers.add(rm);

        Role orgRole = new Role().setName("sys.auth.audit.org:role.neworg").setRoleMembers(roleMembers);

        List<Role> roles1 = new ArrayList<>();
        roles1.add(orgRole);

        AthenzDomain athenzDomain1 = new AthenzDomain("sys.auth.audit.org");
        athenzDomain1.setRoles(roles1);

        List<Role> roles2 = new ArrayList<>();
        roles2.add(domainRole);

        AthenzDomain athenzDomain2 = new AthenzDomain("sys.auth.audit.domain");
        athenzDomain2.setRoles(roles2);

        Mockito.when(dbsvc.getRolesByDomain("sys.auth.audit.org")).thenReturn(athenzDomain1.getRoles());
        Mockito.when(dbsvc.getRole("sys.auth.audit.org", "neworg", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(orgRole);

        Mockito.when(dbsvc.getRolesByDomain("sys.auth.audit.domain")).thenReturn(athenzDomain2.getRoles());
        Mockito.when(dbsvc.getRole("sys.auth.audit.domain", "testdomain1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(domainRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Group notifyGroup = new Group().setAuditEnabled(true).setSelfServe(false);
        List<Notification> notifications = new PutGroupMembershipNotificationTask("testdomain1", "neworg",
                notifyGroup, details, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification();
        notification.addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2")
                .addRecipient("user.orgapprover1")
                .addRecipient("user.orgapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("group", "group1");

        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter converter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter(notificationToEmailConverterCommon);
        notification.setNotificationToEmailConverter(converter);

        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter metricConverter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutGroupMembershipNotificationNullDomainGroup() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("group", "group1");

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.orgapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.orgapprover2").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("dom2.testsvc1").setActive(true);
        roleMembers.add(rm);

        Role orgRole = new Role().setName("sys.auth.audit.org:role.neworg").setRoleMembers(roleMembers);

        List<Role> roles = new ArrayList<>();
        roles.add(orgRole);

        AthenzDomain athenzDomain = new AthenzDomain("sys.auth.audit.org");
        athenzDomain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("sys.auth.audit.org")).thenReturn(athenzDomain.getRoles());
        Mockito.when(dbsvc.getRole("sys.auth.audit.org", "neworg", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(orgRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Group notifyGroup = new Group().setAuditEnabled(true).setSelfServe(false);
        List<Notification> notifications = new PutGroupMembershipNotificationTask("testdomain1", "neworg",
                notifyGroup, details, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification();
        notification
                .addRecipient("user.orgapprover1")
                .addRecipient("user.orgapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("group", "group1");
        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter converter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter(notificationToEmailConverterCommon);
        notification.setNotificationToEmailConverter(converter);


        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter metricConverter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutGroupMembershipNotificationNullOrgGroup() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("group", "group1");

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.domapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.domapprover2").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("dom2.testsvc1").setActive(true);
        roleMembers.add(rm);

        Role domainRole = new Role().setName("sys.auth.audit.domain:role.testdomain1").setRoleMembers(roleMembers);

        List<Role> roles = new ArrayList<>();
        roles.add(domainRole);

        AthenzDomain athenzDomain = new AthenzDomain("sys.auth.audit.domain");
        athenzDomain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("sys.auth.audit.domain")).thenReturn(athenzDomain.getRoles());
        Mockito.when(dbsvc.getRole("sys.auth.audit.domain", "testdomain1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(domainRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Group notifyGroup = new Group().setAuditEnabled(true).setSelfServe(false);
        List<Notification> notifications = new PutGroupMembershipNotificationTask("testdomain1", "neworg",
                notifyGroup, details, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification();
        notification
                .addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("group", "group1");

        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter converter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter(notificationToEmailConverterCommon);
        notification.setNotificationToEmailConverter(converter);

        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter metricConverter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutGroupMembershipNotificationSelfserve() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("group", "group1");

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.domadmin1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.domadmin2").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("dom2.testsvc1").setActive(true);
        roleMembers.add(rm);

        Role adminRole = new Role().setName("testdomain1:role.admin").setRoleMembers(roleMembers);

        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);

        AthenzDomain athenzDomain = new AthenzDomain("testdomain1");
        athenzDomain.setRoles(roles);

        Mockito.when(dbsvc.getRolesByDomain("testdomain1")).thenReturn(athenzDomain.getRoles());
        Mockito.when(dbsvc.getRole("testdomain1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(adminRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Group notifyGroup = new Group().setAuditEnabled(false).setSelfServe(true);
        List<Notification> notifications = new PutGroupMembershipNotificationTask("testdomain1", "neworg",
                notifyGroup, details, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification();
        notification
                .addRecipient("user.domadmin1")
                .addRecipient("user.domadmin2");
        notification.addDetails("domain", "testdomain1").addDetails("group", "group1");

        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter converter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter(notificationToEmailConverterCommon);
        notification.setNotificationToEmailConverter(converter);

        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter metricConverter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutGroupMembershipNotificationNotifyGroups() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("group", "group1");

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.domapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.domapprover2").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("dom2.testsvc1").setActive(true);
        roleMembers.add(rm);

        Role domainRole = new Role().setName("athenz:role.approvers").setRoleMembers(roleMembers);

        roleMembers = new ArrayList<>();
        rm = new RoleMember().setMemberName("user.approver1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.approver2").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("dom2.testsvc1").setActive(true);
        roleMembers.add(rm);

        Role localRole = new Role().setName("testdomain1:role.notify").setRoleMembers(roleMembers);

        List<Role> roles1 = new ArrayList<>();
        roles1.add(localRole);

        AthenzDomain athenzDomain1 = new AthenzDomain("coretech");
        athenzDomain1.setRoles(roles1);

        List<Role> roles2 = new ArrayList<>();
        roles2.add(domainRole);

        AthenzDomain athenzDomain2 = new AthenzDomain("athenz");
        athenzDomain2.setRoles(roles2);

        Mockito.when(dbsvc.getRolesByDomain("testdomain1")).thenReturn(athenzDomain1.getRoles());
        Mockito.when(dbsvc.getRole("testdomain1", "notify", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(localRole);

        Mockito.when(dbsvc.getRolesByDomain("athenz")).thenReturn(athenzDomain2.getRoles());
        Mockito.when(dbsvc.getRole("athenz", "approvers", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(domainRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Group notifyGroup = new Group().setAuditEnabled(false).setSelfServe(false).setReviewEnabled(true)
                .setNotifyRoles("athenz:role.approvers,notify");
        List<Notification> notifications = new PutGroupMembershipNotificationTask("testdomain1", "neworg",
                notifyGroup, details, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification();
        notification.addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2")
                .addRecipient("user.approver1")
                .addRecipient("user.approver2");
        notification.addDetails("domain", "testdomain1").addDetails("group", "group1");

        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter converter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter(notificationToEmailConverterCommon);
        notification.setNotificationToEmailConverter(converter);

        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter metricConverter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter();
        notification.setNotificationToMetricConverter(metricConverter);

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutGroupMembershipNotificationInvalidType() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(Collections.emptySet());

        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Group notifyGroup = new Group().setAuditEnabled(false).setSelfServe(false);
        List<Notification> notifications = new PutGroupMembershipNotificationTask("testdomain1", "neworg",
                notifyGroup, null, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);
        Mockito.verify(mockNotificationService, times(0)).notify(any());
    }

    @Test
    public void testGenerateAndSendPostPutGroupMembershipNotificationNullNotificationSvc() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(Collections.emptySet());

        NotificationServiceFactory testfact = () -> null;
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Group notifyGroup = new Group().setAuditEnabled(false).setSelfServe(false);
        List<Notification> notifications = new PutGroupMembershipNotificationTask("testdomain1", "neworg",
                notifyGroup, null, dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon).getNotifications();
        notificationManager.sendNotifications(notifications);
        verify(mockNotificationService, never()).notify(any(Notification.class));
    }

    @Test
    public void testDescriptionAndType() {
        DBService dbsvc = Mockito.mock(DBService.class);
        PutGroupMembershipNotificationTask putGroupMembershipNotificationTask =
                new PutGroupMembershipNotificationTask("testDomain", "testOrg", new Group(),
                        new HashMap<>(), dbsvc, USER_DOMAIN_PREFIX, notificationToEmailConverterCommon);

        String description = putGroupMembershipNotificationTask.getDescription();
        assertEquals("Group Membership Approval Notification", description);
    }

    @Test
    public void testGetEmailBody() {
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

        Notification notification = new Notification();
        notification.setDetails(details);
        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter converter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter(new NotificationToEmailConverterCommon(null));
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("dom1"));
        assertTrue(body.contains("group1"));
        assertTrue(body.contains("user.member1"));
        assertTrue(body.contains("test reason"));
        assertTrue(body.contains("user.requester"));
        assertTrue(body.contains("https://athenz.example.com/workflow/domain?domain=dom1"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("athenz.notification_support_text");
        System.clearProperty("athenz.notification_support_url");
        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void getEmailSubject() {
        Notification notification = new Notification();
        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter converter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToEmailConverter(notificationToEmailConverterCommon);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Group Membership Approval Notification");
    }

    @Test
    public void testGetNotificationAsMetric() {
        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("group", "group1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");

        Notification notification = new Notification();
        notification.setDetails(details);

        PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter converter =
                new PutGroupMembershipNotificationTask.PutGroupMembershipNotificationToMetricConverter();

        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification, Timestamp.fromMillis(System.currentTimeMillis()));
        String[] record = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "group_membership_approval",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_GROUP_KEY, "group1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.member1",
                METRIC_NOTIFICATION_REASON_KEY, "test reason",
                METRIC_NOTIFICATION_REQUESTER_KEY, "user.requester"
        };

        List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(record);

        assertEquals(new NotificationMetric(expectedAttributes), notificationAsMetrics);
    }
}
