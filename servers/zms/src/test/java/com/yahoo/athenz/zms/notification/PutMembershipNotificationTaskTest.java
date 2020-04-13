/*
 * Copyright 2020 Verizon Media
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
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.AthenzDomain;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.zms.notification.NotificationManagerTest.getNotificationManager;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.never;
import static org.testng.Assert.*;
import static org.testng.Assert.assertFalse;

public class PutMembershipNotificationTaskTest {
    @Test
    public void testGenerateAndSendPostPutMembershipNotification() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");

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

        Mockito.when(dbsvc.getAthenzDomain("sys.auth.audit.org", false)).thenReturn(athenzDomain1);
        Mockito.when(dbsvc.getAthenzDomain("sys.auth.audit.domain", false)).thenReturn(athenzDomain2);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Role notifyRole = new Role().setAuditEnabled(true).setSelfServe(false);
        List<Notification> notifications = new PutMembershipNotificationTask("testdomain1", "neworg", notifyRole, details, dbsvc, USER_DOMAIN_PREFIX).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification.addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2")
                .addRecipient("user.orgapprover1")
                .addRecipient("user.orgapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");
        PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter converter = new PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter();
        notification.setNotificationToEmailConverter(converter);
        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullDomainRole() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");

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

        Mockito.when(dbsvc.getAthenzDomain("sys.auth.audit.org", false)).thenReturn(athenzDomain);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Role notifyRole = new Role().setAuditEnabled(true).setSelfServe(false);
        List<Notification> notifications = new PutMembershipNotificationTask("testdomain1", "neworg", notifyRole, details, dbsvc, USER_DOMAIN_PREFIX).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification
                .addRecipient("user.orgapprover1")
                .addRecipient("user.orgapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");
        PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter converter = new PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter();
        notification.setNotificationToEmailConverter(converter);
        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullOrgRole() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");

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

        Mockito.when(dbsvc.getAthenzDomain("sys.auth.audit.domain", false)).thenReturn(athenzDomain);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Role notifyRole = new Role().setAuditEnabled(true).setSelfServe(false);
        List<Notification> notifications = new PutMembershipNotificationTask("testdomain1", "neworg", notifyRole, details, dbsvc, USER_DOMAIN_PREFIX).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification
                .addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");
        PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter converter = new PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter();
        notification.setNotificationToEmailConverter(converter);
        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationSelfserve() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");

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

        Mockito.when(dbsvc.getAthenzDomain("testdomain1", false)).thenReturn(athenzDomain);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Role notifyRole = new Role().setAuditEnabled(false).setSelfServe(true);
        List<Notification> notifications = new PutMembershipNotificationTask("testdomain1", "neworg", notifyRole, details, dbsvc, USER_DOMAIN_PREFIX).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification
                .addRecipient("user.domadmin1")
                .addRecipient("user.domadmin2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");
        PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter converter = new PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter();
        notification.setNotificationToEmailConverter(converter);
        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNotifyRoles() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");

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

        Mockito.when(dbsvc.getAthenzDomain("testdomain1", false)).thenReturn(athenzDomain1);
        Mockito.when(dbsvc.getAthenzDomain("athenz", false)).thenReturn(athenzDomain2);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        Role notifyRole = new Role().setAuditEnabled(false).setSelfServe(false).setReviewEnabled(true)
                .setNotifyRoles("athenz:role.approvers,notify");
        List<Notification> notifications = new PutMembershipNotificationTask("testdomain1", "neworg", notifyRole, details, dbsvc, USER_DOMAIN_PREFIX).getNotifications();
        notificationManager.sendNotifications(notifications);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification.addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2")
                .addRecipient("user.approver1")
                .addRecipient("user.approver2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");
        PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter converter = new PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter();
        notification.setNotificationToEmailConverter(converter);
        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(actualNotification, notification);
        assertEquals(actualNotification, notification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationInvalidType() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Role notifyRole = new Role().setAuditEnabled(false).setSelfServe(false);
        List<Notification> notifications = new PutMembershipNotificationTask("testdomain1", "neworg", notifyRole, null, dbsvc, USER_DOMAIN_PREFIX).getNotifications();
        notificationManager.sendNotifications(notifications);
        Mockito.verify(mockNotificationService, times(0)).notify(any());
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullNotificationSvc() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        NotificationServiceFactory testfact = () -> null;
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        Role notifyRole = new Role().setAuditEnabled(false).setSelfServe(false);
        List<Notification> notifications = new PutMembershipNotificationTask("testdomain1", "neworg", notifyRole, null, dbsvc, USER_DOMAIN_PREFIX).getNotifications();
        notificationManager.sendNotifications(notifications);
        verify(mockNotificationService, never()).notify(any(Notification.class));
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

        Notification notification = new Notification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL);
        notification.setDetails(details);
        PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter converter = new PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter();
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("dom1"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("user.member1"));
        assertTrue(body.contains("test reason"));
        assertTrue(body.contains("user.requester"));
        assertTrue(body.contains("https://athenz.example.com/workflow"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
    }

    @Test
    public void getEmailSubject() {
        Notification notification = new Notification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL);
        PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter converter = new PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter();
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Membership Approval Notification");
    }
}
