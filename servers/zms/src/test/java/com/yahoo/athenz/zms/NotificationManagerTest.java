/*
 * Copyright 2019 Oath Holdings Inc.
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

package com.yahoo.athenz.zms;

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import com.yahoo.athenz.zms.store.AthenzDomain;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class NotificationManagerTest {

    @Mock private DBService dbService;
    @Mock private AthenzDomain mockAthenzDomain;

    @BeforeClass
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        System.setProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS, "com.yahoo.athenz.zms.notification.MockNotificationServiceFactory");
    }

    @Test
    public void testSendNotification() {
        DBService dbsvc = Mockito.mock(DBService.class);
        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(recipients);
        NotificationManager notificationManager = new NotificationManager(dbsvc, ZMSConsts.USER_DOMAIN_PREFIX);
        notificationManager.shutdown();
        notificationManager.sendNotification(notification);
        assertTrue(true);
    }

    @Test
    public void testSendNotificationNullService() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationServiceFactory testfact = () -> null;
        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(recipients);
        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
        notificationManager.shutdown();
        notificationManager.sendNotification(notification);
        assertTrue(true);
    }

    @Test
    public void testCreateNotification() {
        Mockito.when(dbService.getAthenzDomain("testdom", false)).thenReturn(mockAthenzDomain);
        List<Role> roles = new ArrayList<>();
        List<RoleMember> members = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.use1");
        members.add(rm);
        rm = new RoleMember().setMemberName("user.use2");
        members.add(rm);
        rm = new RoleMember().setMemberName("testdom2.svc1");
        members.add(rm);
        Role r = new Role().setName("testdom:role.role1").setRoleMembers(members);
        roles.add(r);
        Mockito.when(mockAthenzDomain.getName()).thenReturn("testdom");
        Mockito.when(mockAthenzDomain.getRoles()).thenReturn(roles);

        Set<String> recipients = new HashSet<>();
        recipients.add("testdom:role.role1");
        recipients.add("user.user3");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdom");
        details.put("role", "role1");

        NotificationManager notificationManager = new NotificationManager(dbService, ZMSConsts.USER_DOMAIN_PREFIX);
        Notification notification = notificationManager.createNotification("MEMBERSHIP_APPROVAL", recipients, details);

        assertNotNull(notification);
        assertFalse(notification.getRecipients().contains("testdom2.svc1"));
    }

    @Test
    public void testCreateNotificationNoValidRecipients() {
        Set<String> recipients = new HashSet<>();
        recipients.add("unix.ykeykey");
        recipients.add("testdom:role.role3");

        Mockito.when(dbService.getAthenzDomain("testdom", false)).thenReturn(mockAthenzDomain);
        List<Role> roles = new ArrayList<>();
        List<RoleMember> members = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.use1");
        members.add(rm);
        rm = new RoleMember().setMemberName("user.use2");
        members.add(rm);
        Role r = new Role().setName("testdom:role.role1").setRoleMembers(members);
        roles.add(r);
        Mockito.when(mockAthenzDomain.getName()).thenReturn("testdom");
        Mockito.when(mockAthenzDomain.getRoles()).thenReturn(roles);

        NotificationManager notificationManager = new NotificationManager(dbService, ZMSConsts.USER_DOMAIN_PREFIX);

        Notification notification = notificationManager.createNotification("MEMBERSHIP_APPROVAL", recipients, null);
        assertNull(notification);
    }

    @Test
    public void testNotificationManagerFail() {
        System.setProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS, "aa");
        try {
            NotificationManager notificationManager = new NotificationManager(dbService, ZMSConsts.USER_DOMAIN_PREFIX);
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid notification service factory"));
        }
        System.setProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS, "com.yahoo.athenz.zms.notification.MockNotificationServiceFactory");
    }

    @Test
    public void testNotificationManagerNullFactoryClass() {
        System.clearProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);
        try {
            NotificationManager notificationManager = new NotificationManager(dbService, ZMSConsts.USER_DOMAIN_PREFIX);
        } catch (Exception ex) {
            fail();
        }
        System.setProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS, "com.yahoo.athenz.zms.notification.MockNotificationServiceFactory");
    }

    @Test
    public void testNotificationManagerServiceNull() {
        try {
            NotificationServiceFactory testfact = () -> null;
            NotificationManager notificationManager = new NotificationManager(dbService, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
            notificationManager.shutdown();
            assertTrue(true);
        } catch (Exception ex) {
            fail();
        }
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotification() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
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

        Role domainRole = new Role().setName("sys.auth.audit:role.approver.neworg.testdomain1").setRoleMembers(roleMembers);

        roleMembers = new ArrayList<>();
        rm = new RoleMember().setMemberName("user.orgapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.orgapprover2").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("dom2.testsvc1").setActive(true);
        roleMembers.add(rm);

        Role orgRole = new Role().setName("sys.auth.audit:role.approver.neworg").setRoleMembers(roleMembers);

        Mockito.when(dbsvc.getRole("sys.auth.audit", "approver.neworg.testdomain1", false, true, false)).thenReturn(domainRole);
        Mockito.when(dbsvc.getRole("sys.auth.audit", "approver.neworg", false, true, false)).thenReturn(orgRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", true, false, details);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification.addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2")
                .addRecipient("user.orgapprover1")
                .addRecipient("user.orgapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(notification, actualNotification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullDomainRole() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
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

        Role orgRole = new Role().setName("sys.auth.audit:role.approver.neworg").setRoleMembers(roleMembers);

        Mockito.when(dbsvc.getRole("sys.auth.audit", "approver.neworg.testdomain1", false, true, false)).thenReturn(null);
        Mockito.when(dbsvc.getRole("sys.auth.audit", "approver.neworg", false, true, false)).thenReturn(orgRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", true, false, details);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification
                .addRecipient("user.orgapprover1")
                .addRecipient("user.orgapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(notification, actualNotification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullOrgRole() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
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

        Role domainRole = new Role().setName("sys.auth.audit:role.approver.neworg").setRoleMembers(roleMembers);

        Mockito.when(dbsvc.getRole("sys.auth.audit", "approver.neworg.testdomain1", false, true, false)).thenReturn(domainRole);
        Mockito.when(dbsvc.getRole("sys.auth.audit", "approver.neworg", false, true, false)).thenReturn(null);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", true, false, details);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification
                .addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(notification, actualNotification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationSelfserve() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
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

        Mockito.when(dbsvc.getRole("testdomain1", "admin", false, true, false)).thenReturn(adminRole);

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", false, true, details);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification
                .addRecipient("user.domadmin1")
                .addRecipient("user.domadmin2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");

        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(notification, actualNotification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationException() {
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = new NotificationManager(dbService, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", false, false, null);
        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);
        Mockito.verify(mockNotificationService, atLeastOnce()).notify(captor.capture());
        Notification actualNotification = captor.getValue();
        assertNull(actualNotification);

    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullNotificationSvc() {
        NotificationServiceFactory testfact = () -> null;
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationManager notificationManager = new NotificationManager(dbService, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", false, false, null);
        verify(mockNotificationService, never()).notify(any(Notification.class));
    }

    @Test
    public void testSendPendingMembershipApprovalRemindersException() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenThrow(new ResourceException(400));
        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
        // wait for 2 seconds for scheduler to throw an exception
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            //ignored
        }
        notificationManager.shutdown();
        assertTrue(true);
    }
}