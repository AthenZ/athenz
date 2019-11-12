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
import com.yahoo.rdl.Timestamp;
import org.mockito.*;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class NotificationManagerTest {

    @Mock private DBService mockDbService;
    @Mock private AthenzDomain mockAthenzDomain;

    @BeforeClass
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @BeforeMethod
    public void setUpMethod() {
        System.setProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS, "com.yahoo.athenz.zms.notification.MockNotificationServiceFactory");
        Mockito.when(mockDbService.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());
    }

    @AfterMethod(alwaysRun=true)
    public void clearMethod() {
        System.clearProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);
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
        System.clearProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);

        Mockito.when(mockDbService.getAthenzDomain("testdom", false)).thenReturn(mockAthenzDomain);
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

        NotificationManager notificationManager = new NotificationManager(mockDbService, ZMSConsts.USER_DOMAIN_PREFIX);
        Notification notification = notificationManager.createNotification("MEMBERSHIP_APPROVAL", recipients, details);
        notificationManager.shutdown();
        assertNotNull(notification);
        assertFalse(notification.getRecipients().contains("testdom2.svc1"));
    }

    @Test
    public void testCreaeteNotificationNullRecipients() {

        NotificationManager notificationManager = new NotificationManager(mockDbService, ZMSConsts.USER_DOMAIN_PREFIX);
        assertNull(notificationManager.createNotification("MEMBERSHIP_APPROVAL", (Set<String>) null, null));
        assertNull(notificationManager.createNotification("MEMBERSHIP_APPROVAL", Collections.emptySet(), null));
        notificationManager.shutdown();
    }

    @Test
    public void testCreateNotificationNoValidRecipients() {
        Set<String> recipients = new HashSet<>();
        recipients.add("unix.ykeykey");
        recipients.add("testdom:role.role3");

        Mockito.when(mockDbService.getAthenzDomain("testdom", false)).thenReturn(mockAthenzDomain);
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

        NotificationManager notificationManager = new NotificationManager(mockDbService, ZMSConsts.USER_DOMAIN_PREFIX);
        notificationManager.shutdown();
        Notification notification = notificationManager.createNotification("MEMBERSHIP_APPROVAL", recipients, null);
        assertNull(notification);
    }

    @Test
    public void testNotificationManagerFail() {
        System.setProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS, "aa");

        NotificationManager notificationManager = new NotificationManager(mockDbService, ZMSConsts.USER_DOMAIN_PREFIX);
        assertNotNull(notificationManager);
        assertFalse(notificationManager.isNotificationFeatureAvailable());
        notificationManager.shutdown();

        System.clearProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);
    }

    @Test
    public void testNotificationManagerNullFactoryClass() {
        System.clearProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);
        NotificationManager notificationManager = new NotificationManager(mockDbService, ZMSConsts.USER_DOMAIN_PREFIX);
        assertNotNull(notificationManager);
        notificationManager.shutdown();
    }

    @Test
    public void testNotificationManagerServiceNull() {
         NotificationServiceFactory testfact = () -> null;
         NotificationManager notificationManager = new NotificationManager(mockDbService, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
         notificationManager.shutdown();
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

        Role domainRole = new Role().setName("sys.auth.audit.domain:role.testdomain1").setRoleMembers(roleMembers);

        roleMembers = new ArrayList<>();
        rm = new RoleMember().setMemberName("user.orgapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.orgapprover2").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("dom2.testsvc1").setActive(true);
        roleMembers.add(rm);

        Role orgRole = new Role().setName("sys.auth.audit.org:role.neworg").setRoleMembers(roleMembers);

        Mockito.when(dbsvc.getRole("sys.auth.audit.domain", "testdomain1", false, true, false)).thenReturn(domainRole);
        Mockito.when(dbsvc.getRole("sys.auth.audit.org", "neworg", false, true, false)).thenReturn(orgRole);

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

        Role orgRole = new Role().setName("sys.auth.audit.org:role.neworg").setRoleMembers(roleMembers);

        Mockito.when(dbsvc.getRole("sys.auth.audit.domain", "testdomain1", false, true, false)).thenReturn(null);
        Mockito.when(dbsvc.getRole("sys.auth.audit.org", "neworg", false, true, false)).thenReturn(orgRole);

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

        Role domainRole = new Role().setName("sys.auth.audit.org:role.neworg").setRoleMembers(roleMembers);

        Mockito.when(dbsvc.getRole("sys.auth.audit.domain", "testdomain1", false, true, false)).thenReturn(domainRole);
        Mockito.when(dbsvc.getRole("sys.auth.audit.org", "neworg", false, true, false)).thenReturn(null);

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
    public void testGenerateAndSendPostPutMembershipNotificationInvalidType() {
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = new NotificationManager(mockDbService, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
        notificationManager.shutdown();
        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", false, false, null);
        Mockito.verify(mockNotificationService, times(0)).notify(any());
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullNotificationSvc() {
        NotificationServiceFactory testfact = () -> null;
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationManager notificationManager = new NotificationManager(mockDbService, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
        notificationManager.shutdown();
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
        ZMSTestUtils.sleep(2000);
        notificationManager.shutdown();
        assertTrue(true);
    }

    @Test
    public void testSendPendingMembershipApprovalReminders() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        Mockito.when(dbsvc.getRoleExpiryMembers()).thenReturn(null);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getPendingMembershipApproverRoles())
                .thenReturn(null)
                .thenReturn(Collections.singleton("user.joe"));

        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);

        ZMSTestUtils.sleep(1000);

        NotificationManager.RoleMemberReminders reminders = notificationManager.new RoleMemberReminders();
        reminders.sendPendingMembershipApprovalReminders();

        // we should get 1 notification processed

        Mockito.verify(mockNotificationService, times(1)).notify(any());
        notificationManager.shutdown();
    }

    @Test
    public void testProcessMemberExpiryReminderEmptySet() {

        System.clearProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);
        NotificationManager notificationManager = new NotificationManager(mockDbService, ZMSConsts.USER_DOMAIN_PREFIX);

        NotificationManager.RoleMemberReminders reminders = notificationManager.new RoleMemberReminders();

        Map<String, String> details = reminders.processMemberExpiryReminder("athenz", null);
        assertTrue(details.isEmpty());

        details = reminders.processMemberExpiryReminder("athenz", Collections.emptyList());
        assertTrue(details.isEmpty());

        final String ts = Timestamp.fromMillis(100).toString();
        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz").setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));

        details = reminders.processMemberExpiryReminder("athenz", memberRoles);
        assertEquals(details.size(), 2);
        assertEquals(details.get(NotificationService.NOTIFICATION_DETAILS_EXPIRY_MEMBERS),
            "user.joe;role1;" + ts);
        assertEquals(details.get(NotificationService.NOTIFICATION_DETAILS_DOMAIN), "athenz");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz").setMemberName("user.jane")
                .setExpiration(Timestamp.fromMillis(100)));
        details = reminders.processMemberExpiryReminder("athenz", memberRoles);
        assertEquals(details.size(), 2);
        assertEquals(details.get(NotificationService.NOTIFICATION_DETAILS_EXPIRY_MEMBERS),
                "user.joe;role1;" + ts + "|user.jane;role1;" + ts);
        assertEquals(details.get(NotificationService.NOTIFICATION_DETAILS_DOMAIN), "athenz");

        notificationManager.shutdown();
    }

    @Test
    public void testProcessRoleExpiryReminder() {

        System.clearProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);
        NotificationManager notificationManager = new NotificationManager(mockDbService, ZMSConsts.USER_DOMAIN_PREFIX);

        NotificationManager.RoleMemberReminders reminders = notificationManager.new RoleMemberReminders();

        Map<String, List<MemberRole>> domainAdminMap = new HashMap<>();
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");

        Map<String, String> details = reminders.processRoleExpiryReminder(domainAdminMap, roleMember);
        assertTrue(details.isEmpty());

        domainAdminMap.clear();
        roleMember.setMemberRoles(Collections.emptyList());
        details = reminders.processRoleExpiryReminder(domainAdminMap, roleMember);
        assertTrue(details.isEmpty());

        final String ts = Timestamp.fromMillis(100).toString();
        domainAdminMap.clear();

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        roleMember.setMemberRoles(memberRoles);

        domainAdminMap.clear();
        details = reminders.processRoleExpiryReminder(domainAdminMap, roleMember);
        assertEquals(details.size(), 2);
        assertEquals(details.get(NotificationService.NOTIFICATION_DETAILS_EXPIRY_ROLES),
                "athenz1;role1;" + ts);
        assertEquals(details.get(NotificationService.NOTIFICATION_DETAILS_MEMBER), "user.joe");

        assertEquals(domainAdminMap.size(), 1);
        List<MemberRole> domainRoleMembers = domainAdminMap.get("athenz1");
        assertEquals(domainRoleMembers.size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.joe");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        domainAdminMap.clear();
        details = reminders.processRoleExpiryReminder(domainAdminMap, roleMember);
        assertEquals(details.size(), 2);
        assertEquals(details.get(NotificationService.NOTIFICATION_DETAILS_EXPIRY_ROLES),
                "athenz1;role1;" + ts + "|athenz2;role1;" + ts + "|athenz2;role2;" + ts);
        assertEquals(details.get(NotificationService.NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(domainAdminMap.size(), 2);
        domainRoleMembers = domainAdminMap.get("athenz1");
        assertEquals(domainRoleMembers.size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.joe");
        domainRoleMembers = domainAdminMap.get("athenz2");
        assertEquals(domainRoleMembers.size(), 2);
        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.joe");
        assertEquals(domainRoleMembers.get(1).getMemberName(), "user.joe");

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryRemindersException() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        // we're going to throw an exception when called

        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenThrow(new IllegalArgumentException());
        Mockito.when(dbsvc.getRoleExpiryMembers()).thenThrow(new IllegalArgumentException());
        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);
        NotificationManager.RoleMemberReminders reminders = notificationManager.new RoleMemberReminders();

        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        try {
            reminders.sendRoleMemberExpiryReminders();
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
        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);

        NotificationManager.RoleMemberReminders reminders = notificationManager.new RoleMemberReminders();

        // we're going to return an empty set

        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(null);

        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        reminders.sendRoleMemberExpiryReminders();
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

        Mockito.when(dbsvc.getRoleExpiryMembers())
                .thenReturn(null)
                .thenReturn(expiryMembers);

        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);

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

        Mockito.when(dbsvc.getAthenzDomain("athenz1", false)).thenReturn(domain);

        NotificationManager.RoleMemberReminders reminders = notificationManager.new RoleMemberReminders();
        reminders.sendRoleMemberExpiryReminders();

        // we should get 2 notifications - one for user and one for domain

        Mockito.verify(mockNotificationService, times(2)).notify(any());
        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryRemindersNoValidDomain() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

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

        Mockito.when(dbsvc.getRoleExpiryMembers())
                .thenReturn(null)
                .thenReturn(expiryMembers);

        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);

        ZMSTestUtils.sleep(1000);

        // we're going to return not found domain always

        Mockito.when(dbsvc.getAthenzDomain("athenz1", false)).thenReturn(null);

        NotificationManager.RoleMemberReminders reminders = notificationManager.new RoleMemberReminders();
        reminders.sendRoleMemberExpiryReminders();

        // we should get 0 notifications

        Mockito.verify(mockNotificationService, times(0)).notify(any());
        notificationManager.shutdown();
    }

    @Test
    public void testCreateNotificationsInvalidRecipient() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleExpiryMembers()).thenReturn(null);
        NotificationManager notificationManager = new NotificationManager(dbsvc, testfact, ZMSConsts.USER_DOMAIN_PREFIX);

        Map<String, String> details = new HashMap<>();
        assertNull(notificationManager.createNotification("reminder", (String) null, details));
        assertNull(notificationManager.createNotification("reminder", "", details));
        assertNull(notificationManager.createNotification("reminder", "athenz", details));

        // valid service name but we have no valid domain so we're still
        // going to get null notification

        assertNull(notificationManager.createNotification("reminder", "athenz.service", details));
        notificationManager.shutdown();
    }
}
