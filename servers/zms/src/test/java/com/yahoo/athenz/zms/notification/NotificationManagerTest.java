package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.store.AthenzDomain;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.testng.Assert.*;

public class NotificationManagerTest {

    @Mock private DBService dbService;
    @Mock private AthenzDomain mockAthenzDomain;

    @BeforeClass
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        System.setProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS, "com.yahoo.athenz.zms.notification.impl.MockNotificationServiceFactory");
    }

    @Test
    public void testSendNotification() {

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        Mockito.when(dbService.getPendingMembershipApproverRoles()).thenReturn(recipients);
        NotificationManager notificationManager = new NotificationManager(dbService);
        notificationManager.sendNotification(notification);
        notificationManager.shutdown();
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

        NotificationManager notificationManager = new NotificationManager(dbService);
        Notification notification = notificationManager.createNotification("MEMBERSHIP_APPROVAL", recipients, details);

        assertNotNull(notification);
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

        NotificationManager notificationManager = new NotificationManager(dbService);
        try {
            Notification notification = notificationManager.createNotification("MEMBERSHIP_APPROVAL", recipients, null);
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 400);
        }
    }

    @Test
    public void testNotificationManagerFail() {
        System.setProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS, "aa");
        try {
            NotificationManager notificationManager = new NotificationManager(dbService);
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid notification service factory"));
        }
        System.setProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS, "com.yahoo.athenz.zms.notification.impl.MockNotificationServiceFactory");
    }

    @Test
    public void testNotificationManagerServiceNull() {
        try {
            NotificationServiceFactory testfact = () -> null;
            NotificationManager notificationManager = new NotificationManager(dbService, testfact);
            assertNull(notificationManager.scheduledExecutor);
            notificationManager.shutdown();
            assertTrue(true);
        } catch (Exception ex) {
            fail();
        }
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotification() {

        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> null;
        NotificationManager notificationManager = new NotificationManager(dbService, testfact);
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.domapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.domapprover2").setActive(true);
        roleMembers.add(rm);

        Role domainRole = new Role().setName("sys.auth.audit:role.approver.neworg.testdomain1").setRoleMembers(roleMembers);

        roleMembers = new ArrayList<>();
        rm = new RoleMember().setMemberName("user.orgapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.orgapprover2").setActive(true);
        roleMembers.add(rm);

        Role orgRole = new Role().setName("sys.auth.audit:role.approver.neworg").setRoleMembers(roleMembers);

        Mockito.when(dbService.getRole("sys.auth.audit", "approver.neworg.testdomain1", false, true, false)).thenReturn(domainRole);
        Mockito.when(dbService.getRole("sys.auth.audit", "approver.neworg", false, true, false)).thenReturn(orgRole);

        notificationManager.notificationService = mockNotificationService;

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", true, false, details);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification.addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2")
                .addRecipient("user.orgapprover1")
                .addRecipient("user.orgapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");

        Mockito.verify(mockNotificationService).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(notification, actualNotification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullDomainRole() {
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> null;
        NotificationManager notificationManager = new NotificationManager(dbService, testfact);
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.orgapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.orgapprover2").setActive(true);
        roleMembers.add(rm);

        Role orgRole = new Role().setName("sys.auth.audit:role.approver.neworg").setRoleMembers(roleMembers);

        Mockito.when(dbService.getRole("sys.auth.audit", "approver.neworg.testdomain1", false, true, false)).thenReturn(null);
        Mockito.when(dbService.getRole("sys.auth.audit", "approver.neworg", false, true, false)).thenReturn(orgRole);

        notificationManager.notificationService = mockNotificationService;

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", true, false, details);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification
                .addRecipient("user.orgapprover1")
                .addRecipient("user.orgapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");

        Mockito.verify(mockNotificationService).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(notification, actualNotification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationNullOrgRole() {
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> null;
        NotificationManager notificationManager = new NotificationManager(dbService, testfact);
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.domapprover1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.domapprover2").setActive(true);
        roleMembers.add(rm);

        Role domainRole = new Role().setName("sys.auth.audit:role.approver.neworg").setRoleMembers(roleMembers);

        Mockito.when(dbService.getRole("sys.auth.audit", "approver.neworg.testdomain1", false, true, false)).thenReturn(domainRole);
        Mockito.when(dbService.getRole("sys.auth.audit", "approver.neworg", false, true, false)).thenReturn(null);

        notificationManager.notificationService = mockNotificationService;

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", true, false, details);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification
                .addRecipient("user.domapprover1")
                .addRecipient("user.domapprover2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");

        Mockito.verify(mockNotificationService).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(notification, actualNotification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationSelfserve() {
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> null;
        NotificationManager notificationManager = new NotificationManager(dbService, testfact);
        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdomain1");
        details.put("role", "role1");

        List<RoleMember> roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.domadmin1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.domadmin2").setActive(true);
        roleMembers.add(rm);

        Role adminRole = new Role().setName("testdomain1:role.admin").setRoleMembers(roleMembers);

        Mockito.when(dbService.getRole("testdomain1", "admin", false, true, false)).thenReturn(adminRole);

        notificationManager.notificationService = mockNotificationService;

        ArgumentCaptor<Notification> captor = ArgumentCaptor.forClass(Notification.class);

        notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", false, true, details);

        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        notification
                .addRecipient("user.domadmin1")
                .addRecipient("user.domadmin2");
        notification.addDetails("domain", "testdomain1").addDetails("role", "role1");

        Mockito.verify(mockNotificationService).notify(captor.capture());
        Notification actualNotification = captor.getValue();

        assertEquals(notification, actualNotification);
    }

    @Test
    public void testGenerateAndSendPostPutMembershipNotificationException() {
        NotificationServiceFactory testfact = () -> null;
        NotificationManager notificationManager = new NotificationManager(dbService, testfact);
        try {
            notificationManager.generateAndSendPostPutMembershipNotification("testdomain1", "neworg", false, false, null);
        } catch (ResourceException r) {
            assertEquals(r.getCode(), 400);
        }
    }
}