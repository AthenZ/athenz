package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.AthenzDomain;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
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
        List<Notification> notifications = new ArrayList<>();
        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        notifications.add(notification);

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
}