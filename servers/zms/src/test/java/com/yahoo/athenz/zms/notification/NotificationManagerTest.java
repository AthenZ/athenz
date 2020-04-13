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

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_PROP_SERVICE_FACTORY_CLASS;
import static org.testng.Assert.*;

public class NotificationManagerTest {

    @BeforeClass
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @BeforeMethod
    public void setUpMethod() {
        System.setProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS, "com.yahoo.athenz.zms.notification.MockNotificationServiceFactory");
    }

    @AfterMethod(alwaysRun=true)
    public void clearMethod() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
    }

    @Test
    public void testSendNotification() {
        DBService dbsvc = Mockito.mock(DBService.class);
        Notification notification = new Notification("MEMBERSHIP_APPROVAL");
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(recipients);
        NotificationManager notificationManager = getNotificationManager(dbsvc, null);

        notificationManager.shutdown();
        notificationManager.sendNotifications(Collections.singletonList(notification));
    }

    public static NotificationManager getNotificationManager(DBService dbsvc, NotificationServiceFactory notificationServiceFactory) {
        ZMSNotificationTaskFactory zmsNotificationTaskFactory = new ZMSNotificationTaskFactory(dbsvc, USER_DOMAIN_PREFIX);
        List<NotificationTask> notificationTasks = zmsNotificationTaskFactory.getNotificationTasks();

        if (notificationServiceFactory == null) {
            return new NotificationManager(notificationTasks);
        }
        return new NotificationManager(notificationServiceFactory, notificationTasks);
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
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        notificationManager.sendNotifications(Collections.singletonList(notification));
        assertTrue(true);
    }

    @Test
    public void testCreateNotification() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        AthenzDomain mockAthenzDomain = Mockito.mock(AthenzDomain.class);

        Mockito.when(dbsvc.getAthenzDomain("testdom", false)).thenReturn(mockAthenzDomain);
        List<Role> roles = new ArrayList<>();
        List<RoleMember> members = new ArrayList<>();

        // Add role users
        RoleMember rm = new RoleMember().setMemberName("user.use1");
        members.add(rm);
        rm = new RoleMember().setMemberName("user.use2");
        members.add(rm);

        // Add role user who's authorization just expired
        long currentTimeInMillis = System.currentTimeMillis();
        rm = new RoleMember().setMemberName("user.expired");
        rm.setExpiration(Timestamp.fromMillis(currentTimeInMillis));
        members.add(rm);

        // Add role user who's authorization will expire tomorrow
        rm = new RoleMember().setMemberName("user.notExpiredYet");
        rm.setExpiration(Timestamp.fromMillis(currentTimeInMillis + TimeUnit.DAYS.toMillis(1)));
        members.add(rm);


        // Add role service
        rm = new RoleMember().setMemberName("testdom2.svc1");
        members.add(rm);

        // Add role
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

        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(zmsDomainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter converter = new PutMembershipNotificationTask.PutMembershipNotificationToEmailConverter();
        Notification notification = notificationCommon.createNotification("MEMBERSHIP_APPROVAL", recipients, details, converter);
        assertNotNull(notification);

        // Assert service is not a receipient
        assertFalse(notification.getRecipients().contains("testdom2.svc1"));

        // Assert expired user is not a recipient
        assertFalse(notification.getRecipients().contains("user.expired"));

        // Assert user with tomorrow's expiration date is a valid recipient
        assertTrue(notification.getRecipients().contains("user.notExpiredYet"));

        // Assert user with no expiration date is a valid recipient
        assertTrue(notification.getRecipients().contains("user.use1"));
    }

    @Test
    public void testCreaeteNotificationNullRecipients() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(zmsDomainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        assertNull(notificationCommon.createNotification("MEMBERSHIP_APPROVAL", (Set<String>) null, null, null));
        assertNull(notificationCommon.createNotification("MEMBERSHIP_APPROVAL", Collections.emptySet(), null, null));
    }

    @Test
    public void testCreateNotificationNoValidRecipients() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        AthenzDomain mockAthenzDomain = Mockito.mock(AthenzDomain.class);

        Set<String> recipients = new HashSet<>();
        recipients.add("unix.ykeykey");
        recipients.add("testdom:role.role3");

        Mockito.when(dbsvc.getAthenzDomain("testdom", false)).thenReturn(mockAthenzDomain);
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

        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(zmsDomainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        PendingMembershipApprovalNotificationTask.PendingMembershipApprovalNotificationToEmailConverter converter = new PendingMembershipApprovalNotificationTask.PendingMembershipApprovalNotificationToEmailConverter();
        Notification notification = notificationCommon.createNotification("MEMBERSHIP_APPROVAL", recipients, null, converter);
        assertNull(notification);
    }

    @Test
    public void testNotificationManagerFail() {
        System.setProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS, "aa");
        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        NotificationManager notificationManager = getNotificationManager(dbsvc, null);
        assertNotNull(notificationManager);
        assertFalse(notificationManager.isNotificationFeatureAvailable());
        notificationManager.shutdown();

        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
    }

    @Test
    public void testNotificationManagerNullFactoryClass() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        NotificationManager notificationManager = getNotificationManager(dbsvc, null);
        assertNotNull(notificationManager);
        notificationManager.shutdown();
    }

    @Test
    public void testNotificationManagerServiceNull() {
        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        NotificationServiceFactory testfact = () -> null;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
    }

    @Test
    public void testSendPendingMembershipApprovalRemindersException() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenThrow(new ResourceException(400));
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        // wait for 2 seconds for scheduler to throw an exception
        ZMSTestUtils.sleep(2000);
        notificationManager.shutdown();
        assertTrue(true);
    }

    @Test
    public void testCreateNotificationsInvalidRecipient() {

        DBService dbsvc = Mockito.mock(DBService.class);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleExpiryMembers()).thenReturn(null);
        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(zmsDomainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        Map<String, String> details = new HashMap<>();
        PendingMembershipApprovalNotificationTask.PendingMembershipApprovalNotificationToEmailConverter converter = new PendingMembershipApprovalNotificationTask.PendingMembershipApprovalNotificationToEmailConverter();
        assertNull(notificationCommon.createNotification("reminder", (String) null, details, converter));
        assertNull(notificationCommon.createNotification("reminder", "", details, converter));
        assertNull(notificationCommon.createNotification("reminder", "athenz", details, converter));

        // valid service name but we have no valid domain so we're still
        // going to get null notification

        assertNull(notificationCommon.createNotification("reminder", "athenz.service", details, converter));
    }
}
