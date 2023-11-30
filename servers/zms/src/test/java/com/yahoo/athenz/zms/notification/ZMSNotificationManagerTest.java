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

public class ZMSNotificationManagerTest {
    final NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

    @BeforeClass
    public void setUp() {
        MockitoAnnotations.openMocks(this);
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
        Notification notification = new Notification();
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(recipients);
        NotificationManager notificationManager = getNotificationManager(dbsvc, null);

        notificationManager.shutdown();
        notificationManager.sendNotifications(Collections.singletonList(notification));
    }

    public static NotificationManager getNotificationManager(DBService dbsvc, NotificationServiceFactory notificationServiceFactory) {
        List<NotificationServiceFactory> notificationServiceFactories = (notificationServiceFactory == null) ?
                null : Collections.singletonList(notificationServiceFactory);
        return getNotificationManagerMultipleServices(dbsvc, notificationServiceFactories);
    }

    public static NotificationManager getNotificationManagerMultipleServices(DBService dbsvc, List<NotificationServiceFactory> notificationServiceFactories) {
        ZMSNotificationTaskFactory zmsNotificationTaskFactory = new ZMSNotificationTaskFactory(dbsvc, USER_DOMAIN_PREFIX, new NotificationToEmailConverterCommon(null));
        List<NotificationTask> notificationTasks = zmsNotificationTaskFactory.getNotificationTasks();

        if (notificationServiceFactories == null) {
            return new NotificationManager(notificationTasks, null);
        }
        return new NotificationManager(notificationServiceFactories, notificationTasks, null);
    }

    @Test
    public void testSendNotificationNullService() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationServiceFactory testfact = () -> null;
        Notification notification = new Notification();
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(recipients);
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
        notificationManager.sendNotifications(Collections.singletonList(notification));
        assertTrue(true);
    }

    @Test
    public void testCreateNotification() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(Collections.emptySet());

        AthenzDomain mockAthenzDomain = Mockito.mock(AthenzDomain.class);

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

        Mockito.when(dbsvc.getRolesByDomain("testdom")).thenReturn(roles);
        Mockito.when(dbsvc.getRole("testdom", "role1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(r);

        Set<String> recipients = new HashSet<>();
        recipients.add("testdom:role.role1");
        recipients.add("user.user3");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "testdom");
        details.put("role", "role1");

        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        PutRoleMembershipNotificationTask.PutMembershipNotificationToEmailConverter converter = new PutRoleMembershipNotificationTask.PutMembershipNotificationToEmailConverter(notificationToEmailConverterCommon);
        PutRoleMembershipNotificationTask.PutMembershipNotificationToMetricConverter metricConverter = new PutRoleMembershipNotificationTask.PutMembershipNotificationToMetricConverter();
        Notification notification = notificationCommon.createNotification(recipients, details, converter, metricConverter);
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
        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(Collections.emptySet());

        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        assertNull(notificationCommon.createNotification((Set<String>) null, null, null, null));
        assertNull(notificationCommon.createNotification(Collections.emptySet(), null, null, null));
    }

    @Test
    public void testCreateNotificationNoValidRecipients() {

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(Collections.emptySet());

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

        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        PendingRoleMembershipApprovalNotificationTask.PendingRoleMembershipApprovalNotificationToEmailConverter converter = new PendingRoleMembershipApprovalNotificationTask.PendingRoleMembershipApprovalNotificationToEmailConverter(notificationToEmailConverterCommon);
        PendingRoleMembershipApprovalNotificationTask.PendingRoleMembershipApprovalNotificationToMetricConverter metricConverter = new PendingRoleMembershipApprovalNotificationTask.PendingRoleMembershipApprovalNotificationToMetricConverter();
        Notification notification = notificationCommon.createNotification(recipients, null, converter, metricConverter);
        assertNull(notification);
    }

    @Test
    public void testNotificationManagerFail() {
        System.setProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS, "aa");
        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(Collections.emptySet());

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
        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(Collections.emptySet());

        NotificationManager notificationManager = getNotificationManager(dbsvc, null);
        assertNotNull(notificationManager);
        notificationManager.shutdown();
    }

    @Test
    public void testNotificationManagerServiceNull() {
        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenReturn(Collections.emptySet());

        NotificationServiceFactory testfact = () -> null;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);
        notificationManager.shutdown();
    }

    @Test
    public void testSendPendingMembershipApprovalRemindersException() {
        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        Mockito.when(dbsvc.getPendingMembershipApproverRoles(1)).thenThrow(new ResourceException(400));
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

        Mockito.when(dbsvc.getRoleExpiryMembers(1)).thenReturn(null);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        Map<String, String> details = new HashMap<>();
        PendingRoleMembershipApprovalNotificationTask.PendingRoleMembershipApprovalNotificationToEmailConverter converter = new PendingRoleMembershipApprovalNotificationTask.PendingRoleMembershipApprovalNotificationToEmailConverter(notificationToEmailConverterCommon);
        PendingRoleMembershipApprovalNotificationTask.PendingRoleMembershipApprovalNotificationToMetricConverter metricConverter = new PendingRoleMembershipApprovalNotificationTask.PendingRoleMembershipApprovalNotificationToMetricConverter();
        assertNull(notificationCommon.createNotification((String) null, details, converter, metricConverter));
        assertNull(notificationCommon.createNotification("", details, converter, metricConverter));
        assertNull(notificationCommon.createNotification("athenz", details, converter, metricConverter));

        // valid service name but we have no valid domain so we're still
        // going to get null notification

        assertNull(notificationCommon.createNotification("athenz.service", details, converter, metricConverter));
    }

    @Test
    public void testNotificationUtils() {
        NotificationUtils utils = new NotificationUtils();
        assertNotNull(utils);
    }
}
