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

package com.yahoo.athenz.common.server.notification;

import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.zms.ResourceException;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_PROP_SERVICE_FACTORY_CLASS;
import static org.testng.Assert.*;

public class NotificationManagerTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationManagerTest.class);

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
        Notification notification = new Notification();
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        NotificationManager notificationManager = getNotificationManager(null);
        assertFalse(notificationManager.isNotificationFeatureAvailable());

        notificationManager.shutdown();
        notificationManager.sendNotifications(Collections.singletonList(notification));

        NotificationService service1 = Mockito.mock(NotificationService.class);
        NotificationServiceFactory factory1 = () -> service1;

        NotificationService service2 = Mockito.mock(NotificationService.class);
        NotificationServiceFactory factory2 = () -> service2;

        List<NotificationServiceFactory> factories = new ArrayList<>();
        factories.add(factory1);
        factories.add(factory2);

        notificationManager = getNotificationManagerMultipleServices(factories);
        assertTrue(notificationManager.isNotificationFeatureAvailable());

        notificationManager.sendNotifications(Collections.singletonList(notification));
        Mockito.verify(service1, Mockito.times(1)).notify(notification);
        Mockito.verify(service2, Mockito.times(1)).notify(notification);
    }

    public static NotificationManager getNotificationManager(NotificationServiceFactory notificationServiceFactory) {
        List<NotificationServiceFactory> notificationServiceFactories = (notificationServiceFactory == null) ?
                null : Collections.singletonList(notificationServiceFactory);
        return getNotificationManagerMultipleServices(notificationServiceFactories);
    }

    public static NotificationManager getNotificationManagerMultipleServices(List<NotificationServiceFactory> notificationServiceFactories) {
        NotificationTask notificationTask1 = Mockito.mock(NotificationTask.class);
        NotificationTask notificationTask2 = Mockito.mock(NotificationTask.class);
        List<NotificationTask> notificationTasks = new ArrayList<>();
        notificationTasks.add(notificationTask1);
        notificationTasks.add(notificationTask2);

        if (notificationServiceFactories == null) {
            return new NotificationManager(notificationTasks, null);
        }
        return new NotificationManager(notificationServiceFactories, notificationTasks, null);
    }

    @Test
    public void testNotificationManagerCtor() {
        NotificationTask notificationTask1 = Mockito.mock(NotificationTask.class);
        NotificationTask notificationTask2 = Mockito.mock(NotificationTask.class);
        List<NotificationTask> notificationTasks = new ArrayList<>();
        notificationTasks.add(notificationTask1);
        notificationTasks.add(notificationTask2);

        // Notification factory classes
        String emailNotificationFactory = "com.yahoo.athenz.common.server.notification.impl.NotificationServiceFactoryImpl";
        String metricNotificationFactory = "com.yahoo.athenz.common.server.notification.impl.MetricNotificationServiceFactory";

        // Notification service classes
        String emailNotificationService = "com.yahoo.athenz.common.server.notification.impl.EmailNotificationService";
        String metricNotificationService = "com.yahoo.athenz.common.server.notification.impl.MetricNotificationService";

        // Test with two factories
        System.setProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS, emailNotificationFactory + ", " + metricNotificationFactory);
        NotificationManager notificationManager = new NotificationManager(notificationTasks, null);
        assertEquals(notificationManager.getLoadedNotificationServices().size(), 2);
        assertEquals(notificationManager.getLoadedNotificationServices().get(0), emailNotificationService);
        assertEquals(notificationManager.getLoadedNotificationServices().get(1), metricNotificationService);
        assertTrue(notificationManager.isNotificationFeatureAvailable());

        // Test with a single factory
        System.setProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS, emailNotificationFactory);
        notificationManager = new NotificationManager(notificationTasks, null);
        assertEquals(notificationManager.getLoadedNotificationServices().size(), 1);
        assertEquals(notificationManager.getLoadedNotificationServices().get(0), emailNotificationService);
        assertTrue(notificationManager.isNotificationFeatureAvailable());

        // Test with no factories
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        notificationManager = new NotificationManager(notificationTasks, null);
        assertEquals(notificationManager.getLoadedNotificationServices().size(), 0);
        assertFalse(notificationManager.isNotificationFeatureAvailable());
    }

    @Test
    public void testSendNotificationNullService() {

        NotificationServiceFactory testfact = () -> null;
        Notification notification = new Notification();
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        NotificationManager notificationManager = getNotificationManager(testfact);
        notificationManager.shutdown();
        notificationManager.sendNotifications(Collections.singletonList(notification));
        assertTrue(true);
    }

    @Test
    public void testCreateNotification() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        Set<String> recipients = new HashSet<>();
        recipients.add("user.recipient1");
        recipients.add("user.recipient2");

        Map<String, String> details = new HashMap<>();
        details.put("key1", "value1");
        details.put("key2", "value2");

        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        Notification notification = notificationCommon.createNotification(recipients, details, converter, metricConverter);
        assertNotNull(notification);

        assertTrue(notification.getRecipients().contains("user.recipient1"));
        assertTrue(notification.getRecipients().contains("user.recipient2"));
        assertEquals(notification.getDetails().size(), 2);
        assertEquals(notification.getDetails().get("key1"), "value1");
        assertEquals(notification.getDetails().get("key2"), "value2");
    }

    @Test
    public void testCreateNotificationGroup() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        Mockito.when(rolesProvider.getRolesByDomain(Mockito.any())).thenThrow(new ResourceException(404));
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        String recipient = "test.domain:group.testgroup";

        Map<String, String> details = new HashMap<>();
        details.put("key1", "value1");
        details.put("key2", "value2");

        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        Notification notification = notificationCommon.createNotification(recipient, details, converter, metricConverter);
        Mockito.verify(rolesProvider, Mockito.times(0)).getRolesByDomain(Mockito.any());
        assertNull(notification);
    }

    @Test
    public void testCreateNotificationException() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        Mockito.when(rolesProvider.getRolesByDomain(Mockito.any())).thenThrow(new ResourceException(404));
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        String recipient = "test.domain:role.admin";

        Map<String, String> details = new HashMap<>();
        details.put("key1", "value1");
        details.put("key2", "value2");

        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        Notification notification = notificationCommon.createNotification(recipient, details, converter, metricConverter);
        Mockito.verify(rolesProvider, Mockito.times(1)).getRole("test.domain", "admin", false, true, false);
        assertNull(notification);
    }

    @Test
    public void testCreaeteNotificationNullRecipients() {
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        assertNull(notificationCommon.createNotification((Set<String>) null, null, null, null));
        assertNull(notificationCommon.createNotification(Collections.emptySet(), null, null, null));
    }

    @Test
    public void testCreateNotificationNoValidRecipients() {
        Set<String> recipients = new HashSet<>();
        recipients.add("unix.ykeykey");
        recipients.add("testdom:role.role3");

        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        Notification notification = notificationCommon.createNotification(recipients, null, converter, metricConverter);
        assertNull(notification);
    }

    @Test
    public void testNotificationManagerFail() {
        System.setProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS, "aa");

        NotificationManager notificationManager = getNotificationManager(null);
        assertNotNull(notificationManager);
        assertFalse(notificationManager.isNotificationFeatureAvailable());
        notificationManager.shutdown();

        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
    }

    @Test
    public void testNotificationManagerNullFactoryClass() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);

        NotificationManager notificationManager = getNotificationManager(null);
        assertNotNull(notificationManager);
        notificationManager.shutdown();
    }

    @Test
    public void testNotificationManagerServiceNull() {
        NotificationServiceFactory testfact = () -> null;
        NotificationManager notificationManager = getNotificationManager(testfact);
        notificationManager.shutdown();
    }

    @Test
    public void testCreateNotificationsInvalidRecipient() {

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        Map<String, String> details = new HashMap<>();

        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        assertNull(notificationCommon.createNotification((String) null, details, converter, metricConverter));
        assertNull(notificationCommon.createNotification("", details, converter, metricConverter));
        assertNull(notificationCommon.createNotification("athenz", details, converter, metricConverter));

        // valid service name but we have no valid domain so we're still
        // going to get null notification

        assertNull(notificationCommon.createNotification("athenz.service", details, converter, metricConverter));
    }

    @Test
    public void testPrintNotificationDetailsToLog() {
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        assertNull(notificationCommon.printNotificationDetailsToLog(null, "descrition", LOGGER));
        assertNotNull(notificationCommon.printNotificationDetailsToLog(new ArrayList<>(), "descrition", LOGGER));
        List<Notification> notifications = new ArrayList<>();

        Map<String, String> details = new HashMap<>();
        details.put("test", "test");
        notifications.add(new Notification().setDetails(details));
        assertNotNull(notificationCommon.printNotificationDetailsToLog(notifications, "descrition", LOGGER));
    }
}
