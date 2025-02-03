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

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.db.DomainProvider;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.zms.Domain;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_PROP_SERVICE_FACTORY_CLASS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.*;

public class NotificationManagerTest {

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
    public void testSendNotification() throws ServerResourceException {
        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        notification.setRecipients(recipients);

        NotificationManager notificationManager = getNotificationManager(null);
        assertFalse(notificationManager.isNotificationFeatureAvailable());

        notificationManager.shutdown();
        notificationManager.sendNotifications(Collections.singletonList(notification));

        NotificationService service1 = Mockito.mock(NotificationService.class);
        NotificationServiceFactory factory1 = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(factory1.create(any())).thenReturn(service1);

        NotificationService service2 = Mockito.mock(NotificationService.class);
        NotificationServiceFactory factory2 = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(factory2.create(any())).thenReturn(service2);

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
            return new NotificationManager(notificationTasks, null, null, null);
        }
        return new NotificationManager(notificationServiceFactories, notificationTasks, null, null);
    }

    @Test
    public void testNotificationManagerCtor() {
        NotificationTask notificationTask1 = Mockito.mock(NotificationTask.class);
        NotificationTask notificationTask2 = Mockito.mock(NotificationTask.class);
        List<NotificationTask> notificationTasks = new ArrayList<>();
        notificationTasks.add(notificationTask1);
        notificationTasks.add(notificationTask2);

        // Notification factory classes
        String metricNotificationFactory = "com.yahoo.athenz.common.server.notification.impl.MetricNotificationServiceFactory";

        // Notification service classes
        String metricNotificationService = "com.yahoo.athenz.common.server.notification.impl.MetricNotificationService";

        // Test with a single factory
        System.setProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS, metricNotificationFactory);
        NotificationManager notificationManager = new NotificationManager(notificationTasks, null, null, null);
        assertEquals(notificationManager.getLoadedNotificationServices().size(), 1);
        assertEquals(notificationManager.getLoadedNotificationServices().get(0), metricNotificationService);
        assertTrue(notificationManager.isNotificationFeatureAvailable());

        // Test with no factories
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        notificationManager = new NotificationManager(notificationTasks, null, null, null);
        assertEquals(notificationManager.getLoadedNotificationServices().size(), 0);
        assertFalse(notificationManager.isNotificationFeatureAvailable());
    }

    @Test
    public void testSendNotificationNullService() throws ServerResourceException {

        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(null);
        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
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
        DomainProvider domainProvider = Mockito.mock(DomainProvider.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        DomainMetaFetcher domainMetaFetcher = new DomainMetaFetcher(domainProvider);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX, domainMetaFetcher);

        Set<String> recipients = new HashSet<>();
        recipients.add("user.recipient1");
        recipients.add("user.recipient2");

        Map<String, String> details = new HashMap<>();
        details.put("key1", "value1");
        details.put("key2", "value2");

        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        NotificationToSlackMessageConverter slackMessageConverter = Mockito.mock(NotificationToSlackMessageConverter.class);
        Notification notification = notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.PRINCIPAL,
                recipients, details, converter, metricConverter, slackMessageConverter);
        assertNotNull(notification);

        assertTrue(notification.getRecipients().contains("user.recipient1"));
        assertTrue(notification.getRecipients().contains("user.recipient2"));
        assertEquals(notification.getDetails().size(), 2);
        assertEquals(notification.getDetails().get("key1"), "value1");
        assertEquals(notification.getDetails().get("key2"), "value2");

        notification = notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.DOMAIN,
                recipients, details, converter, metricConverter, slackMessageConverter);
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
        Mockito.when(rolesProvider.getRolesByDomain(any())).thenThrow(new IllegalArgumentException("invalid request"));
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        String recipient = "test.domain:group.testgroup";

        Map<String, String> details = new HashMap<>();
        details.put("key1", "value1");
        details.put("key2", "value2");

        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        Notification notification = notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY,
                recipient, details, converter, metricConverter);
        Mockito.verify(rolesProvider, Mockito.times(0)).getRolesByDomain(any());
        assertNull(notification);
    }

    @Test
    public void testCreateNotificationException() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        Mockito.when(rolesProvider.getRolesByDomain(any())).thenThrow(new IllegalArgumentException("invalid request"));
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        String recipient = "test.domain:role.admin";

        Map<String, String> details = new HashMap<>();
        details.put("key1", "value1");
        details.put("key2", "value2");

        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        NotificationToSlackMessageConverter slackMessageConverter = Mockito.mock(NotificationToSlackMessageConverter.class);

        Notification notification = notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.PRINCIPAL,
                recipient, details, converter, metricConverter, slackMessageConverter);
        Mockito.verify(rolesProvider, Mockito.times(1)).getRole("test.domain", "admin", false, true, false);
        assertNull(notification);
    }

    @Test
    public void testCreateNotificationByDomainException() {
        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainProvider domainProvider = Mockito.mock(DomainProvider.class);
        Mockito.when(domainProvider.getDomain("test.domain", false)).thenThrow(new IllegalArgumentException("invalid request"));
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        DomainMetaFetcher domainMetaFetcher = new DomainMetaFetcher(domainProvider);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX, domainMetaFetcher);

        String recipient = "test.domain";

        Map<String, String> details = new HashMap<>();
        details.put("key1", "value1");
        details.put("key2", "value2");

        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        NotificationToSlackMessageConverter slackMessageConverter = Mockito.mock(NotificationToSlackMessageConverter.class);

        Notification notification = notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.DOMAIN,
                recipient, details, converter, metricConverter, slackMessageConverter);
        Mockito.verify(domainProvider, Mockito.times(1)).getDomain("test.domain", false);
        assertNull(notification);
    }

    @Test
    public void testCreaeteNotificationNullRecipients() {
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        assertNull(notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY,
                (Set<String>) null, null, null, null));
        assertNull(notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY,
                Collections.emptySet(), null, null, null));
        assertNull(notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.DOMAIN,
                Collections.emptySet(), null, null, null, null));
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
        Notification notification = notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY,
                recipients, null, converter, metricConverter);
        assertNull(notification);
    }

    @Test
    public void testCreateNotificationByDomainValidRecipients() {
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        recipients.add("testdom");

        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainProvider domainProvider = Mockito.mock(DomainProvider.class);

        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        DomainMetaFetcher domainMetaFetcher = new DomainMetaFetcher(domainProvider);

        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX, domainMetaFetcher);
        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        NotificationToSlackMessageConverter slackMessageConverter = Mockito.mock(NotificationToSlackMessageConverter.class);

        Notification notification = notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.DOMAIN,
                recipients, null, converter, metricConverter, slackMessageConverter);
        assertNotNull(notification);
        assertEquals(notification.getRecipients(), Set.of("user.joe"));
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
    public void testNotificationManagerServiceNull() throws ServerResourceException {

        NotificationServiceFactory testfact = Mockito.mock(NotificationServiceFactory.class);
        Mockito.when(testfact.create(any())).thenReturn(null);
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
        NotificationToSlackMessageConverter slackMessageConverter = Mockito.mock(NotificationToSlackMessageConverter.class);

        assertNull(notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.PRINCIPAL,
                (String) null, details, converter, metricConverter, slackMessageConverter));
        assertNull(notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.PRINCIPAL,
                "", details, converter, metricConverter, slackMessageConverter));
        assertNull(notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.PRINCIPAL,
                "athenz", details, converter, metricConverter, slackMessageConverter));

        // valid service name but we have no valid domain so we're still
        // going to get null notification

        assertNull(notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.PRINCIPAL,
                "athenz.service", details, converter, metricConverter, slackMessageConverter));
    }

    @Test
    public void testPrintNotificationDetailsToLog() {
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX);
        assertNull(notificationCommon.printNotificationDetailsToLog(null, "description"));
        assertNotNull(notificationCommon.printNotificationDetailsToLog(new ArrayList<>(), "description"));
        List<Notification> notifications = new ArrayList<>();

        Map<String, String> details = new HashMap<>();
        details.put("test", "test");
        notifications.add(new Notification(Notification.Type.ROLE_MEMBER_EXPIRY).setDetails(details));
        assertNotNull(notificationCommon.printNotificationDetailsToLog(notifications, "description"));
    }

    @Test
    public void testCreateNotificationByDomainValidMeta() {
        Set<String> recipients = new HashSet<>();
        recipients.add("user.joe");
        recipients.add("testdom");

        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        DomainProvider domainProvider = Mockito.mock(DomainProvider.class);
        DomainMetaFetcher domainMetaFetcher = new DomainMetaFetcher(domainProvider);

        Domain domain = new Domain().setName("testdom").setSlackChannel("channel-1");
        Mockito.when(domainProvider.getDomain("testdom", false)).thenReturn(domain);

        NotificationCommon notificationCommon = new NotificationCommon(domainRoleMembersFetcher, USER_DOMAIN_PREFIX, domainMetaFetcher);
        NotificationToEmailConverter converter = Mockito.mock(NotificationToEmailConverter.class);
        NotificationToMetricConverter metricConverter = Mockito.mock(NotificationToMetricConverter.class);
        NotificationToSlackMessageConverter slackMessageConverter = Mockito.mock(NotificationToSlackMessageConverter.class);

        Notification notification = notificationCommon.createNotification(Notification.Type.ROLE_MEMBER_EXPIRY, Notification.ConsolidatedBy.DOMAIN,
                recipients, null, converter, metricConverter, slackMessageConverter);
        assertNotNull(notification);
        assertEquals(notification.getRecipients(), Set.of("user.joe", "testdom"));
        assertEquals(notification.getNotificationDomainMeta().size(), 1);
        assertNotNull(notification.getNotificationDomainMeta().get("testdom"));
        assertEquals(notification.getNotificationDomainMeta().get("testdom").getSlackChannel(), "channel-1");
    }
}
