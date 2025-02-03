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

package com.yahoo.athenz.common.notification.slack;

import com.yahoo.athenz.common.notification.slack.client.AthenzSlackClient;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationSlackMessage;
import com.yahoo.athenz.auth.PrivateKeyStore;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class SlackNotificationServiceTest {

    @Mock
    private AthenzSlackClient mockSlackClient;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        System.setProperty("athenz.user_domain", "user");
        System.setProperty("athenz.slack.max_retries", "3");
        System.setProperty("athenz.slack.rate_limit_delay_ms", "100");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty("athenz.user_domain");
        System.clearProperty("athenz.slack.max_retries");
        System.clearProperty("athenz.slack.rate_limit_delay_ms");
    }

    @Test
    public void testNotifyNull() {
        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        boolean status = svc.notify(null);
        assertFalse(status);
    }

    @Test
    public void testNotifyNoRecipients() {
        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);

        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage("blocks", Collections.emptySet());
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        boolean status = svc.notify(notification);
        assertFalse(status);
    }

    @Test
    public void testNotifyNullMessage() {
        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);

        Notification notification = mock(Notification.class);
        when(notification.getNotificationAsSlackMessage()).thenReturn(null);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        boolean status = svc.notify(notification);
        assertFalse(status);
    }

    @Test
    public void testNotifyEmptyMessage() {
        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);

        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = null;
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertFalse(status);
    }

    @Test
    public void testNotifySuccess() {
        Set<String> recipients = Collections.singleton("recipient");
        String message = "message-1";

        when(mockSlackClient.sendMessage(recipients, message)).thenReturn(true);

        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertTrue(status);
    }

    @Test
    public void testNotifyClientFailure() {
        Set<String> recipients = Collections.singleton("recipient");
        String message = "message-1";

        when(mockSlackClient.sendMessage(recipients, message)).thenReturn(false);

        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertFalse(status);
    }

    @Test
    public void testNotifyPrincipalConsolidation() {
        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        Notification notification = mock(Notification.class);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.PRINCIPAL);

        boolean status = svc.notify(notification);
        assertFalse(status);
    }

    @Test
    public void testNotifyWithMultipleRecipients() {
        Set<String> recipients = new HashSet<>();
        recipients.add("recipient1");
        recipients.add("recipient2");
        String message = "message-1";

        when(mockSlackClient.sendMessage(recipients, message)).thenReturn(true);

        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertTrue(status);
        verify(mockSlackClient, times(1)).sendMessage(recipients, message);
    }

    @Test
    public void testNotifyWithEmailRecipient() {
        Set<String> recipients = Collections.singleton("user@example.com");
        String message = "message-1";

        when(mockSlackClient.sendMessage(recipients, message)).thenReturn(true);

        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertTrue(status);
    }

    @Test
    public void testNotifyWithMixedRecipients() {
        Set<String> recipients = new HashSet<>();
        recipients.add("user@example.com");
        recipients.add("CHANNEL123");
        String message = "message-1";

        when(mockSlackClient.sendMessage(recipients, message)).thenReturn(true);

        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertTrue(status);
    }

    @Test
    public void testNotifyWithLongMessage() {
        Set<String> recipients = Collections.singleton("recipient");
        StringBuilder messageBuilder = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            messageBuilder.append("test message content ");
        }
        String message = messageBuilder.toString();

        when(mockSlackClient.sendMessage(recipients, message)).thenReturn(true);

        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertTrue(status);
    }

    @Test
    public void testNotifyWithSpecialCharacters() {
        Set<String> recipients = Collections.singleton("recipient");
        String message = "Special chars: !@#$%^&*()_+ \n\t";

        when(mockSlackClient.sendMessage(recipients, message)).thenReturn(true);

        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertTrue(status);
    }

    @Test
    public void testNotifyWithEmptyMessage() {
        Set<String> recipients = Collections.singleton("recipient");
        String message = "";

        when(mockSlackClient.sendMessage(recipients, message)).thenReturn(true);

        SlackNotificationService svc = new SlackNotificationService(mockSlackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertTrue(status);
    }
}