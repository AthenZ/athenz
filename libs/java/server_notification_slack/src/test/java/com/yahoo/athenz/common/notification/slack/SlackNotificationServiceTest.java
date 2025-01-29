package com.yahoo.athenz.common.notification.slack;

import com.yahoo.athenz.common.notification.slack.client.AthenzSlackClient;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationSlackMessage;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class SlackNotificationServiceTest {

    @BeforeMethod
    public void setUp() {
        System.setProperty("athenz.user_domain", "user");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty("athenz.user_domain");
    }

    @Test
    public void testNotifyNull() {
        AthenzSlackClient slackClient = mock(AthenzSlackClient.class);
        SlackNotificationService svc = new SlackNotificationService(slackClient);
        boolean status = svc.notify(null);
        assertFalse(status);
    }


    @Test
    public void testNotifyNoRecipients() {
        AthenzSlackClient slackClient = mock(AthenzSlackClient.class);
        SlackNotificationService svc = new SlackNotificationService(slackClient);

        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage("blocks", Collections.emptySet());
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertFalse(status);
    }

    @Test
    public void testNotifyEmptyMessage() {
        AthenzSlackClient slackClient = mock(AthenzSlackClient.class);
        SlackNotificationService svc = new SlackNotificationService(slackClient);

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

        AthenzSlackClient slackClient = mock(AthenzSlackClient.class);
        when(slackClient.sendMessage(recipients, message)).thenReturn(true);

        SlackNotificationService svc = new SlackNotificationService(slackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertTrue(status);
    }

    @Test
    public void testNotifyClientFailure() {
        Set<String> recipients = Collections.singleton("recipient");
        String message = "message-1";

        AthenzSlackClient slackClient = mock(AthenzSlackClient.class);
        when(slackClient.sendMessage(recipients, message)).thenReturn(false);

        SlackNotificationService svc = new SlackNotificationService(slackClient);
        Notification notification = mock(Notification.class);
        NotificationSlackMessage notificationAsSlack = new NotificationSlackMessage(message, recipients);
        when(notification.getNotificationAsSlackMessage()).thenReturn(notificationAsSlack);

        boolean status = svc.notify(notification);
        assertFalse(status);
    }
}
