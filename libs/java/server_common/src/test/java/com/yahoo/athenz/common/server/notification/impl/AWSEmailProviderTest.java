package com.yahoo.athenz.common.server.notification.impl;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.model.SendEmailRequest;
import com.amazonaws.services.simpleemail.model.SendRawEmailRequest;
import com.amazonaws.services.simpleemail.model.SendRawEmailResult;
import com.yahoo.athenz.common.server.notification.Notification;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class AWSEmailProviderTest {
    @Test
    public void testSendEmail() {
        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        String subject = "test email subject";
        String body = "test email body";
        System.setProperty("athenz.notification_email_domain_from", "from.example.com");
        System.setProperty("athenz.notification_email_domain_to", "example.com");
        System.setProperty("athenz.notification_email_from", "no-reply-athenz");

        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        SendRawEmailResult result = mock(SendRawEmailResult.class);
        Mockito.when(ses.sendRawEmail(any(SendRawEmailRequest.class))).thenReturn(result);
        AWSEmailProvider awsEmailProvider = new AWSEmailProvider(ses);

        ArgumentCaptor<SendRawEmailRequest> captor = ArgumentCaptor.forClass(SendRawEmailRequest.class);

        EmailNotificationService svc = new EmailNotificationService(awsEmailProvider);

        svc.sendEmail(recipients, subject, body);

        Mockito.verify(ses, atLeastOnce()).sendRawEmail(captor.capture());

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
        System.clearProperty("athenz.notification_email_from");
    }

    @Test
    public void testSendEmailBatch() {
        Set<String> recipients = new HashSet<>();
        for (int i =0; i<60; i++) {
            recipients.add("user.user" + i);
        }
        String subject = "test email subject";
        String body = "test email body";
        System.setProperty("athenz.notification_email_domain_from", "example.com");
        System.setProperty("athenz.notification_email_domain_to", "example.com");
        System.setProperty("athenz.notification_email_from", "no-reply-athenz");

        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);

        SendRawEmailResult result = mock(SendRawEmailResult.class);
        Mockito.when(ses.sendRawEmail(any(SendRawEmailRequest.class))).thenReturn(result);
        ArgumentCaptor<SendRawEmailRequest> captor = ArgumentCaptor.forClass(SendRawEmailRequest.class);

        AWSEmailProvider emailProvider = new AWSEmailProvider(ses);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);

        boolean emailResult = svc.sendEmail(recipients, subject, body);

        assertTrue(emailResult);
        Mockito.verify(ses, times(2)).sendRawEmail(captor.capture());

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
        System.clearProperty("athenz.notification_email_from");
    }

    @Test
    public void testSendEmailError() {

        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        String subject = "test email subject";
        String body = "test email body";
        System.setProperty("athenz.notification_email_domain_to", "example.com");
        System.setProperty("athenz.notification_email_domain_from", "from.example.com");
        System.setProperty("athenz.notification_email_from", "no-reply-athenz");

        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        Mockito.when(ses.sendEmail(any(SendEmailRequest.class))).thenThrow(new RuntimeException());
        AWSEmailProvider awsEmailProvider = new AWSEmailProvider(ses);

        EmailNotificationService svc = new EmailNotificationService(awsEmailProvider);

        boolean result = svc.sendEmail(recipients, subject, body);
        assertFalse(result);

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
        System.clearProperty("athenz.notification_email_from");
    }

    @Test
    public void testNotify() {

        System.setProperty("athenz.notification_email_domain_from", "example.com");
        System.setProperty("athenz.notification_email_domain_to", "example.com");
        System.setProperty("athenz.notification_email_from", "no-reply-athenz");

        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        SendRawEmailResult result = mock(SendRawEmailResult.class);
        Mockito.when(ses.sendRawEmail(any(SendRawEmailRequest.class))).thenReturn(result);
        AWSEmailProvider awsEmailProvider = new AWSEmailProvider(ses);
        EmailNotificationService svc = new EmailNotificationService(awsEmailProvider);

        Notification notification = new Notification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL);
        notification.addRecipient("user.user1").addRecipient("user.user2");
        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        notification.setDetails(details);

        boolean status = svc.notify(notification);
        assertTrue(status);

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
        System.clearProperty("athenz.notification_email_from");
    }
}
