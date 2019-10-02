package com.yahoo.athenz.common.server.notification.impl;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;

import com.amazonaws.services.simpleemail.model.*;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationService;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class EmailNotificationServiceTest {

    @BeforeMethod
    public void setUp() {
        System.setProperty("athenz.user_domain", "user");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty("athenz.user_domain");
    }

    @Test
    public void testGetBody() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        EmailNotificationService svc = new EmailNotificationService();
        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requestor", "user.requestor");
        String body = svc.getBody("MEMBERSHIP_APPROVAL", details);

        assertNotNull(body);
        assertTrue(body.contains("dom1"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("user.member1"));
        assertTrue(body.contains("test reason"));
        assertTrue(body.contains("user.requestor"));
        assertTrue(body.contains("https://athenz.example.com/workflow"));

        body = svc.getBody("MEMBERSHIP_APPROVAL_REMINDER", null);
        assertNotNull(body);
        assertTrue(body.contains("https://athenz.example.com/workflow"));

        body = svc.getBody("INVALID", null);
        assertEquals(body, "");

        System.clearProperty("athenz.notification_workflow_url");
    }

    @Test
    public void testGetSubject() {
        EmailNotificationService svc = new EmailNotificationService();
        String sub = svc.getSubject("MEMBERSHIP_APPROVAL");
        assertNotNull(sub);

        sub = svc.getSubject("MEMBERSHIP_APPROVAL_REMINDER");
        assertNotNull(sub);

        sub = svc.getSubject("INVALID");
        assertEquals(sub, "");
    }

    @Test
    public void testGetFullyQualifiedEmailAddresses() {
        System.clearProperty("athenz.user_domain");
        System.setProperty("athenz.user_domain", "entuser");
        System.setProperty("athenz.notification_email_domain", "example.com");
        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        EmailNotificationService svc = new EmailNotificationService(ses);

        Set<String> recipients = new HashSet<>(Arrays.asList("entuser.user1", "entuser.user2", "entuser.user3"));
        Set<String> recipientsResp = svc.getFullyQualifiedEmailAddresses(recipients);
        assertNotNull(recipientsResp);

        assertEquals(recipientsResp.size(), 3);
        assertTrue(recipientsResp.contains("user1@example.com"));
        assertTrue(recipientsResp.contains("user2@example.com"));
        assertTrue(recipientsResp.contains("user3@example.com"));

        System.clearProperty("athenz.notification_email_domain");

    }

    @Test
    public void testGetFullyQualifiedEmailAddressesDefaultUserDomain() {
        System.setProperty("athenz.notification_email_domain", "test.com");
        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        EmailNotificationService svc = new EmailNotificationService(ses);

        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        Set<String> recipientsResp = svc.getFullyQualifiedEmailAddresses(recipients);
        assertNotNull(recipientsResp);

        assertEquals(recipientsResp.size(), 3);
        assertTrue(recipientsResp.contains("user1@test.com"));
        assertTrue(recipientsResp.contains("user2@test.com"));
        assertTrue(recipientsResp.contains("user3@test.com"));

        System.clearProperty("athenz.notification_email_domain");
    }

    @Test
    public void testSendEmail() {

        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        String subject = "test email subject";
        String body = "test email body";
        System.setProperty("athenz.notification_email_domain", "example.com");
        System.setProperty("athenz.notification_email_from", "no-reply-athenz");

        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        SendEmailResult result = mock(SendEmailResult.class);
        Mockito.when(ses.sendEmail(any(SendEmailRequest.class))).thenReturn(result);

        ArgumentCaptor<SendEmailRequest> captor = ArgumentCaptor.forClass(SendEmailRequest.class);

        EmailNotificationService svc = new EmailNotificationService(ses);

        svc.sendEmail(recipients, subject, body);

        Mockito.verify(ses, atLeastOnce()).sendEmail(captor.capture());
        SendEmailRequest sesReqRes = captor.getValue();

        SendEmailRequest expectedSESReq = new SendEmailRequest()
                .withDestination(new Destination().withBccAddresses(recipients))
                .withMessage(new Message()
                        .withBody(new Body()
                                .withHtml(new Content()
                                        .withCharset("UTF-8").withData(body)))
                        .withSubject(new Content()
                                .withCharset("UTF-8").withData(subject)))
                .withSource("no-reply-athenz@example.com");

        assertEquals(sesReqRes, expectedSESReq);

        System.clearProperty("athenz.notification_email_domain");
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
        System.setProperty("athenz.notification_email_domain", "example.com");
        System.setProperty("athenz.notification_email_from", "no-reply-athenz");

        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        SendEmailResult result = mock(SendEmailResult.class);
        Mockito.when(ses.sendEmail(any(SendEmailRequest.class))).thenReturn(result);
        ArgumentCaptor<SendEmailRequest> captor = ArgumentCaptor.forClass(SendEmailRequest.class);

        EmailNotificationService svc = new EmailNotificationService(ses);
        boolean emailResult = svc.sendEmail(recipients, subject, body);

        assertTrue(emailResult);
        Mockito.verify(ses, times(2)).sendEmail(captor.capture());
        List<SendEmailRequest> sesReqExpectedList = captor.getAllValues();

        assertEquals(sesReqExpectedList.get(0).getDestination().getBccAddresses().size(), 50);
        assertEquals(sesReqExpectedList.get(1).getDestination().getBccAddresses().size(), 10);

        System.clearProperty("athenz.notification_email_domain");
        System.clearProperty("athenz.notification_email_from");
    }


    @Test
    public void testSendEmailError() {

        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        String subject = "test email subject";
        String body = "test email body";
        System.setProperty("athenz.notification_email_domain", "example.com");
        System.setProperty("athenz.notification_email_from", "no-reply-athenz");

        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        Mockito.when(ses.sendEmail(any(SendEmailRequest.class))).thenThrow(new RuntimeException());

        EmailNotificationService svc = new EmailNotificationService(ses);

        boolean result = svc.sendEmail(recipients, subject, body);
        assertFalse(result);

        System.clearProperty("athenz.notification_email_domain");
        System.clearProperty("athenz.notification_email_from");
    }

    @Test
    public void testNotify() {

        System.setProperty("athenz.notification_email_domain", "example.com");
        System.setProperty("athenz.notification_email_from", "no-reply-athenz");

        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        SendEmailResult result = mock(SendEmailResult.class);
        Mockito.when(ses.sendEmail(any(SendEmailRequest.class))).thenReturn(result);

        EmailNotificationService svc = new EmailNotificationService(ses);

        Notification notification = new Notification(NotificationService.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL);
        notification.addRecipient("user.user1").addRecipient("user.user2");
        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requestor", "user.requestor");
        notification.setDetails(details);

        boolean status = svc.notify(notification);

        assertTrue(status);

        System.clearProperty("athenz.notification_email_domain");
        System.clearProperty("athenz.notification_email_from");
    }

    @Test
    public void testNotifyNull() {
        AmazonSimpleEmailService ses = mock(AmazonSimpleEmailService.class);
        EmailNotificationService svc = new EmailNotificationService(ses);
        boolean status = svc.notify(null);
        assertFalse(status);

    }
}