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

package com.yahoo.athenz.common.server.notification.impl;

import com.yahoo.athenz.common.server.notification.EmailProvider;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static org.mockito.Mockito.mock;
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
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);
        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("role", "role1");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");
        String body = svc.getBody("MEMBERSHIP_APPROVAL", details);

        assertNotNull(body);
        assertTrue(body.contains("dom1"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("user.member1"));
        assertTrue(body.contains("test reason"));
        assertTrue(body.contains("user.requester"));
        assertTrue(body.contains("https://athenz.example.com/workflow"));

        body = svc.getBody("MEMBERSHIP_APPROVAL_REMINDER", null);
        assertNotNull(body);
        assertTrue(body.contains("https://athenz.example.com/workflow"));

        // first let's try with no details

        body = svc.getBody("DOMAIN_MEMBER_EXPIRY_REMINDER", details);
        assertNotNull(body);
        assertFalse(body.contains("user.member1"));

        // now set the correct expiry members details
        // with one bad entry that should be skipped

        details.put(NOTIFICATION_DETAILS_EXPIRY_MEMBERS,
                "user.joe;role1;2020-12-01T12:00:00.000Z|user.jane;role1;2020-12-01T12:00:00.000Z|user.bad;role3");
        body = svc.getBody("DOMAIN_MEMBER_EXPIRY_REMINDER", details);
        assertNotNull(body);
        assertTrue(body.contains("user.joe"));
        assertTrue(body.contains("user.jane"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("2020-12-01T12:00:00.000Z"));

        // make sure the bad entries are not included

        assertFalse(body.contains("user.bad"));
        assertFalse(body.contains("role3"));

        // now try the expiry roles reminder

        details.put(NOTIFICATION_DETAILS_EXPIRY_ROLES,
                "athenz1;role1;2020-12-01T12:00:00.000Z|athenz2;role2;2020-12-01T12:00:00.000Z");
        body = svc.getBody("PRINCIPAL_EXPIRY_REMINDER", details);
        assertNotNull(body);
        assertTrue(body.contains("athenz1"));
        assertTrue(body.contains("athenz2"));
        assertTrue(body.contains("role1"));
        assertTrue(body.contains("role2"));
        assertTrue(body.contains("2020-12-01T12:00:00.000Z"));

        // now try the unrefreshed certs notification

        details.put(NOTIFICATION_DETAILS_UNREFRESHED_CERTS,
                "domain0.service0;provider;instanceID0;Sun Mar 15 15:08:07 IST 2020;;hostName0|" +
                 "domain.bad;instanceID0;Sun Mar 15 15:08:07 IST 2020;;hostBad|" + // bad entry with missing provider
                 "domain0.service0;provider;instanceID0;Sun Mar 15 15:08:07 IST 2020;;secondHostName0");
        body = svc.getBody("UNREFRESHED_CERTS", details);
        assertNotNull(body);
        assertTrue(body.contains("domain0.service0"));
        assertTrue(body.contains("hostName0"));
        assertTrue(body.contains("secondHostName0"));
        assertTrue(body.contains("instanceID0"));
        assertTrue(body.contains("Sun Mar 15 15:08:07 IST 2020"));

        // make sure the bad entries are not included
        assertFalse(body.contains("domain.bad"));
        assertFalse(body.contains("hostBad"));

        System.clearProperty("athenz.notification_workflow_url");
    }

    @Test
    public void testGetSubject() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);
        String sub = svc.getSubject("MEMBERSHIP_APPROVAL");
        assertNotNull(sub);
        assertFalse(sub.isEmpty());

        sub = svc.getSubject("MEMBERSHIP_APPROVAL_REMINDER");
        assertNotNull(sub);
        assertFalse(sub.isEmpty());

        sub = svc.getSubject("PRINCIPAL_EXPIRY_REMINDER");
        assertNotNull(sub);
        assertFalse(sub.isEmpty());

        sub = svc.getSubject("DOMAIN_MEMBER_EXPIRY_REMINDER");
        assertNotNull(sub);
        assertFalse(sub.isEmpty());

        sub = svc.getSubject("UNREFRESHED_CERTS");
        assertNotNull(sub);
        assertFalse(sub.isEmpty());

        sub = svc.getSubject("INVALID");
        assertNotNull(sub);
        assertTrue(sub.isEmpty());
    }

    @Test
    public void testGetFullyQualifiedEmailAddresses() {
        System.clearProperty("athenz.user_domain");
        System.setProperty("athenz.user_domain", "entuser");
        System.setProperty("athenz.notification_email_domain_from", "from.example.com");
        System.setProperty("athenz.notification_email_domain_to", "example.com");
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);

        Set<String> recipients = new HashSet<>(Arrays.asList("entuser.user1", "entuser.user2", "entuser.user3"));
        Set<String> recipientsResp = svc.getFullyQualifiedEmailAddresses(recipients);
        assertNotNull(recipientsResp);

        assertEquals(recipientsResp.size(), 3);
        assertTrue(recipientsResp.contains("user1@example.com"));
        assertTrue(recipientsResp.contains("user2@example.com"));
        assertTrue(recipientsResp.contains("user3@example.com"));

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
    }

    @Test
    public void testGetFullyQualifiedEmailAddressesDefaultUserDomain() {
        System.setProperty("athenz.notification_email_domain_from", "from.test.com");
        System.setProperty("athenz.notification_email_domain_to", "test.com");
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);

        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        Set<String> recipientsResp = svc.getFullyQualifiedEmailAddresses(recipients);
        assertNotNull(recipientsResp);

        assertEquals(recipientsResp.size(), 3);
        assertTrue(recipientsResp.contains("user1@test.com"));
        assertTrue(recipientsResp.contains("user2@test.com"));
        assertTrue(recipientsResp.contains("user3@test.com"));

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
    }

    @Test
    public void testNotifyNull() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);
        boolean status = svc.notify(null);
        assertFalse(status);
    }

    @Test
    public void testReadContentFromFile() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);
        assertTrue(svc.readContentFromFile("resources/non-existent").isEmpty());
    }

    @Test
    public void testReadContentFromFileNull() throws Exception {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);
        BufferedReader reader = mock(BufferedReader.class);
        Mockito.when(reader.readLine()).thenReturn(null);
        assertTrue(svc.readContentFromFile("resources/dummy").isEmpty());
    }

    @Test
    public void testReadContentFromFileException() throws Exception {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);
        BufferedReader reader = mock(BufferedReader.class);
        Mockito.when(reader.readLine()).thenThrow(new IOException());
        assertTrue(svc.readContentFromFile("resources/dummy").isEmpty());
    }

    @Test
    public void testReadBinaryFromFile() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);
        assertNotNull(svc.readBinaryFromFile("emails/athenz-logo-white.png"));
    }

    @Test
    public void testReadBinaryFromFileNull() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);
        assertNull(svc.readBinaryFromFile("resources/non-existent"));
    }

}