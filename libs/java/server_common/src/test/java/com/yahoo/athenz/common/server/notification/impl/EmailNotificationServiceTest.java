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

package com.yahoo.athenz.common.server.notification.impl;

import com.yahoo.athenz.common.server.notification.EmailProvider;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationEmail;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
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
    public void testNotifyNull() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);
        boolean status = svc.notify(null);
        assertFalse(status);
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

    @Test
    public void testNotifyNoRecipients() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);

        Notification notification = mock(Notification.class);
        NotificationEmail notificationAsEmail = new NotificationEmail("subject", "body", Collections.emptySet());
        when(notification.getNotificationAsEmail()).thenReturn(notificationAsEmail);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.PRINCIPAL);

        boolean status = svc.notify(notification);
        assertFalse(status);
    }

    @Test
    public void testNotifyConsolidatedByDomain() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailNotificationService svc = new EmailNotificationService(emailProvider);

        Notification notification = mock(Notification.class);
        NotificationEmail notificationAsEmail = new NotificationEmail("subject", "body", Set.of("user@test.dom"));
        when(notification.getNotificationAsEmail()).thenReturn(notificationAsEmail);
        when(notification.getConsolidatedBy()).thenReturn(Notification.ConsolidatedBy.DOMAIN);

        boolean status = svc.notify(notification);
        assertTrue(status);
    }
}