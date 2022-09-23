/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.notification;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.common.server.debug.DebugUserAuthority;
import com.yahoo.athenz.common.server.notification.impl.NotificationAuthorityForTest;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.*;
import static org.testng.Assert.assertTrue;

public class NotificationToEmailConverterCommonTest {

    @Test
    public void testGetFullyQualifiedEmailAddresses() {
        System.clearProperty("athenz.user_domain");
        System.setProperty("athenz.user_domain", "entuser");
        System.setProperty("athenz.notification_email_domain_from", "from.example.com");
        System.setProperty("athenz.notification_email_domain_to", "example.com");

        Set<String> recipients = new HashSet<>(Arrays.asList("entuser.user1", "entuser.user2", "entuser.user3"));

        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);
        Set<String> recipientsResp = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(recipients);
        assertNotNull(recipientsResp);

        assertEquals(recipientsResp.size(), 3);
        assertTrue(recipientsResp.contains("user1@example.com"));
        assertTrue(recipientsResp.contains("user2@example.com"));
        assertTrue(recipientsResp.contains("user3@example.com"));

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
        System.clearProperty("athenz.user_domain");
    }

    @Test
    public void testGetFullyQualifiedEmailAddressesUserAuthority() {
        System.clearProperty("athenz.user_domain");
        System.setProperty("athenz.user_domain", "entuser");
        System.setProperty("athenz.notification_email_domain_from", "from.example.com");
        System.setProperty("athenz.notification_email_domain_to", "example.com");

        Set<String> recipients = new HashSet<>(Arrays.asList("entuser.user1", "entuser.user2", "entuser.user3", "unknown.user"));

        Authority notificationAuthorityForTest = new NotificationAuthorityForTest();
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(notificationAuthorityForTest);
        Set<String> recipientsResp = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(recipients);
        assertNotNull(recipientsResp);

        assertEquals(recipientsResp.size(), 4);
        assertTrue(recipientsResp.contains("entuser.user1@mail.from.authority.com"));
        assertTrue(recipientsResp.contains("entuser.user2@mail.from.authority.com"));
        assertTrue(recipientsResp.contains("entuser.user3@mail.from.authority.com"));
        assertTrue(recipientsResp.contains("unknown.user@example.com"));

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
        System.clearProperty("athenz.user_domain");
    }

    @Test
    public void testGetFullyQualifiedEmailAddressesUserAuthorityProp() {
        System.clearProperty("athenz.user_domain");
        System.setProperty("athenz.user_domain", "entuser");
        System.setProperty("athenz.notification_email_domain_from", "from.example.com");
        System.setProperty("athenz.notification_email_domain_to", "example.com");
        System.setProperty("athenz.notification_user_authority", "com.yahoo.athenz.common.server.notification.impl.NotificationAuthorityForTest");

        Set<String> recipients = new HashSet<>(Arrays.asList("entuser.user1", "entuser.user2", "entuser.user3", "unknown.user"));

        // Verify when athenz.notification_user_authority is set it will take precedence over passed authority
        DebugUserAuthority debugUserAuthority = new DebugUserAuthority();
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(debugUserAuthority);
        Set<String> recipientsResp = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(recipients);
        assertNotNull(recipientsResp);

        assertEquals(recipientsResp.size(), 4);
        assertTrue(recipientsResp.contains("entuser.user1@mail.from.authority.com"));
        assertTrue(recipientsResp.contains("entuser.user2@mail.from.authority.com"));
        assertTrue(recipientsResp.contains("entuser.user3@mail.from.authority.com"));
        assertTrue(recipientsResp.contains("unknown.user@example.com"));

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
        System.clearProperty("athenz.user_domain");
        System.clearProperty("athenz.notification_user_authority");
    }

    @Test
    public void testGetFullyQualifiedEmailAddressesDefaultUserDomain() {
        System.setProperty("athenz.notification_email_domain_from", "from.test.com");
        System.setProperty("athenz.notification_email_domain_to", "test.com");

        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);
        Set<String> recipientsResp = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(recipients);
        assertNotNull(recipientsResp);

        assertEquals(recipientsResp.size(), 3);
        assertTrue(recipientsResp.contains("user1@test.com"));
        assertTrue(recipientsResp.contains("user2@test.com"));
        assertTrue(recipientsResp.contains("user3@test.com"));

        System.clearProperty("athenz.notification_email_domain_from");
        System.clearProperty("athenz.notification_email_domain_to");
    }

    @Test
    public void testReadContentFromFile() {
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);
        assertTrue(notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), "resources/non-existent").isEmpty());
    }

    @Test
    public void testReadContentFromFileNull() throws Exception {
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

        BufferedReader reader = mock(BufferedReader.class);
        Mockito.when(reader.readLine()).thenReturn(null);
        assertTrue(notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), "resources/dummy").isEmpty());
    }

    @Test
    public void testReadContentFromFileException() throws Exception {
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

        BufferedReader reader = mock(BufferedReader.class);
        Mockito.when(reader.readLine()).thenThrow(new IOException());
        assertTrue(notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), "resources/dummy").isEmpty());
    }

    @Test
    public void testgettTbleEntryTemplate() {
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);
        int numOfColumns = 1;
        String tableEntryTemplate = notificationToEmailConverterCommon.getTableEntryTemplate(numOfColumns);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td></tr>");

        numOfColumns = 3;
        tableEntryTemplate = notificationToEmailConverterCommon.getTableEntryTemplate(numOfColumns);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td></tr>");

        numOfColumns = 6;
        tableEntryTemplate = notificationToEmailConverterCommon.getTableEntryTemplate(numOfColumns);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td><td class=\"cv\">{3}</td><td class=\"cv\">{4}</td><td class=\"cv\">{5}</td></tr>");
    }
}
