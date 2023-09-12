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
import java.net.URL;
import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_DETAILS_MEMBER;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_DETAILS_ROLES_LIST;
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
        NotificationToEmailConverterCommon notificationToEmailConverterCommon =
                new NotificationToEmailConverterCommon(notificationAuthorityForTest);
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
        NotificationToEmailConverterCommon notificationToEmailConverterCommon =
                new NotificationToEmailConverterCommon(debugUserAuthority);
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
        assertTrue(notificationToEmailConverterCommon.readContentFromFile(
                getClass().getClassLoader(), "resources/non-existent").isEmpty());
    }

    @Test
    public void testReadContentFromFileNull() throws Exception {
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

        BufferedReader reader = mock(BufferedReader.class);
        Mockito.when(reader.readLine()).thenReturn(null);
        assertTrue(notificationToEmailConverterCommon.readContentFromFile(
                getClass().getClassLoader(), "resources/dummy").isEmpty());
    }

    @Test
    public void testReadContentFromFileException() throws Exception {
        NotificationToEmailConverterCommon notificationToEmailConverterCommon =
                new NotificationToEmailConverterCommon(null);

        BufferedReader reader = mock(BufferedReader.class);
        Mockito.when(reader.readLine()).thenThrow(new IOException());
        assertTrue(notificationToEmailConverterCommon.readContentFromFile(
                getClass().getClassLoader(), "resources/dummy").isEmpty());
    }

    @Test
    public void testgettTbleEntryTemplate() {
        NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);
        int numOfColumns = 1;
        String tableEntryTemplate = notificationToEmailConverterCommon.getTableEntryTemplate(numOfColumns, null);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td></tr>");

        numOfColumns = 3;
        tableEntryTemplate = notificationToEmailConverterCommon.getTableEntryTemplate(numOfColumns, null);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td></tr>");

        numOfColumns = 6;
        tableEntryTemplate = notificationToEmailConverterCommon.getTableEntryTemplate(numOfColumns, null);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td><td class=\"cv\">{3}</td><td class=\"cv\">{4}</td><td class=\"cv\">{5}</td></tr>");
    }

    @Test
    public void testgettTbleEntryTemplateColumnNames() {

        System.clearProperty("athenz.notification_athenz_ui_url");
        NotificationToEmailConverterCommon converter = new NotificationToEmailConverterCommon(null);
        int numOfColumns = 3;
        String[] columnNames = { "DOMAIN", "ROLE", "GROUP" };

        // with no url, there are no changes
        String tableEntryTemplate = converter.getTableEntryTemplate(numOfColumns, columnNames);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td></tr>");

        // similarly, with empty url, there are no changes either

        System.setProperty("athenz.notification_athenz_ui_url", "");
        converter = new NotificationToEmailConverterCommon(null);
        tableEntryTemplate = converter.getTableEntryTemplate(numOfColumns, columnNames);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td></tr>");

        // we're going to set the url but no domain in the column names

        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");
        converter = new NotificationToEmailConverterCommon(null);
        columnNames = new String[]{ "ROLE", "GROUP" };

        tableEntryTemplate = converter.getTableEntryTemplate(numOfColumns, columnNames);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td></tr>");

        // now we're setting both column names and role group values

        numOfColumns = 4;
        columnNames = new String[]{ "DOMAIN", "ROLE", "GROUP", "EXPIRATION" };
        tableEntryTemplate = converter.getTableEntryTemplate(numOfColumns, columnNames);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\"><a href=\"{4}/domain/{0}/role\">{0}</a></td>" +
                "<td class=\"cv\"><a href=\"{4}/domain/{0}/role/{1}/members\">{1}</a></td>" +
                "<td class=\"cv\"><a href=\"{4}/domain/{0}/group/{2}/members\">{2}</a></td>" +
                "<td class=\"cv\">{3}</td></tr>");

        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void testGetTableColumnIndex() {

        NotificationToEmailConverterCommon converter = new NotificationToEmailConverterCommon(null);
        assertNull(converter.getTableColumnName(3, 4, null));
        assertNull(converter.getTableColumnName(3, 4, new String[]{"DOMAIN"}));
        assertNull(converter.getTableColumnName(2, 1, new String[]{"DOMAIN"}));
        assertNull(converter.getTableColumnName(1, 1, new String[]{"DOMAIN"}));
        assertEquals("DOMAIN", converter.getTableColumnName(0, 1, new String[]{"DOMAIN"}));
        assertEquals("ROLE", converter.getTableColumnName(1, 3, new String[]{"DOMAIN", "ROLE", "GROUP"}));
    }

    @Test
    public void testGetAthenzUIUrl() {
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");
        NotificationToEmailConverterCommon converter = new NotificationToEmailConverterCommon(null);
        assertEquals("https://athenz.io", converter.getAthenzUIUrl());
        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void testGetWorkflowUrl() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.io");
        NotificationToEmailConverterCommon converter = new NotificationToEmailConverterCommon(null);
        assertEquals("https://athenz.io", converter.getWorkflowUrl());
        System.clearProperty("athenz.notification_workflow_url");
    }

    @Test
    public void testProcessEntry() {

        NotificationToEmailConverterCommon converter = new NotificationToEmailConverterCommon(null);

        String entryNames = "athenz;admin;user.joe;2023-01-01T000000Z|athenz;readers;user.jane;2023-01-01T000000Z|athenz;writers;user.bad";
        String entryFormat = "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td><td class=\"cv\">{3}</td></tr>";

        // empty string without entry names

        StringBuilder body = new StringBuilder(256);
        converter.processEntry(body, null, entryFormat, 4, null);
        assertEquals(body.length(), 0);

        // expected output without athenz url

        String expectedOutput = "<tr><td class=\"cv\">athenz</td><td class=\"cv\">admin</td><td class=\"cv\">user.joe</td><td class=\"cv\">2023-01-01T000000Z</td></tr>\n";
        expectedOutput += "<tr><td class=\"cv\">athenz</td><td class=\"cv\">readers</td><td class=\"cv\">user.jane</td><td class=\"cv\">2023-01-01T000000Z</td></tr>\n";

        converter.processEntry(body, entryNames, entryFormat, 4, null);
        assertEquals(body.toString(), expectedOutput);

        // expected format and output with athenz url

        entryFormat = "<tr><td class=\"cv\"><a href=\"{4}/domain/{0}/role\">{0}</a></td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td><td class=\"cv\">{3}</td></tr>";

        expectedOutput = "<tr><td class=\"cv\"><a href=\"https://athenz.io/domain/athenz/role\">athenz</a></td><td class=\"cv\">admin</td><td class=\"cv\">user.joe</td><td class=\"cv\">2023-01-01T000000Z</td></tr>\n";
        expectedOutput += "<tr><td class=\"cv\"><a href=\"https://athenz.io/domain/athenz/role\">athenz</a></td><td class=\"cv\">readers</td><td class=\"cv\">user.jane</td><td class=\"cv\">2023-01-01T000000Z</td></tr>\n";

        body.setLength(0);
        converter.processEntry(body, entryNames, entryFormat, 4, "https://athenz.io");
        assertEquals(body.toString(), expectedOutput);
    }

    @Test
    public void testGenerateBodyFromTemplate() {

        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");
        NotificationToEmailConverterCommon converter = new NotificationToEmailConverterCommon(null);

        String emailBody = converter.readContentFromFile(getClass().getClassLoader(), "messages/role-member-expiry.html");
        String[] columnNames = new String[] { "DOMAIN", "ROLE", "MEMBER", "EXPIRATION" };
        Map<String, String> metaDetails = new HashMap<>();

        String entryNames = "athenz;admin;user.joe;2023-01-01T000000Z|athenz;readers;user.jane;2023-01-01T000000Z|athenz;writers;user.bad";
        metaDetails.put(NOTIFICATION_DETAILS_ROLES_LIST, entryNames);

        String expectedOutput = converter.readContentFromFile(getClass().getClassLoader(),
                "messages/role-member-expiry-email.html").replaceAll("\\s+","");

        String actualOutput = converter.generateBodyFromTemplate(metaDetails, emailBody,
                NOTIFICATION_DETAILS_MEMBER, NOTIFICATION_DETAILS_ROLES_LIST,
                columnNames.length, columnNames).replaceAll("\\s+","");

        assertEquals(actualOutput, expectedOutput);
        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void testInvalidNotificationClass() {

        System.setProperty("athenz.notification_user_authority", "unknown-class");
        NotificationToEmailConverterCommon converter = new NotificationToEmailConverterCommon(null);
        assertNotNull(converter);
        System.clearProperty("athenz.notification_user_authority");
    }

    @Test
    public void testGetSubject() {
        NotificationToEmailConverterCommon converter = new NotificationToEmailConverterCommon(null);
        assertEquals("Athenz Role Member Expiration Notification",
                converter.getSubject("athenz.notification.email.role_member.expiry.subject"));
    }

    @Test
    public void testReadContentsFromFileFailure() throws IOException {

        NotificationToEmailConverterCommon converter = new NotificationToEmailConverterCommon(null);
        ClassLoader loader = Mockito.mock(ClassLoader.class);
        URL resource = Mockito.mock(URL.class);
        Mockito.when(loader.getResource("file1")).thenReturn(resource);
        Mockito.when(resource.openStream()).thenThrow(new IOException());
        String contents = converter.readContentFromFile(loader, "file1");
        assertTrue(contents.isEmpty());
    }
}
