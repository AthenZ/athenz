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

import static com.yahoo.athenz.common.ServerCommonConsts.OBJECT_GROUP;
import static com.yahoo.athenz.common.ServerCommonConsts.OBJECT_ROLE;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.*;
import static org.testng.Assert.assertTrue;

public class NotificationConverterCommonTest {

    @Test
    public void testGetFullyQualifiedEmailAddresses() {
        System.clearProperty("athenz.user_domain");
        System.setProperty("athenz.user_domain", "entuser");
        System.setProperty("athenz.notification_email_domain_from", "from.example.com");
        System.setProperty("athenz.notification_email_domain_to", "example.com");

        Set<String> recipients = new HashSet<>(Arrays.asList("entuser.user1", "entuser.user2", "entuser.user3"));

        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        Set<String> recipientsResp = notificationConverterCommon.getFullyQualifiedEmailAddresses(recipients);
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
        NotificationConverterCommon notificationConverterCommon =
                new NotificationConverterCommon(notificationAuthorityForTest);
        Set<String> recipientsResp = notificationConverterCommon.getFullyQualifiedEmailAddresses(recipients);
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
        NotificationConverterCommon notificationConverterCommon =
                new NotificationConverterCommon(debugUserAuthority);
        Set<String> recipientsResp = notificationConverterCommon.getFullyQualifiedEmailAddresses(recipients);
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
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        Set<String> recipientsResp = notificationConverterCommon.getFullyQualifiedEmailAddresses(recipients);
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
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        assertTrue(notificationConverterCommon.readContentFromFile(
                getClass().getClassLoader(), "resources/non-existent").isEmpty());
    }

    @Test
    public void testReadContentFromFileNull() throws Exception {
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

        BufferedReader reader = mock(BufferedReader.class);
        Mockito.when(reader.readLine()).thenReturn(null);
        assertTrue(notificationConverterCommon.readContentFromFile(
                getClass().getClassLoader(), "resources/dummy").isEmpty());
    }

    @Test
    public void testReadContentFromFileException() throws Exception {
        NotificationConverterCommon notificationConverterCommon =
                new NotificationConverterCommon(null);

        BufferedReader reader = mock(BufferedReader.class);
        Mockito.when(reader.readLine()).thenThrow(new IOException());
        assertTrue(notificationConverterCommon.readContentFromFile(
                getClass().getClassLoader(), "resources/dummy").isEmpty());
    }

    @Test
    public void testgettTbleEntryTemplate() {
        NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);
        int numOfColumns = 1;
        String tableEntryTemplate = notificationConverterCommon.getTableEntryTemplate(numOfColumns, null);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td></tr>");

        numOfColumns = 3;
        tableEntryTemplate = notificationConverterCommon.getTableEntryTemplate(numOfColumns, null);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td></tr>");

        numOfColumns = 6;
        tableEntryTemplate = notificationConverterCommon.getTableEntryTemplate(numOfColumns, null);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td><td class=\"cv\">{3}</td><td class=\"cv\">{4}</td><td class=\"cv\">{5}</td></tr>");
    }

    @Test
    public void testgettTbleEntryTemplateColumnNames() {

        System.clearProperty("athenz.notification_athenz_ui_url");
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        int numOfColumns = 3;
        String[] columnNames = { "DOMAIN", "ROLE", "GROUP" };

        // with no url, there are no changes
        String tableEntryTemplate = converter.getTableEntryTemplate(numOfColumns, columnNames);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td></tr>");

        // similarly, with empty url, there are no changes either

        System.setProperty("athenz.notification_athenz_ui_url", "");
        converter = new NotificationConverterCommon(null);
        tableEntryTemplate = converter.getTableEntryTemplate(numOfColumns, columnNames);
        assertEquals(tableEntryTemplate, "<tr><td class=\"cv\">{0}</td><td class=\"cv\">{1}</td><td class=\"cv\">{2}</td></tr>");

        // we're going to set the url but no domain in the column names

        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");
        converter = new NotificationConverterCommon(null);
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

        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        assertNull(converter.getTableColumnName(3, 4, null));
        assertNull(converter.getTableColumnName(3, 4, new String[]{"DOMAIN"}));
        assertNull(converter.getTableColumnName(2, 1, new String[]{"DOMAIN"}));
        assertNull(converter.getTableColumnName(1, 1, new String[]{"DOMAIN"}));
        assertEquals(converter.getTableColumnName(0, 1, new String[]{"DOMAIN"}), "DOMAIN");
        assertEquals(converter.getTableColumnName(1, 3, new String[]{"DOMAIN", "ROLE", "GROUP"}), "ROLE");
    }

    @Test
    public void testGetAthenzUIUrl() {
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        assertEquals(converter.getAthenzUIUrl(), "https://athenz.io");
        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void testGetAdminWorkflowUrl() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.io");
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        assertEquals(converter.getAdminWorkflowUrl(), "https://athenz.io");

        System.clearProperty("athenz.notification_workflow_url");
        converter = new NotificationConverterCommon(null);
        // if workflow url is not set, then we should return empty string
        assertEquals(converter.getAdminWorkflowUrl(), "");
    }

    @Test
    public void testGetDominWorkflowUrl() {
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        // if Athenz UI url is not set, then we should return empty string
        assertEquals(converter.getDomainWorkflowUrl(null), "");

        // set Athenz UI url
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");
        converter = new NotificationConverterCommon(null);

        // if domainName is empty or null, return domain workflow url
        assertEquals(converter.getDomainWorkflowUrl(""), "https://athenz.io/workflow/domain");
        assertEquals(converter.getDomainWorkflowUrl(null), "https://athenz.io/workflow/domain");

        // if domainName is set, return domain workflow url with query param set for domainName
        assertEquals(converter.getDomainWorkflowUrl("test.dom1"), "https://athenz.io/workflow/domain?domain=test.dom1");

        System.clearProperty("athenz.notification_athenz_ui_url");
    }

    @Test
    public void testProcessEntry() {

        NotificationConverterCommon converter = new NotificationConverterCommon(null);

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
        NotificationConverterCommon converter = new NotificationConverterCommon(null);

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
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        assertNotNull(converter);
        System.clearProperty("athenz.notification_user_authority");
    }

    @Test
    public void testGetSubject() {
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        assertEquals(converter.getSubject("athenz.notification.email.role_member.expiry.subject"),
                "Athenz Role Member Expiration Notification");
    }

    @Test
    public void testReadContentsFromFileFailure() throws IOException {

        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        ClassLoader loader = Mockito.mock(ClassLoader.class);
        URL resource = Mockito.mock(URL.class);
        Mockito.when(loader.getResource("file1")).thenReturn(resource);
        Mockito.when(resource.openStream()).thenThrow(new IOException());
        String contents = converter.readContentFromFile(loader, "file1");
        assertTrue(contents.isEmpty());
    }

    @Test
    public void testReadContentFromFileSlackTemplate() {
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        String fileContent = converter.readContentFromFile(getClass().getClassLoader(), "messages/slack-role-member-expiry.ftl");
        assertNotEquals(fileContent, "");
    }

    @Test
    public void testGenerateSlackMessageFromTemplateEmptyNotes() {
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        Map<String, Object> rootDataModel = new HashMap<>();

        List<Map<String, String>> dataModel = new ArrayList<>();
        Map<String, String> role1 = new HashMap<>();
        role1.put("domain", "athenz");
        role1.put("collection", "admin");
        role1.put("member", "user.joe");
        role1.put("expirationOrReviewDate", "2023-01-01T000000Z");
        role1.put("notes", "");
        role1.put("collectionLink", converter.getRoleLink("athenz", "admin"));
        role1.put("domainLink", converter.getDomainLink("athenz"));

        dataModel.add(role1);
        rootDataModel.put("collectionData", dataModel);
        String slackTemplate = converter.readContentFromFile(getClass().getClassLoader(),"messages/slack-role-member-expiry.ftl");
        String entryNames = "athenz;admin;user.joe;2023-01-01T000000Z|athenz;readers;user.jane;2023-01-01T000000Z|athenz;writers;user.bad";
        Map<String, String> metaDetails = new HashMap<>();
        metaDetails.put(NOTIFICATION_DETAILS_ROLES_LIST, entryNames);
        String slackMessage = converter.generateSlackMessageFromTemplate(rootDataModel, slackTemplate);
        assertEquals(slackMessage, converter.readContentFromFile(getClass().getClassLoader(),
                "messages/role-member-expiry-slack.txt"));

        System.clearProperty("notification_athenz_ui_url");
    }

    @Test
    public void testGenerateSlackMessageFromTemplateMultipleRoles() {
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        Map<String, Object> rootDataModel = new HashMap<>();

        List<Map<String, String>> dataModel = new ArrayList<>();
        Map<String, String> role1 = new HashMap<>();
        role1.put("domain", "athenz");
        role1.put("collection", "admin");
        role1.put("member", "user.joe");
        role1.put("expirationOrReviewDate", "2023-01-01T000000Z");
        role1.put("notes", "");
        role1.put("collectionLink", converter.getRoleLink("athenz", "admin"));
        role1.put("domainLink", converter.getDomainLink("athenz"));

        dataModel.add(role1);

        Map<String, String> role2 = new HashMap<>();
        role2.put("domain", "athenz.dev");
        role2.put("collection", "admin-dev");
        role2.put("member", "user.john");
        role2.put("expirationOrReviewDate", "2024-01-01T000000Z");
        role2.put("notes", "Lorem Ipsum");
        role2.put("collectionLink", converter.getRoleLink("athenz", "admin-dev"));
        role2.put("domainLink", converter.getDomainLink("athenz"));

        dataModel.add(role2);
        rootDataModel.put("collectionData", dataModel);

        String slackTemplate = converter.readContentFromFile(getClass().getClassLoader(),"messages/slack-role-member-expiry.ftl");
        String entryNames = "athenz;admin;user.joe;2023-01-01T000000Z|athenz;readers;user.jane;2023-01-01T000000Z|athenz;writers;user.bad";
        Map<String, String> metaDetails = new HashMap<>();
        metaDetails.put(NOTIFICATION_DETAILS_ROLES_LIST, entryNames);
        String slackMessage = converter.generateSlackMessageFromTemplate(rootDataModel, slackTemplate);
        assertEquals(slackMessage, converter.readContentFromFile(getClass().getClassLoader(),
                "messages/role-member-expiry-multiple-roles-slack.txt"));

        System.clearProperty("notification_athenz_ui_url");
    }

    @Test
    public void testGenerateSlackMessageFromTemplateException() {
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        String invalidTemplateContent = "<#ftl>\n"
                + "${InvalidFreemarkerSyntax???}\n";

        String result = converter.generateSlackMessageFromTemplate(new HashMap<>(), invalidTemplateContent);
        assertNull(result);
    }

    @Test
    public void testGetDominLink() {
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");

        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        String domainName = "athenz";
        String domainLink = converter.getDomainLink(domainName);
        assertEquals(domainLink, "https://athenz.io/domain/" + domainName + "/role");

        System.clearProperty("athenz.notification_athenz_ui_url");
        converter = new NotificationConverterCommon(null);
        domainLink = converter.getDomainLink(domainName);
        assertEquals(domainLink, "");
    }

    @Test
    public void testGetRoleLink() {
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");

        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        String domainName = "athenz";
        String roleName = "team";
        String roleLink = converter.getRoleLink(domainName, roleName);
        assertEquals(roleLink, "https://athenz.io/domain/" + domainName + "/role/" + roleName + "/members");

        System.clearProperty("athenz.notification_athenz_ui_url");
        converter = new NotificationConverterCommon(null);
        roleLink = converter.getRoleLink(domainName, roleName);
        assertEquals(roleLink, "");
    }

    @Test
    public void testGetGroupLink() {
        System.setProperty("athenz.notification_athenz_ui_url", "https://athenz.io");

        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        String domainName = "athenz";
        String groupName = "team";
        String groupLink = converter.getGroupLink(domainName, groupName);
        assertEquals(groupLink, "https://athenz.io/domain/" + domainName + "/group/" + groupName + "/members");

        System.clearProperty("athenz.notification_athenz_ui_url");
        converter = new NotificationConverterCommon(null);
        groupLink = converter.getGroupLink(domainName, groupName);
        assertEquals(groupLink, "");
    }

    @Test
    public void testGetSlackRecipients() {
        System.setProperty("athenz.notification_email_domain_to", "yahoo.com");
        System.setProperty("athenz.user_domain", "entuser");
        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        Set<String> slackRecipientsEmpty = converter.getSlackRecipients(null, null);
        assertTrue(slackRecipientsEmpty.isEmpty());

        Set<String> recipients = new HashSet<>(Arrays.asList("athenz", "sports", "weather"));
        Map<String, NotificationDomainMeta> domainMetaMap = new HashMap<>();
        domainMetaMap.put("athenz", new NotificationDomainMeta("athenz").setSlackChannel("channel1"));
        domainMetaMap.put("sports", new NotificationDomainMeta("sports").setSlackChannel("channel2"));

        Set<String> slackRecipients = converter.getSlackRecipients(recipients, domainMetaMap);
        assertEquals(slackRecipients.size(), 2);
        assertTrue(slackRecipients.contains("channel1"));
        assertTrue(slackRecipients.contains("channel2"));

        recipients = new HashSet<>(Arrays.asList("athenz", "sports", "entuser.user1"));
        domainMetaMap = new HashMap<>();
        domainMetaMap.put("athenz", new NotificationDomainMeta("athenz").setSlackChannel("channel1"));
        domainMetaMap.put("sports", new NotificationDomainMeta("sports").setSlackChannel("channel2"));
        domainMetaMap.put("weather", new NotificationDomainMeta("sports").setSlackChannel("channel2"));

        slackRecipients = converter.getSlackRecipients(recipients, domainMetaMap);
        assertEquals(slackRecipients.size(), 3);
        assertTrue(slackRecipients.contains("channel1"));
        assertTrue(slackRecipients.contains("channel2"));
        assertTrue(slackRecipients.contains("user1@yahoo.com"));

        System.clearProperty("athenz.user_domain");
        System.clearProperty("athenz.notification_email_domain_to");
    }

    @Test
    public void testGetSlackMessageFromTemplate() {
        // getSlackMessageFromTemplate(Map<String, String> metaDetails, String template, String detailsKey, Integer numColumns, String collectionType)
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");

        NotificationConverterCommon converter = new NotificationConverterCommon(null);
        String slackTemplate = converter.readContentFromFile(getClass().getClassLoader(),"messages/slack-role-member-expiry.ftl");

        Map<String, String> metaDetails = null;
        assertNull(converter.getSlackMessageFromTemplate(metaDetails, slackTemplate, NOTIFICATION_DETAILS_ROLES_LIST, 5, OBJECT_ROLE));

        metaDetails = new HashMap<>();
        metaDetails.put(NOTIFICATION_DETAILS_ROLES_LIST, "athenz1;role1;user.joe;2020-12-01T12:00:00.000Z;notify%20details|athenz2;role2;user.joe;2020-12-01T12:00:00.000Z;");

        assertNull(converter.getSlackMessageFromTemplate(metaDetails, slackTemplate, NOTIFICATION_DETAILS_MEMBERS_LIST, 5, OBJECT_ROLE));
        // no entries for key
        assertNull(converter.getSlackMessageFromTemplate(metaDetails, slackTemplate, NOTIFICATION_DETAILS_MEMBERS_LIST, 5, OBJECT_ROLE));

        // number of cloumns is more than entries
        String result = converter.getSlackMessageFromTemplate(metaDetails, slackTemplate, NOTIFICATION_DETAILS_ROLES_LIST, 10, OBJECT_ROLE);
        assertNull(result);

        result = converter.getSlackMessageFromTemplate(metaDetails, slackTemplate, NOTIFICATION_DETAILS_ROLES_LIST, 5, OBJECT_ROLE);
        assertNotNull(result);
        assertTrue(result.contains("athenz1"));
        assertTrue(result.contains("role1"));
        assertTrue(result.contains("user.joe"));
        assertTrue(result.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(result.contains("notify details"));

        result = converter.getSlackMessageFromTemplate(metaDetails, slackTemplate, NOTIFICATION_DETAILS_ROLES_LIST, 5, OBJECT_GROUP);
        assertNotNull(result);
        assertTrue(result.contains("athenz1"));
        assertTrue(result.contains("role1"));
        assertTrue(result.contains("user.joe"));
        assertTrue(result.contains("2020-12-01T12:00:00.000Z"));
        assertTrue(result.contains("notify details"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
    }
}
