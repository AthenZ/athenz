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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.text.MessageFormat;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class NotificationToEmailConverterCommon {
    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationToEmailConverterCommon.class);

    private static final String AT = "@";
    private static final String USER_DOMAIN_DEFAULT = "user";
    private static final String PROP_USER_DOMAIN = "athenz.user_domain";
    private static final String PROP_NOTIFICATION_EMAIL_DOMAIN_TO = "athenz.notification_email_domain_to";
    private static final String PROP_NOTIFICATION_WORKFLOW_URL = "athenz.notification_workflow_url";
    private static final String PROP_NOTIFICATION_ATHENZ_UI_URL = "athenz.notification_athenz_ui_url";
    private static final String PROP_NOTIFICATION_SUPPORT_TEXT = "athenz.notification_support_text";
    private static final String PROP_NOTIFICATION_SUPPORT_URL = "athenz.notification_support_url";
    private static final String PROP_NOTIFICATION_USER_AUTHORITY = "athenz.notification_user_authority";
    private static final String EMAIL_TEMPLATE_CSS = "emails/base.css";

    private static final String TABLE_COLUMN_NAME_DOMAIN = "DOMAIN";
    private static final String TABLE_COLUMN_NAME_ROLE   = "ROLE";
    private static final String TABLE_COLUMN_NAME_GROUP  = "GROUP";

    private static final String HTML_STYLE_TAG_START = "<style>";
    private static final String HTML_STYLE_TAG_END = "</style>";
    private static final String HTML_TBODY_TAG_START = "<tbody>";
    private static final String HTML_TBODY_TAG_END = "</tbody>";

    // can be moved to constructor which can take Locale as input parameter and return appropriate resource bundle
    private static final ResourceBundle RB = ResourceBundle.getBundle("messages/ServerCommon");

    private final String userDomainPrefix;
    private final String emailDomainTo;
    private final String workflowUrl;
    private final String athenzUIUrl;
    private final String supportText;
    private final String supportUrl;
    private final String emailBaseCSS;
    private final Authority notificationUserAuthority;

    public NotificationToEmailConverterCommon(Authority notificationUserAuthority) {

        String userDomain = System.getProperty(PROP_USER_DOMAIN, USER_DOMAIN_DEFAULT);
        userDomainPrefix = userDomain + "\\.";
        emailDomainTo = System.getProperty(PROP_NOTIFICATION_EMAIL_DOMAIN_TO);
        workflowUrl = System.getProperty(PROP_NOTIFICATION_WORKFLOW_URL);
        athenzUIUrl = System.getProperty(PROP_NOTIFICATION_ATHENZ_UI_URL);
        supportText = System.getProperty(PROP_NOTIFICATION_SUPPORT_TEXT);
        supportUrl = System.getProperty(PROP_NOTIFICATION_SUPPORT_URL);

        emailBaseCSS = readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_CSS);

        // If a notificationUserAuthority is configured load it.
        final String configuredNotificationAuthority = System.getProperty(PROP_NOTIFICATION_USER_AUTHORITY);
        if (configuredNotificationAuthority != null) {
            this.notificationUserAuthority = loadNotificationUserAuthority(configuredNotificationAuthority);
        } else {
            this.notificationUserAuthority = notificationUserAuthority;
        }
    }

    private Authority loadNotificationUserAuthority(String className) {
        LOGGER.debug("Loading Notification user authority {}...", className);

        Authority authority;
        try {
            authority = (Authority) Class.forName(className).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOGGER.error("Invalid Notification user Authority class: {}", className, ex);
            return null;
        }
        return authority;
    }

    public String readContentFromFile(ClassLoader classLoader, String fileName) {
        StringBuilder contents = new StringBuilder();
        URL resource = classLoader.getResource(fileName);
        if (resource != null) {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(resource.openStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    contents.append(line);
                    contents.append(System.getProperty("line.separator"));
                }
            } catch (IOException ex) {
                LOGGER.error("Could not read file: {}. Error message: {}", fileName, ex.getMessage());
            }
        }
        return contents.toString();
    }

    public String generateBodyFromTemplate(Map<String, String> metaDetails, final String bodyTemplate,
            final String bodyTemplateDetails, final String tableValuesKey, int tableEntryNumColumns,
            final String[] tableEntryColumnNames) {

        // first get the template and replace placeholders
        String body = MessageFormat.format(bodyTemplate, metaDetails.get(bodyTemplateDetails), athenzUIUrl,
                supportUrl, supportText);

        // then get table rows and replace placeholders
        StringBuilder bodyEntry = new StringBuilder(256);
        final String tableValues = metaDetails.get(tableValuesKey);
        final String tableEntryTemplate = getTableEntryTemplate(tableEntryNumColumns, tableEntryColumnNames);
        processEntry(bodyEntry, tableValues, tableEntryTemplate, tableEntryNumColumns, athenzUIUrl);

        // add table rows to the template
        String bodyString = body.replace(HTML_TBODY_TAG_START + HTML_TBODY_TAG_END,
                HTML_TBODY_TAG_START + bodyEntry + HTML_TBODY_TAG_END);

        // add css style to the template
        return addCssStyleToBody(bodyString);
    }

    boolean appendHrefLink(StringBuilder stringBuilder, int idx, int numOfColumns, final String[] columnNames, int domainIdx) {

        // special href handling for 3 reserved column names: DOMAIN, ROLE and GROUP

        if (TABLE_COLUMN_NAME_DOMAIN.equals(getTableColumnName(idx, numOfColumns, columnNames))) {
            // athenz ui domain link is <athenz-url>/domain/<domain-name>/role
            stringBuilder.append("<a href=\"{").append(numOfColumns).append("}/domain/{")
                    .append(idx).append("}/role\">");
            return true;
        } else if (TABLE_COLUMN_NAME_ROLE.equals(getTableColumnName(idx, numOfColumns, columnNames))) {
            // athenz ui role link is <athenz-url>/domain/<domain-name>/role/<role-name>/members
            stringBuilder.append("<a href=\"{").append(numOfColumns).append("}/domain/{")
                    .append(domainIdx).append("}/role/{").append(idx).append("}/members\">");
            return true;
        } else if (TABLE_COLUMN_NAME_GROUP.equals(getTableColumnName(idx, numOfColumns, columnNames))) {
            // athenz ui group link is <athenz-url>/domain/<domain-name>/group/<group-name>/members
            stringBuilder.append("<a href=\"{").append(numOfColumns).append("}/domain/{")
                    .append(domainIdx).append("}/group/{").append(idx).append("}/members\">");
            return true;
        }
        return false;
    }

    public String getTableEntryTemplate(int numOfColumns, final String[] columnNames) {

        // we're going to generate our table rows. we only three special
        // column names reserved: DOMAIN, ROLE and GROUP - where we'll generate
        // an athenz link based on the configured uri. So we're going to cycle
        // through the column name first and find the domain index first

        int domainIdx = getTableColumnIndex(columnNames, TABLE_COLUMN_NAME_DOMAIN);
        boolean includeHref = athenzUIUrl != null && !athenzUIUrl.isEmpty() && domainIdx != -1;
        StringBuilder tableEntryTemplate = new StringBuilder(256);
        tableEntryTemplate.append("<tr>");
        for (int i = 0; i < numOfColumns; ++i) {
            tableEntryTemplate.append("<td class=\"cv\">");
            // we are going to include inks for our special fields only if the athenz
            // ui url is configured and not empty, and we have domain field specified
            boolean hRrefAdded = false;
            if (includeHref) {
                hRrefAdded = appendHrefLink(tableEntryTemplate, i, numOfColumns, columnNames, domainIdx);
            }
            tableEntryTemplate.append("{");
            tableEntryTemplate.append(i);
            tableEntryTemplate.append("}");
            if (hRrefAdded) {
                tableEntryTemplate.append("</a>");
            }
            tableEntryTemplate.append("</td>");
        }
        tableEntryTemplate.append("</tr>");
        return tableEntryTemplate.toString();
    }

    int getTableColumnIndex(final String[] columnNames, final String columnName) {
        if (columnNames == null) {
            return -1;
        }
        for (int idx = 0; idx < columnNames.length; idx++) {
            if (columnName.equals(columnNames[idx])) {
                return idx;
            }
        }
        return -1;
    }

    String getTableColumnName(int idx, int numOfColumns, final String[] columnNames) {
        if (columnNames == null || columnNames.length != numOfColumns || idx >= numOfColumns) {
            return null;
        }
        return columnNames[idx];
    }

    public String addCssStyleToBody(String body) {
        return body.replace(HTML_STYLE_TAG_START + HTML_STYLE_TAG_END, HTML_STYLE_TAG_START + emailBaseCSS + HTML_STYLE_TAG_END);
    }

    void processEntry(StringBuilder body, final String entryNames, final String entryFormat, int entryLength,
                      final String athenzUIUrl) {

        // if we have no entry names then there is nothing to process
        if (entryNames == null) {
            return;
        }
        String[] entries = entryNames.split("\\|");
        for (String entry : entries) {
            String[] comps = entry.split(";");
            if (comps.length != entryLength) {
                continue;
            }
            if (athenzUIUrl != null && !athenzUIUrl.isEmpty()) {
                List<String> combinedComps = Stream.of(comps).collect(Collectors.toCollection(ArrayList::new));
                combinedComps.add(athenzUIUrl);
                comps = combinedComps.toArray(new String[0]);
            }
            body.append(MessageFormat.format(entryFormat, (Object[]) comps));
            body.append('\n');
        }
    }

    public String getSubject(String propertyName) {
        return RB.getString(propertyName);
    }

    public Set<String> getFullyQualifiedEmailAddresses(Set<String> recipients) {
        return recipients.stream()
                .map(userName -> {
                    if (notificationUserAuthority != null) {
                        String email = notificationUserAuthority.getUserEmail(userName);
                        if (email != null) {
                            return email;
                        }
                    }
                    return userName.replaceAll(userDomainPrefix, "") + AT + emailDomainTo;
                })
                .collect(Collectors.toSet());
    }

    public String getWorkflowUrl() {
        return workflowUrl;
    }

    public String getAthenzUIUrl() {
        return athenzUIUrl;
    }
}
