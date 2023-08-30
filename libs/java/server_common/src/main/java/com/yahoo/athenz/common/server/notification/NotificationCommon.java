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

package com.yahoo.athenz.common.server.notification;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Common functionality for Notification Tasks.
 */
public class NotificationCommon {

    private final DomainRoleMembersFetcher domainRoleMembersFetcher;
    private final String userDomainPrefix;
    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationCommon.class);

    public NotificationCommon(DomainRoleMembersFetcher domainRoleMembersFetcher, String userDomainPrefix) {
        this.domainRoleMembersFetcher = domainRoleMembersFetcher;
        this.userDomainPrefix = userDomainPrefix;
    }

    public Notification createNotification(Set<String> recipients,
                                           Map<String, String> details,
                                           NotificationToEmailConverter notificationToEmailConverter,
                                           NotificationToMetricConverter notificationToMetricConverter) {

        if (recipients == null || recipients.isEmpty()) {
            LOGGER.error("Notification requires at least 1 recipient.");
            return null;
        }

        Notification notification = new Notification();
        notification.setDetails(details);
        notification.setNotificationToEmailConverter(notificationToEmailConverter);
        notification.setNotificationToMetricConverter(notificationToMetricConverter);

        for (String recipient : recipients) {
            addNotificationRecipient(notification, recipient, true);
        }

        if (notification.getRecipients() == null || notification.getRecipients().isEmpty()) {
            LOGGER.error("Notification requires at least 1 recipient.");
            return null;
        }

        return notification;
    }

    public Notification createNotification(final String recipient,
                                           Map<String, String> details,
                                           NotificationToEmailConverter notificationToEmailConverter,
                                           NotificationToMetricConverter notificationToMetricConverter) {

        if (recipient == null || recipient.isEmpty()) {
            LOGGER.error("Notification requires a valid recipient");
            return null;
        }

        Notification notification = new Notification();
        notification.setDetails(details);
        notification.setNotificationToEmailConverter(notificationToEmailConverter);
        notification.setNotificationToMetricConverter(notificationToMetricConverter);

        // if the recipient is a service then we're going to send a notification
        // to the service's domain admin users

        addNotificationRecipient(notification, recipient, false);

        if (notification.getRecipients() == null || notification.getRecipients().isEmpty()) {
            LOGGER.error("Notification requires at least 1 recipient.");
            return null;
        }

        return notification;
    }

    void addDomainRoleRecipients(Notification notification, final String domainName, final String roleName) {
        try {
            Set<String> domainRoleMembers = domainRoleMembersFetcher.getDomainRoleMembers(domainName, roleName);
            if (domainRoleMembers == null || domainRoleMembers.isEmpty()) {
                return;
            }

            notification.getRecipients().addAll(domainRoleMembers);
        } catch (ResourceException ex) {
            LOGGER.error("Error getting domain role members ", ex);
        }
    }

    void addNotificationRecipient(Notification notification, final String recipient, boolean ignoreService) {

        int roleDomainIndex = recipient.indexOf(AuthorityConsts.ROLE_SEP);
        if (roleDomainIndex != -1) {
            addDomainRoleRecipients(notification, recipient.substring(0, roleDomainIndex), recipient);
        } else if (recipient.contains(AuthorityConsts.GROUP_SEP)) {
            // Do nothing. Group members will not get individual notifications.
        } else if (recipient.startsWith(userDomainPrefix)) {
            notification.addRecipient(recipient);
        } else if (!ignoreService) {
            final String domainName = AthenzUtils.extractPrincipalDomainName(recipient);
            if (domainName != null) {
                addDomainRoleRecipients(notification, domainName, ResourceUtils.roleResourceName(domainName, ServerCommonConsts.ADMIN_ROLE_NAME));
            }
        }
    }

    public List<Notification> printNotificationDetailsToLog(List<Notification> notificationDetails, String description, Logger logger) {
        if (notificationDetails != null && !notificationDetails.isEmpty()) {
            StringBuilder detailsForLog = new StringBuilder();
            detailsForLog.append("Notifications details for ").append(description).append(" :\n");
            for (Notification notification : notificationDetails) {
                detailsForLog.append(notification).append("\n");
            }
            logger.info(detailsForLog.toString());
        } else {
            logger.info("No notifications details for " + description);
        }
        return notificationDetails;
    }
}
