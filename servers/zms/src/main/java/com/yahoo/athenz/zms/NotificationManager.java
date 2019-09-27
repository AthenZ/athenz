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

package com.yahoo.athenz.zms;

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import com.yahoo.athenz.zms.store.AthenzDomain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static com.yahoo.athenz.common.server.notification.NotificationService.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL;

public class NotificationManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationManager.class);


    private NotificationServiceFactory notificationServiceFactory;
    private NotificationService notificationService;
    private ScheduledExecutorService scheduledExecutor;
    private final DBService dbService;
    private String userDomain;
    private String userDomainPrefix;

    NotificationManager(final DBService dbService) {
        this.dbService = dbService;
        String notificationServiceFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);
        if (notificationServiceFactoryClass != null) {
            NotificationServiceFactory notificationServiceFactory;
            try {
                notificationServiceFactory = (NotificationServiceFactory) Class.forName(notificationServiceFactoryClass).newInstance();
                notificationService = notificationServiceFactory.create();
                init();
            } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
                LOGGER.error("Invalid NotificationServiceFactory class: " + notificationServiceFactoryClass + " error: " + e.getMessage());
            }
        }
    }

    private void init() {
        userDomain = System.getProperty(ZMSConsts.ZMS_PROP_USER_DOMAIN, ZMSConsts.USER_DOMAIN);
        userDomainPrefix = userDomain + ".";
        if (notificationService != null) {
            scheduledExecutor = Executors.newScheduledThreadPool(1);
            scheduledExecutor.scheduleAtFixedRate(new PendingMembershipApprovalReminder(), 0, 1, TimeUnit.DAYS);
        }
    }

    NotificationManager(final DBService dbService, final NotificationServiceFactory notificationServiceFactory) {
        this.dbService = dbService;
        this.notificationServiceFactory = notificationServiceFactory;
        notificationService = this.notificationServiceFactory.create();
        init();
    }

    void shutdown() {
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdownNow();
        }
    }

    void generateAndSendPostPutMembershipNotification(String domain, String org, Boolean auditEnabled, Boolean selfserve, Map<String, String> details) {
        if (isNotificationFeatureAvailable()) {
            Set<String> recipients = new HashSet<>();
            if (auditEnabled == Boolean.TRUE) {
                //get recipient role(s) from audit domain
                Role domainRole = dbService.getRole(ZMSConsts.SYS_AUTH_AUDIT_DOMAIN, ZMSConsts.AUDIT_APPROVER_ROLE_PREFIX + org + "." + domain, false, true, false);
                Role orgRole = dbService.getRole(ZMSConsts.SYS_AUTH_AUDIT_DOMAIN, ZMSConsts.AUDIT_APPROVER_ROLE_PREFIX + org, false, true, false);
                if (domainRole != null) {
                    recipients.addAll(domainRole.getRoleMembers().stream()
                            .map(RoleMember::getMemberName).collect(Collectors.toSet()));
                }
                if (orgRole != null) {
                    recipients.addAll(orgRole.getRoleMembers().stream()
                            .map(RoleMember::getMemberName).collect(Collectors.toSet()));
                }
            } else if (selfserve == Boolean.TRUE) {
                // get admin role from the request domain
                Role adminRole = dbService.getRole(domain, "admin", false, true, false);
                recipients.addAll(adminRole.getRoleMembers().stream()
                        .map(RoleMember::getMemberName).collect(Collectors.toSet()));
            }
            Notification notification = createNotification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL, recipients, details);
            notificationService.notify(notification);
        }
    }

    Notification createNotification(String notificationType, Set<String> recipients, Map<String, String> details) {
        String recDomain;
        AthenzDomain domain;
        Notification notification = new Notification(notificationType);
        notification.setDetails(details);
        for (String recipient : recipients) {
            if (recipient.contains(":role.")) {
                //recipient is of type role. Extract role members
                recDomain = recipient.substring(0, recipient.indexOf(":"));
                domain = dbService.getAthenzDomain(recDomain, false);
                for (Role role : domain.getRoles()) {
                    if (role.getName().equals(recipient)) {
                        for (RoleMember member : role.getRoleMembers()) {
                            notification.addRecipient(member.getMemberName());
                        }
                        break;
                    }
                }
            } else if (recipient.startsWith(userDomainPrefix)) {
                notification.addRecipient(recipient);
            }
        }
        if (notification.getRecipients() == null || notification.getRecipients().isEmpty()) {
            LOGGER.error("Notification requires atleast 1 recipient.");
            return null;
        }
        return notification;
    }

    void sendNotification(Notification notification) {
        if (isNotificationFeatureAvailable()) {
            notificationService.notify(notification);
        }
    }

    private boolean isNotificationFeatureAvailable () {
        return notificationService != null;
    }

    class PendingMembershipApprovalReminder implements Runnable {
        @Override
        public void run() {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PendingMembershipApprovalReminder: Starting pending membership approval reminder thread...");
            }
            try {
                sendPendingMembershipApprovalReminders();
            } catch (Throwable t) {
                LOGGER.error("PendingMembershipApprovalReminder: unable to send pending membership approval reminders: {}",
                        t.getMessage());
            }
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PendingMembershipApprovalReminder: Sent reminder for pending membership approvals.");
            }

        }

        private void sendPendingMembershipApprovalReminders() {
            Set<String> recipients = dbService.getPendingMembershipApproverRoles();
            Notification notification = createNotification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL, recipients, null);
            notificationService.notify(notification);
        }
    }
}
