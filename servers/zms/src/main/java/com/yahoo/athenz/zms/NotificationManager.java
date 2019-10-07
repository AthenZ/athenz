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
import static com.yahoo.athenz.common.server.notification.NotificationService.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER;

public class NotificationManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationManager.class);

    private NotificationService notificationService;
    private ScheduledExecutorService scheduledExecutor;
    private final DBService dbService;
    private final String userDomainPrefix;
    private int pendingRoleMemberLifespan;
    private String monitorIdentity;

    NotificationManager(final DBService dbService, final String userDomainPrefix) {
        this.dbService = dbService;
        this.userDomainPrefix = userDomainPrefix;
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
        if (isNotificationFeatureAvailable()) {
            scheduledExecutor = Executors.newScheduledThreadPool(1);
            scheduledExecutor.scheduleAtFixedRate(new PendingMembershipApprovalReminder(), 0, 1, TimeUnit.DAYS);
        }
        pendingRoleMemberLifespan = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_PENDING_ROLE_MEMBER_LIFESPAN, ZMSConsts.ZMS_PENDING_ROLE_MEMBER_LIFESPAN_DEFAULT));
        monitorIdentity = System.getProperty(ZMSConsts.ZMS_PROP_MONITOR_IDENTITY, ZMSConsts.SYS_AUTH_MONITOR);
    }

    NotificationManager(final DBService dbService, final NotificationServiceFactory notificationServiceFactory, final String userDomainPrefix) {
        this.dbService = dbService;
        this.userDomainPrefix = userDomainPrefix;
        notificationService = notificationServiceFactory.create();
        init();
    }

    void shutdown() {
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdownNow();
        }
    }

    void generateAndSendPostPutMembershipNotification(final String domain, final String org,
             Boolean auditEnabled, Boolean selfServe, Map<String, String> details) {

        if (!isNotificationFeatureAvailable()) {
            return;
        }

        Set<String> recipients = new HashSet<>();
        if (auditEnabled == Boolean.TRUE) {

            //get recipient role(s) from audit domain

            Role domainRole = dbService.getRole(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN,
                    domain, false, true, false);
            Role orgRole = dbService.getRole(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG,
                    org, false, true, false);
            if (domainRole != null) {
                recipients.addAll(domainRole.getRoleMembers().stream().filter(m -> m.getMemberName().startsWith(userDomainPrefix))
                        .map(RoleMember::getMemberName).collect(Collectors.toSet()));
            }
            if (orgRole != null) {
                recipients.addAll(orgRole.getRoleMembers().stream().filter(m -> m.getMemberName().startsWith(userDomainPrefix))
                        .map(RoleMember::getMemberName).collect(Collectors.toSet()));
            }
        } else if (selfServe == Boolean.TRUE) {
            // get admin role from the request domain
            Role adminRole = dbService.getRole(domain, "admin", false, true, false);
            recipients.addAll(adminRole.getRoleMembers().stream().filter(m -> m.getMemberName().startsWith(userDomainPrefix))
                    .map(RoleMember::getMemberName).collect(Collectors.toSet()));
        }
        Notification notification = createNotification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL,
                recipients, details);
        notificationService.notify(notification);
    }

    Notification createNotification(String notificationType, Set<String> recipients, Map<String,
            String> details) {

        String recDomain;
        AthenzDomain domain;
        Notification notification = new Notification(notificationType);
        notification.setDetails(details);
        int idx;
        for (String recipient : recipients) {
            idx = recipient.indexOf(":role.");
            if (idx != -1) {
                //recipient is of type role. Extract role members
                recDomain = recipient.substring(0, idx);
                domain = dbService.getAthenzDomain(recDomain, false);
                for (Role role : domain.getRoles()) {
                    if (role.getName().equals(recipient)) {
                        notification.getRecipients().addAll(role.getRoleMembers().stream().filter(m -> m.getMemberName().startsWith(userDomainPrefix))
                                .map(RoleMember::getMemberName).collect(Collectors.toSet()));
                        break;
                    }
                }
            } else if (recipient.startsWith(userDomainPrefix)) {
                notification.addRecipient(recipient);
            }
        }
        if (notification.getRecipients() == null || notification.getRecipients().isEmpty()) {
            LOGGER.error("Notification requires at least 1 recipient.");
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
            System.out.println("started thread");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PendingMembershipApprovalReminder: Starting pending membership approval reminder thread...");
            }
            try {
                // clean up expired pending members
                dbService.processExpiredPendingMembers(pendingRoleMemberLifespan, monitorIdentity);
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
            dbService.updateLastNotifiedTimestamp(pendingRoleMemberLifespan);
            Set<String> recipients = dbService.getPendingMembershipApproverRoles();
            Notification notification = createNotification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER, recipients, null);
            notificationService.notify(notification);
        }
    }
}
