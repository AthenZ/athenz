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

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.AthenzDomain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class NotificationManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationManager.class);

    private NotificationServiceFactory notificationServiceFactory;
    private NotificationService notificationService;
    ScheduledExecutorService scheduledExecutor;
    private DBService dbService;

    public NotificationManager(DBService dbService) {

        this.dbService = dbService;
        String notificationServiceFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);
        NotificationServiceFactory notificationServiceFactory;
        try {
            notificationServiceFactory = (NotificationServiceFactory) Class.forName(notificationServiceFactoryClass).newInstance();
            notificationService = notificationServiceFactory.create();

        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid NotificationServiceFactory class: " + notificationServiceFactoryClass + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid notification service factory");
        }

        init();
    }

    private void init() {
        if (notificationService != null) {
            scheduledExecutor = Executors.newScheduledThreadPool(1);
            scheduledExecutor.scheduleAtFixedRate(new PendingMembershipApprovalReminder(), 0, 1, TimeUnit.DAYS);
        }
    }

    public NotificationManager(DBService dbService, NotificationServiceFactory notificationServiceFactory) {

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

    public List<Notification> createNotifications(String notificationType, Set<String> recipients, Map<String, String> details) {
        List<Notification> notifications = new ArrayList<>();
        String recDomain, recRole;
        AthenzDomain domain;
        for (String recipient : recipients) {
            if (recipient.contains(":role.")) {
                //recipient is of type role. Extract role members
                recDomain = recipient.substring(0, recipient.indexOf(":"));
                recRole = recipient.substring(recipient.indexOf(":") + 6);
                domain = dbService.getAthenzDomain(recDomain, false);
                for (Role role : domain.getRoles()) {
                    if (role.getName().equalsIgnoreCase(domain.getName() + ":role." + recRole)) {
                        notifications.add(new Notification(notificationType)
                                .setRecipients(new HashSet<>(role.getMembers()))
                                .setDetails(details));
                    }
                }
            } else if (recipient.startsWith("user.")) {
                Set<String> recSet = new HashSet<>();
                recSet.add(recipient);
                notifications.add(new Notification(notificationType)
                        .setRecipients(recSet)
                        .setDetails(details));
            }
        }
        return notifications;
    }

    public void sendNotification (Notification notification) {
        notificationService.notify(notification);
    }

    class PendingMembershipApprovalReminder implements Runnable {
        @Override
        public void run() {
            LOGGER.info("PendingMembershipApprovalReminder: Starting pending membership approval reminder thread...");
            int remindersSent = 0;
            try {
                remindersSent = sendPendingMembershipApprovalReminders();
            } catch (Throwable t) {
                LOGGER.error("PendingMembershipApprovalReminder: unable to send pending membership approval reminders: {}",
                        t.getMessage());
            }
            LOGGER.info("PendingMembershipApprovalReminder: Sent {} reminders for pending membership approvals", remindersSent);
        }

        private int sendPendingMembershipApprovalReminders() {
            Set<String> recipients = dbService.getPendingMembershipNotifications();
            List<Notification> notifications = createNotifications(ZMSConsts.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL, recipients, null);
            int counter = 0;
            for (Notification notification : notifications) {
                if (notificationService.notify(notification)) {
                    counter++;
                }
            }
            return counter;
        }
    }
}
