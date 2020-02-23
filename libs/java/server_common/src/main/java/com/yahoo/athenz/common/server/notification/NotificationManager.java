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

package com.yahoo.athenz.common.server.notification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_PROP_SERVICE_FACTORY_CLASS;

public class NotificationManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationManager.class);

    private NotificationService notificationService;
    private ScheduledExecutorService scheduledExecutor;
    private List<NotificationTask> notificationTasks;

    public NotificationManager(List<NotificationTask> notificationTasks) {
        this.notificationTasks = notificationTasks;
        String notificationServiceFactoryClass = System.getProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
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
        if (enableScheduledNotifications()) {
            scheduledExecutor = Executors.newScheduledThreadPool(1);
            scheduledExecutor.scheduleAtFixedRate(new PeriodicNotificationsSender(), 0, 1, TimeUnit.DAYS);
        }
    }

    public NotificationManager(final NotificationServiceFactory notificationServiceFactory, List<NotificationTask> notificationTasks) {
        this.notificationTasks = notificationTasks;
        notificationService = notificationServiceFactory.create();
        init();
    }

    public void shutdown() {
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdownNow();
        }
    }

    public void sendNotifications(List<Notification> notifications) {
        if (isNotificationFeatureAvailable()) {
            notifications.stream().filter(Objects::nonNull).forEach(notification -> notificationService.notify(notification));
        }
    }

    public boolean isNotificationFeatureAvailable () {
        return notificationService != null;
    }

    private boolean enableScheduledNotifications() {
        // Enable notification scheduler if a NotificationService is available and NotificationTasks exist
        return isNotificationFeatureAvailable() && this.notificationTasks != null && !this.notificationTasks.isEmpty();
    }

    class PeriodicNotificationsSender implements Runnable {

        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PeriodicNotificationsSender: Starting notifications thread...");
            }

            // Note that ordering in the list of notifications is important as a NotificationTask might depend on a previous
            // NotificationTask running
            for (NotificationTask notificationTask: notificationTasks) {
                try {
                    List<Notification> notifications = notificationTask.getNotifications();
                    notifications.stream()
                            .filter(Objects::nonNull)
                            .forEach(notification -> notificationService.notify(notification));

                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug(String.format("PeriodicNotificationsSender: Sent %s.", notificationTask.getDescription()));
                    }

                } catch (Throwable t) {
                    LOGGER.error(String.format("PeriodicNotificationsSender: unable to send %s: ", notificationTask.getDescription()), t);
                }
            }

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PeriodicNotificationsSender: completed");
            }
        }
    }
}
