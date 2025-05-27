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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.db.DomainProvider;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class NotificationManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationManager.class);

    private final List<NotificationService> notificationServices = new ArrayList<>();
    private ScheduledExecutorService scheduledExecutor;
    private final List<NotificationTask> notificationTasks;
    private final Authority notificationUserAuthority;
    private final NotificationObjectStore notificationObjectStore;

    public NotificationManager(List<NotificationTask> notificationTasks, Authority notificationUserAuthority,
            PrivateKeyStore privateKeyStore, DomainProvider domainProvider, NotificationObjectStore notificationObjectStore) {

        this.notificationTasks = notificationTasks;
        this.notificationUserAuthority = notificationUserAuthority;
        this.notificationObjectStore = notificationObjectStore;

        final String notificationServiceFactoryClasses = System.getProperty(
                NotificationServiceConstants.NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);
        if (!StringUtil.isEmpty(notificationServiceFactoryClasses)) {
            String[] notificationServiceFactoryClassArray = notificationServiceFactoryClasses.split(",");
            for (String notificationServiceFactoryClass : notificationServiceFactoryClassArray) {
                NotificationServiceFactory notificationServiceFactory;
                try {
                    notificationServiceFactory = (NotificationServiceFactory) Class.forName(
                            notificationServiceFactoryClass.trim()).getDeclaredConstructor().newInstance();
                    NotificationService notificationService = notificationServiceFactory.create(privateKeyStore);
                    if (notificationService != null) {
                        notificationService.setDomainProvider(domainProvider);
                        notificationServices.add(notificationService);
                    }
                } catch (Exception ex) {
                    LOGGER.error("Invalid NotificationServiceFactory class: {}", notificationServiceFactoryClass, ex);
                }
            }
            LOGGER.info("Loaded Notification Services: {}", String.join(",", getLoadedNotificationServices()));
            init();
        }
    }

    private void init() {
        if (enableScheduledNotifications()) {
            scheduledExecutor = Executors.newScheduledThreadPool(1);
            scheduledExecutor.scheduleAtFixedRate(new PeriodicNotificationsSender(), 0, 1, TimeUnit.DAYS);
        }
    }

    public NotificationManager(final List<NotificationServiceFactory> notificationServiceFactories,
            List<NotificationTask> notificationTasks, Authority notificationUserAuthority,
            PrivateKeyStore privateKeyStore, NotificationObjectStore notificationObjectStore) {
        this.notificationTasks = notificationTasks;
        this.notificationUserAuthority = notificationUserAuthority;
        this.notificationObjectStore = notificationObjectStore;
        notificationServiceFactories.stream().filter(Objects::nonNull).forEach(notificationFactory -> {
            NotificationService notificationService = null;
            try {
                notificationService = notificationFactory.create(privateKeyStore);
            } catch (ServerResourceException ex) {
                LOGGER.error("unable to create NotificationService", ex);
            }
            if (notificationService != null) {
                notificationServices.add(notificationService);
            }
        });
        init();
    }

    public void shutdown() {
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdownNow();
        }
    }

    public void sendNotifications(List<Notification> notifications) {
        if (isNotificationFeatureAvailable()) {
            notifications.stream().filter(Objects::nonNull).forEach(
                    notification -> notificationServices.stream()
                            .filter(Objects::nonNull).forEach(service -> {
                                try {
                                    service.notify(notification);
                                } catch (ServerResourceException ex) {
                                    LOGGER.error("unable to send notification", ex);
                                }
                            }));
        }
    }

    public boolean isNotificationFeatureAvailable () {
        return !notificationServices.isEmpty();
    }

    private boolean enableScheduledNotifications() {
        // Enable notification scheduler if a NotificationService is available and NotificationTasks exist
        return isNotificationFeatureAvailable() && this.notificationTasks != null && !this.notificationTasks.isEmpty();
    }

    public List<String> getLoadedNotificationServices() {
        List<String> loadedNotificationServices = new ArrayList<>();
        notificationServices.forEach(notificationService -> loadedNotificationServices.add(notificationService.getClass().getName()));
        return loadedNotificationServices;
    }

    public Authority getNotificationUserAuthority() {
        return notificationUserAuthority;
    }

    class PeriodicNotificationsSender implements Runnable {

        @Override
        public void run() {

            LOGGER.info("PeriodicNotificationsSender: Starting notifications thread...");

            // Note that ordering in the list of notifications is important as a NotificationTask might depend on a previous
            // NotificationTask running
            for (NotificationTask notificationTask: notificationTasks) {
                try {
                    List<Notification> notifications = notificationTask.getNotifications(notificationObjectStore);
                    notifications.stream()
                            .filter(Objects::nonNull)
                            .forEach(notification -> notificationServices.forEach(service -> {
                                try {
                                    service.notify(notification);
                                } catch (ServerResourceException ex) {
                                    LOGGER.error("PeriodicNotificationsSender: unable to send notification", ex);
                                }
                            }));
                    LOGGER.info("PeriodicNotificationsSender: Sent {} notifications of type {}",
                            notifications.size(), notificationTask.getDescription());
                } catch (Throwable t) {
                    LOGGER.error("PeriodicNotificationsSender: unable to send {}", notificationTask.getDescription(), t);
                }
            }

            LOGGER.info("PeriodicNotificationsSender: completed");
        }
    }
}
