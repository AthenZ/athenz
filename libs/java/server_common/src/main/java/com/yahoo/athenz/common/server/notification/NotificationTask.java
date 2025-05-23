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

import java.util.List;

public interface NotificationTask {

    /**
     * Get the list of notifications to be submitted to the notification service.
     * If the notification object store object is not null, the task si responsible
     * for registering any role/group review arns for all principals.
     * @param notificationObjectStore object store
     * @return list of notifications
     */
    default List<Notification> getNotifications(NotificationObjectStore notificationObjectStore) {
        return getNotifications();
    }

    /**
     * @return list of notifications
     */
    @Deprecated
    List<Notification> getNotifications();

    /**
     * @return description of the NotificationTask (for logging purposes)
     */
    String getDescription();
}
