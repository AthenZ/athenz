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

import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.assertEquals;

public class NotificationTaskTest {

    @Test
    public void testNotificationTask() {
        NotificationTask task = new NotificationTask() {
            @Override
            public List<Notification> getNotifications() {
                return List.of(new Notification(Notification.Type.ROLE_MEMBER_EXPIRY));
            }

            @Override
            public String getDescription() {
                return "Test Notification Task";
            }
        };

        assertEquals(task.getNotifications(), List.of(new Notification(Notification.Type.ROLE_MEMBER_EXPIRY)));
        assertEquals(task.getNotifications(null), List.of(new Notification(Notification.Type.ROLE_MEMBER_EXPIRY)));
        assertEquals(task.getNotifications(Mockito.mock(NotificationObjectStore.class)),
                List.of(new Notification(Notification.Type.ROLE_MEMBER_EXPIRY)));
        assertEquals(task.getDescription(), "Test Notification Task");

    }
}
