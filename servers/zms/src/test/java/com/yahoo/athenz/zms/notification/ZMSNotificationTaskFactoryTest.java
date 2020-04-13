/*
 *  Copyright 2020 Verizon Media
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

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.NotificationTask;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.ZMSConsts;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static org.testng.AssertJUnit.assertEquals;

public class ZMSNotificationTaskFactoryTest {

    @Test
    public void testNotificationTasksOrdering() {
        DBService dbsvc = Mockito.mock(DBService.class);
        ZMSNotificationTaskFactory zmsNotificationTaskFactory = new ZMSNotificationTaskFactory(dbsvc, USER_DOMAIN_PREFIX);
        List<NotificationTask> notificationTasks = zmsNotificationTaskFactory.getNotificationTasks();
        assertEquals(3, notificationTasks.size());
        assertEquals(notificationTasks.get(0).getDescription(), "pending membership approvals reminders");
        assertEquals(notificationTasks.get(1).getDescription(), "membership expiration reminders");
        assertEquals(notificationTasks.get(2).getDescription(), "Review before expiration reminder");

    }
}
