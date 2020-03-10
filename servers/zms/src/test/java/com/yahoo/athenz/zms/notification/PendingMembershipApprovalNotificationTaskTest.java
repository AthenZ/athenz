/*
 * Copyright 2020 Verizon Media
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
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.ZMSTestUtils;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER;
import static com.yahoo.athenz.zms.notification.NotificationManagerTest.getNotificationManager;
import static org.testng.Assert.assertEquals;

public class PendingMembershipApprovalNotificationTaskTest {
    @Test
    public void testSendPendingMembershipApprovalReminders() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        Mockito.when(dbsvc.getRoleExpiryMembers()).thenReturn(null);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getPendingMembershipApproverRoles())
                .thenReturn(null)
                .thenReturn(Collections.singleton("user.joe"));

        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        ZMSTestUtils.sleep(1000);

        PendingMembershipApprovalNotificationTask reminder = new PendingMembershipApprovalNotificationTask(dbsvc, 0, "", USER_DOMAIN_PREFIX);
        List<Notification> notifications = reminder.getNotifications();

        // Verify contents of notification is as expected
        assertEquals(notifications.size(), 1);
        Notification expectedNotification = new Notification(NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER);
        expectedNotification.addRecipient("user.joe");
        assertEquals(notifications.get(0), expectedNotification);
        notificationManager.shutdown();
    }
}
