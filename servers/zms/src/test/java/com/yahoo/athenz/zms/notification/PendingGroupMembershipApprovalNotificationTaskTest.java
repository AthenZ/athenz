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

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.ZMSTestUtils;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.METRIC_NOTIFICATION_TYPE_KEY;
import static com.yahoo.athenz.zms.notification.ZMSNotificationManagerTest.getNotificationManager;
import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertEquals;

public class PendingGroupMembershipApprovalNotificationTaskTest {
    @Test
    public void testSendPendingGroupMembershipApprovalReminders() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getPendingGroupMembershipApproverRoles(1))
                .thenReturn(null)
                .thenReturn(Collections.singleton("user.joe"));

        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        ZMSTestUtils.sleep(1000);

        PendingGroupMembershipApprovalNotificationTask reminder =
                new PendingGroupMembershipApprovalNotificationTask(dbsvc, 0, "", USER_DOMAIN_PREFIX, new NotificationToEmailConverterCommon(null));
        List<Notification> notifications = reminder.getNotifications();

        // Verify contents of notification is as expected
        assertEquals(notifications.size(), 1);
        Notification expectedNotification = new Notification();
        expectedNotification.setNotificationToEmailConverter(new PendingGroupMembershipApprovalNotificationTask.PendingGroupMembershipApprovalNotificationToEmailConverter(new NotificationToEmailConverterCommon(null)));
        expectedNotification.setNotificationToMetricConverter(new PendingGroupMembershipApprovalNotificationTask.PendingGroupMembershipApprovalNotificationToMetricConverter());
        expectedNotification.addRecipient("user.joe");
        assertEquals(notifications.get(0), expectedNotification);
        notificationManager.shutdown();
    }

    @Test
    public void testGetEmailBody() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");
        details.put("group", "group");
        details.put("member", "user.member1");
        details.put("reason", "test reason");
        details.put("requester", "user.requester");

        Notification notification = new Notification();
        notification.setDetails(details);
        PendingGroupMembershipApprovalNotificationTask.PendingGroupMembershipApprovalNotificationToEmailConverter converter
                = new PendingGroupMembershipApprovalNotificationTask.PendingGroupMembershipApprovalNotificationToEmailConverter(new NotificationToEmailConverterCommon(null));
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("https://athenz.example.com/workflow"));

        // Make sure support text and url do not appear

        assertFalse(body.contains("slack"));
        assertFalse(body.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
    }

    @Test
    public void getEmailSubject() {
        Notification notification = new Notification();
        PendingGroupMembershipApprovalNotificationTask.PendingGroupMembershipApprovalNotificationToEmailConverter converter =
                new PendingGroupMembershipApprovalNotificationTask.PendingGroupMembershipApprovalNotificationToEmailConverter(new NotificationToEmailConverterCommon(null));
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        assertEquals(subject, "Group Membership Approval Reminder Notification");
    }

    @Test
    public void testGetNotificationAsMetric() {
        PendingGroupMembershipApprovalNotificationTask.PendingGroupMembershipApprovalNotificationToMetricConverter converter =
                new PendingGroupMembershipApprovalNotificationTask.PendingGroupMembershipApprovalNotificationToMetricConverter();
        Notification notification = new Notification();
        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification, Timestamp.fromMillis(System.currentTimeMillis()));
        String[] record = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "pending_group_membership_approval"
        };

        List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(record);

        assertEquals(new NotificationMetric(expectedAttributes), notificationAsMetrics);
    }
}
