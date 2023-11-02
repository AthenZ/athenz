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

package com.yahoo.athenz.zts.notification;

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationEmail;
import com.yahoo.athenz.common.server.notification.NotificationMetric;
import com.yahoo.athenz.common.server.notification.NotificationToEmailConverterCommon;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zts.ZTSClientNotification;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.ZTSTestUtils;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;
import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertEquals;

public class AWSZTSHealthNotificationTaskTest {
    private ZTSClientNotification ztsClientNotification;
    private DataStore dataStore;
    private final String userDomainPrefix = "user.";
    private final String serverName = "testServer";
    private final NotificationToEmailConverterCommon notificationToEmailConverterCommon = new NotificationToEmailConverterCommon(null);

    @BeforeClass
    public void setup() {
        dataStore = Mockito.mock(DataStore.class);
        ztsClientNotification = Mockito.mock(ZTSClientNotification.class);
    }

    @Test
    public void testNoNotifications() {
        AWSZTSHealthNotificationTask awsztsHealthNotificationTask = new AWSZTSHealthNotificationTask(
                ztsClientNotification,
                dataStore,
                userDomainPrefix,
                serverName,
                notificationToEmailConverterCommon);

        List<Notification> notifications = awsztsHealthNotificationTask.getNotifications();
        assertEquals(0, notifications.size());
    }

    @Test
    public void testGetNotifications() {
        System.setProperty(ZTSConsts.ZTS_PROP_NOTIFICATION_AWS_HEALTH_DOMAIN, "testDomain");

        ZTSClientNotification clientNotification = new ZTSClientNotification(
                "zts.url",
                "role",
                "AWS",
                1592346376,
                false,
                "testDomain"
        );

        RoleMember roleMember1 = new RoleMember();
        roleMember1.setMemberName("user.test1");
        RoleMember roleMember2 = new RoleMember();
        roleMember2.setMemberName("user.test2");
        List<RoleMember> roleMembers = new ArrayList<>();

        roleMembers.add(roleMember1);
        roleMembers.add(roleMember2);
        Role adminRole = new Role();
        adminRole.setRoleMembers(roleMembers);
        adminRole.setName("testDomain:role.admin");

        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);

        when(dataStore.getRolesByDomain("testDomain")).thenReturn(roles);
        when(dataStore.getRole("testDomain", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenThrow(new UnsupportedOperationException());
        AWSZTSHealthNotificationTask awsztsHealthNotificationTask = new AWSZTSHealthNotificationTask(
                clientNotification,
                dataStore,
                userDomainPrefix,
                serverName,
                notificationToEmailConverterCommon);

        List<Notification> notifications = awsztsHealthNotificationTask.getNotifications();
        assertEquals(1, notifications.size());
        assertTrue(notifications.get(0).getRecipients().contains("user.test1"));
        assertTrue(notifications.get(0).getRecipients().contains("user.test2"));
        Timestamp expiration = Timestamp.fromMillis(clientNotification.getExpiration() * 1000);
        assertEquals("zts.url;testDomain;role;" + expiration + ";Fail to get token of type AWS. ", notifications.get(0).getDetails().get("awsZtsHealth"));
        assertEquals("testServer", notifications.get(0).getDetails().get("affectedZts"));

        System.clearProperty(ZTSConsts.ZTS_PROP_NOTIFICATION_AWS_HEALTH_DOMAIN);
    }

    @Test
    public void testDescription() {
        AWSZTSHealthNotificationTask awsztsHealthNotificationTask = new AWSZTSHealthNotificationTask(
                ztsClientNotification,
                dataStore,
                userDomainPrefix,
                serverName,
                notificationToEmailConverterCommon);

        String description = awsztsHealthNotificationTask.getDescription();
        assertEquals("ZTS On AWS Health Notification", description);
    }

    @Test
    public void testGetEmailBody() {
        System.setProperty("athenz.notification_workflow_url", "https://athenz.example.com/workflow");
        System.setProperty("athenz.notification_support_text", "#Athenz slack channel");
        System.setProperty("athenz.notification_support_url", "https://link.to.athenz.channel.com");

        Map<String, String> details = new HashMap<>();
        details.put(NOTIFICATION_DETAILS_AFFECTED_ZTS, "affected zts");
        details.put(NOTIFICATION_DETAILS_AWS_ZTS_HEALTH,
                "zts.url;domain0;role0;Sun Mar 15 15:08:07 IST 2020;Error message");

        Notification notification = new Notification();
        notification.setDetails(details);
        AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter converter = new AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter(new NotificationToEmailConverterCommon(null));
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);

        String body = notificationAsEmail.getBody();
        assertNotNull(body);
        assertTrue(body.contains("zts.url"));
        assertTrue(body.contains("domain0"));
        assertTrue(body.contains("role0"));
        assertTrue(body.contains("Sun Mar 15 15:08:07 IST 2020"));
        assertTrue(body.contains("Error message"));

        // Make sure support text and url do appear

        assertTrue(body.contains("slack"));
        assertTrue(body.contains("link.to.athenz.channel.com"));

        System.clearProperty("athenz.notification_workflow_url");
        System.clearProperty("notification_support_text");
        System.clearProperty("notification_support_url");
    }

    @Test
    public void getEmailSubject() {
        Notification notification = new Notification();
        AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter converter = new AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter(notificationToEmailConverterCommon);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        Assert.assertEquals(subject, "AWS ZTS Failure Notification");
    }

    @Test
    public void testGetNotificationAsMetric() {
        Timestamp currentTimeStamp = Timestamp.fromCurrentTime();
        Timestamp twentyFiveDaysFromNow = ZTSTestUtils.addDays(currentTimeStamp, 25);

        Map<String, String> details = new HashMap<>();
        details.put(NOTIFICATION_DETAILS_AFFECTED_ZTS, "affected zts");
        details.put(NOTIFICATION_DETAILS_AWS_ZTS_HEALTH,
                "zts.url;domain0;role0;" + twentyFiveDaysFromNow + ";Error message");

        Notification notification = new Notification();
        notification.setDetails(details);

        AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToMetricConverter converter = new AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToMetricConverter();
        NotificationMetric notificationAsMetrics = converter.getNotificationAsMetrics(notification, currentTimeStamp);

        String[] expectedRecord = new String[]{
                METRIC_NOTIFICATION_TYPE_KEY, "aws_zts_health",
                METRIC_NOTIFICATION_ZTS_KEY, "zts.url",
                METRIC_NOTIFICATION_DOMAIN_KEY, "domain0",
                METRIC_NOTIFICATION_ROLE_KEY, "role0",
                METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, "25",
                METRIC_NOTIFICATION_ZTS_HEALTH_MSG_KEY, "Error message"
        };

        List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(expectedRecord);

        assertEquals(new NotificationMetric(expectedAttributes), notificationAsMetrics);
    }
}
