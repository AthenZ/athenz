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

package io.athenz.server.aws.common.notification.impl;

import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationEmail;
import com.yahoo.athenz.common.server.notification.NotificationMetric;
import com.yahoo.athenz.common.server.notification.NotificationConverterCommon;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zts.ZTSClientNotification;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static io.athenz.server.aws.common.notification.impl.AWSZTSHealthNotificationTask.ZTS_PROP_NOTIFICATION_AWS_HEALTH_DOMAIN;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class AWSZTSHealthNotificationTaskTest {
    private ZTSClientNotification ztsClientNotification;
    private RolesProvider rolesProvider;
    private final String userDomainPrefix = "user.";
    private final String serverName = "testServer";
    private final NotificationConverterCommon notificationConverterCommon = new NotificationConverterCommon(null);

    @BeforeClass
    public void setup() {
        rolesProvider = Mockito.mock(RolesProvider.class);
        ztsClientNotification = Mockito.mock(ZTSClientNotification.class);
    }

    @Test
    public void testNoNotifications() {
        AWSZTSHealthNotificationTask awsztsHealthNotificationTask = new AWSZTSHealthNotificationTask(
                ztsClientNotification,
                rolesProvider,
                userDomainPrefix,
                serverName,
                notificationConverterCommon);

        List<Notification> notifications = awsztsHealthNotificationTask.getNotifications();
        assertEquals(notifications.size(), 0);
    }

    @Test
    public void testGetNotifications() {
        System.setProperty(ZTS_PROP_NOTIFICATION_AWS_HEALTH_DOMAIN, "testDomain");

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

        when(rolesProvider.getRolesByDomain("testDomain")).thenReturn(roles);
        when(rolesProvider.getRole("testDomain", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenThrow(new UnsupportedOperationException());
        AWSZTSHealthNotificationTask awsztsHealthNotificationTask = new AWSZTSHealthNotificationTask(
                clientNotification,
                rolesProvider,
                userDomainPrefix,
                serverName,
                notificationConverterCommon);

        List<Notification> notifications = awsztsHealthNotificationTask.getNotifications();
        assertEquals(notifications.size(), 1);
        assertTrue(notifications.get(0).getRecipients().contains("user.test1"));
        assertTrue(notifications.get(0).getRecipients().contains("user.test2"));
        Timestamp expiration = Timestamp.fromMillis(clientNotification.getExpiration() * 1000);
        assertEquals(notifications.get(0).getDetails().get("awsZtsHealth"),
                "zts.url;testDomain;role;" + expiration + ";Fail to get token of type AWS. ");
        assertEquals(notifications.get(0).getDetails().get("affectedZts"), "testServer");

        System.clearProperty(ZTS_PROP_NOTIFICATION_AWS_HEALTH_DOMAIN);
    }

    @Test
    public void testDescription() {
        AWSZTSHealthNotificationTask awsztsHealthNotificationTask = new AWSZTSHealthNotificationTask(
                ztsClientNotification,
                rolesProvider,
                userDomainPrefix,
                serverName,
                notificationConverterCommon);

        String description = awsztsHealthNotificationTask.getDescription();
        assertEquals(description, "ZTS On AWS Health Notification");
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

        Notification notification = new Notification(Notification.Type.AWS_ZTS_HEALTH);
        notification.setDetails(details);
        AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter converter
                = new AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter(new NotificationConverterCommon(null));
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
        Notification notification = new Notification(Notification.Type.AWS_ZTS_HEALTH);
        AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter converter
                = new AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter(notificationConverterCommon);
        NotificationEmail notificationAsEmail = converter.getNotificationAsEmail(notification);
        String subject = notificationAsEmail.getSubject();
        Assert.assertEquals(subject, "AWS ZTS Failure Notification");
    }

    @Test
    public void testGetNotificationAsMetric() {
        Timestamp currentTimeStamp = Timestamp.fromCurrentTime();
        Timestamp twentyFiveDaysFromNow = Timestamp.fromMillis(currentTimeStamp.millis()
                + TimeUnit.MILLISECONDS.convert(25, TimeUnit.DAYS));

        Map<String, String> details = new HashMap<>();
        details.put(NOTIFICATION_DETAILS_AFFECTED_ZTS, "affected zts");
        details.put(NOTIFICATION_DETAILS_AWS_ZTS_HEALTH,
                "zts.url;domain0;role0;" + twentyFiveDaysFromNow + ";Error message");

        Notification notification = new Notification(Notification.Type.AWS_ZTS_HEALTH);
        notification.setDetails(details);

        AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToMetricConverter converter =
                new AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToMetricConverter();
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
