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

import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.METRIC_NOTIFICATION_REVIEW_DAYS_KEY;
import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertEquals;

public class NotificationMetricTest {

    @Test
    public void testNotificationMetric() {

        NotificationMetric metric1 = new NotificationMetric(Collections.emptyList());
        assertTrue(metric1.equals(metric1));
        assertFalse(metric1.equals(null));
        assertFalse(metric1.equals("null"));

        NotificationMetric metric2 = new NotificationMetric(Collections.emptyList());
        assertTrue(metric1.equals(metric2));
        assertEquals(metric1.hashCode(), metric2.hashCode());

        List<String[]> attributes = new ArrayList<>();
        attributes.add(new String[]{"attr1"});
        NotificationMetric metric3 = new NotificationMetric(attributes);
        assertFalse(metric1.equals(metric3));
    }

    @Test
    public void testNotificationMetricToString() {
        final String[] expectedRecord1 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "25"
        };

        final String[] expectedRecord2 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.jane",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "20"
        };

        final List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(expectedRecord1);
        expectedAttributes.add(expectedRecord2);

        NotificationMetric notificationMetric = new NotificationMetric(expectedAttributes);
        String expectedToString = "NotificationMetric{" +
                "attributes=" +
                "notif_type,domain_role_membership_review,domain,dom1,member,user.joe,role,role1,review_days,25;" +
                "notif_type,domain_role_membership_review,domain,dom1,member,user.jane,role,role1,review_days,20;}";
        assertEquals(expectedToString, notificationMetric.toString());
    }

    @Test
    public void testNotificationMetricHashCode() {
        final String[] expectedRecord1 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "25"
        };

        final String[] expectedRecord2 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.jane",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "20"
        };

        final List<String[]> expectedAttributes = new ArrayList<>();
        expectedAttributes.add(expectedRecord1);
        expectedAttributes.add(expectedRecord2);

        final NotificationMetric notificationMetric = new NotificationMetric(expectedAttributes);
        assertEquals(-2000085904, notificationMetric.hashCode());

        final String[] expectedRecord3 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "25"
        };

        final String[] expectedRecord4 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.jane",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "20"
        };

        final List<String[]> expectedAttributes2 = new ArrayList<>();
        expectedAttributes2.add(expectedRecord3);
        expectedAttributes2.add(expectedRecord4);

        final NotificationMetric notificationMetric2 = new NotificationMetric(expectedAttributes2);
        assertEquals(-2000085904, notificationMetric2.hashCode());

        // Verify the objects are considered equal
        assertEquals(notificationMetric, notificationMetric2);

        // Now change one of the objects a bit, verify hash change
        final String[] expectedRecord5 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.joe",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "25"
        };

        final String[] expectedRecord6 = new String[] {
                METRIC_NOTIFICATION_TYPE_KEY, "domain_role_membership_review",
                METRIC_NOTIFICATION_DOMAIN_KEY, "dom1",
                METRIC_NOTIFICATION_MEMBER_KEY, "user.jane",
                METRIC_NOTIFICATION_ROLE_KEY, "role1",
                METRIC_NOTIFICATION_REVIEW_DAYS_KEY, "21"
        };

        final List<String[]> expectedAttributes3 = new ArrayList<>();
        expectedAttributes3.add(expectedRecord5);
        expectedAttributes3.add(expectedRecord6);

        final NotificationMetric notificationMetric3 = new NotificationMetric(expectedAttributes3);
        assertEquals(-2000085903, notificationMetric3.hashCode());

        // Verify the objects are considered not equal
        assertNotEquals(notificationMetric, notificationMetric3);
    }
}
