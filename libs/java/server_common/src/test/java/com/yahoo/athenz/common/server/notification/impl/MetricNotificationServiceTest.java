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

package com.yahoo.athenz.common.server.notification.impl;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationMetric;
import com.yahoo.athenz.common.server.notification.NotificationToMetricConverter;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class MetricNotificationServiceTest {

    @Test
    public void testNotify() {
        Metric metric = Mockito.mock(Metric.class);
        MetricNotificationService metricNotificationService = new MetricNotificationService(metric);

        String[] attributesList1 = new String[] {
                "key1", "attribute11",
                "key2", "attribute12",
                "key3", "attribute13"
        };

        String[] attributesList2 = new String[] {
                "key1", "attribute21",
                "key2", "attribute22",
                "key3", "attribute23"
        };

        List<String[]> attributes = new ArrayList<>();
        attributes.add(attributesList1);
        attributes.add(attributesList2);

        NotificationToMetricConverter notificationToMetricConverter = Mockito.mock(NotificationToMetricConverter.class);
        Mockito.when(notificationToMetricConverter.getNotificationAsMetrics(Mockito.any(), Mockito.any())).thenReturn(new NotificationMetric(attributes));

        Notification notification = new Notification(Notification.Type.ROLE_MEMBER_EXPIRY);
        notification.setNotificationToMetricConverter(notificationToMetricConverter);

        boolean notify = metricNotificationService.notify(notification);
        assertTrue(notify);

        ArgumentCaptor<String> captorMetric = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String[]> captorAttributes = ArgumentCaptor.forClass(String[].class);

        Mockito.verify(metric, Mockito.times(2))
                .increment(captorMetric.capture(), captorAttributes.capture());

        assertEquals(captorMetric.getAllValues().size(), 2);
        assertEquals(captorMetric.getAllValues().get(0), "athenz_notification");
        assertEquals(captorMetric.getAllValues().get(1), "athenz_notification");

        // Mockito captures all varargs arguments in a single array

        assertEquals(captorAttributes.getAllValues().size(), 2);

        String[] collectedAttributes1 = captorAttributes.getAllValues().get(0);
        assertEquals(collectedAttributes1.length, 6);
        List<String> expectedAttributes1 = Arrays.asList(
                "key1", "attribute11",
                "key2", "attribute12",
                "key3", "attribute13");
        assertEquals(List.of(collectedAttributes1), expectedAttributes1);

        String[] collectedAttributes2 = captorAttributes.getAllValues().get(1);
        assertEquals(collectedAttributes2.length, 6);
        List<String> expectedAttributes2 = Arrays.asList(
                "key1", "attribute21",
                "key2", "attribute22",
                "key3", "attribute23");
        assertEquals(List.of(collectedAttributes2), expectedAttributes2);
    }
}
