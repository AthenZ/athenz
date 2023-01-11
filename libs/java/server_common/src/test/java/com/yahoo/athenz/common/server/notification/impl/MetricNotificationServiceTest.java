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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

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

        Notification notification = new Notification();
        notification.setNotificationToMetricConverter(notificationToMetricConverter);

        boolean notify = metricNotificationService.notify(notification);
        assertTrue(notify);

        ArgumentCaptor<String> captorMetric = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String[]> captorAttributes = ArgumentCaptor.forClass(String[].class);

        Mockito.verify(metric, Mockito.times(2))
                .increment(captorMetric.capture(), captorAttributes.capture());

        assertEquals(2, captorMetric.getAllValues().size());
        assertEquals("athenz_notification", captorMetric.getAllValues().get(0));
        assertEquals("athenz_notification", captorMetric.getAllValues().get(1));

        // Mockito captures all varargs arguments in a single array

        assertEquals(2, captorAttributes.getAllValues().size());

        String[] collectedAttributes1 = captorAttributes.getAllValues().get(0);
        assertEquals(6, collectedAttributes1.length);
        List<String> expectedAttributes1 = Arrays.asList(
                "key1", "attribute11",
                "key2", "attribute12",
                "key3", "attribute13");
        assertEquals(expectedAttributes1, List.of(collectedAttributes1));

        String[] collectedAttributes2 = captorAttributes.getAllValues().get(1);
        assertEquals(6, collectedAttributes2.length);
        List<String> expectedAttributes2 = Arrays.asList(
                "key1", "attribute21",
                "key2", "attribute22",
                "key3", "attribute23");
        assertEquals(expectedAttributes2, List.of(collectedAttributes2));
    }
}
