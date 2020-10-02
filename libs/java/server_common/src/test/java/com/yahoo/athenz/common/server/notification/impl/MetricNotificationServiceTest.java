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

package com.yahoo.athenz.common.server.notification.impl;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.notification.Notification;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;

import static org.testng.AssertJUnit.assertTrue;

public class MetricNotificationServiceTest {

    @Test
    public void testNotify() {
        Metric metric = Mockito.mock(Metric.class);
        MetricNotificationService metricNotificationService = new MetricNotificationService(metric);

        Map<String, String> details = new HashMap<>();
        details.put("key1", "attribute1");
        details.put("key2", "attribute2");
        details.put("key3", "attribute3");

        Notification notification = new Notification();
        notification.setDetails(details);
        notification.setType("testType");

        boolean notify = metricNotificationService.notify(notification);
        assertTrue(notify);

        String[] expectedAttributes = new String[] {
                "key1", "attribute1",
                "key2", "attribute2",
                "key3", "attribute3",
                "notif_type", "testType"
        };

        Mockito.verify(metric, Mockito.times(1))
                .increment("athenz_notification", expectedAttributes);
    }
}
