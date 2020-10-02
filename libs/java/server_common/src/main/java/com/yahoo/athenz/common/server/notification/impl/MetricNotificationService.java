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
import com.yahoo.athenz.common.server.notification.NotificationService;

import java.util.ArrayList;
import java.util.List;

public class MetricNotificationService implements NotificationService {

    private final Metric metric;

    public MetricNotificationService(Metric metric) {
        this.metric = metric;
    }

    @Override
    public boolean notify(Notification notification) {
        // Convert details to flat array
        List<String> attributesList = new ArrayList<>();
        notification.getDetails().forEach((k, v) -> {
            attributesList.add(k);
            attributesList.add(v);
        });

        // add notification type
        attributesList.add("notif_type");
        attributesList.add(notification.getType());

        // Increment metric
        metric.increment("athenz_notification", attributesList.toArray(new String[0]));
        return true;
    }
}
