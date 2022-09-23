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
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MetricNotificationService implements NotificationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetricNotificationService.class);
    public static final String METRIC_NOTIFICATION_TYPE_KEY             = "notif_type";
    public static final String METRIC_NOTIFICATION_DOMAIN_KEY           = "domain";
    public static final String METRIC_NOTIFICATION_ZTS_KEY              = "zts_url";
    public static final String METRIC_NOTIFICATION_ROLE_KEY             = "role";
    public static final String METRIC_NOTIFICATION_EXPIRY_DAYS_KEY      = "expiry_days";
    public static final String METRIC_NOTIFICATION_UPDATE_DAYS_KEY      = "update_days";
    public static final String METRIC_NOTIFICATION_REVIEW_DAYS_KEY      = "review_days";
    public static final String METRIC_NOTIFICATION_ZTS_HEALTH_MSG_KEY   = "zts_health_msg";
    public static final String METRIC_NOTIFICATION_SERVICE_KEY          = "service";
    public static final String METRIC_NOTIFICATION_PROVIDER_KEY         = "provider";
    public static final String METRIC_NOTIFICATION_INSTANCE_ID_KEY      = "instance_id";
    public static final String METRIC_NOTIFICATION_MEMBER_KEY           = "member";
    public static final String METRIC_NOTIFICATION_GROUP_KEY            = "group";
    public static final String METRIC_NOTIFICATION_REASON_KEY           = "reason";
    public static final String METRIC_NOTIFICATION_REQUESTER_KEY        = "requester";

    private final Metric metric;

    public MetricNotificationService(Metric metric) {
        this.metric = metric;
    }

    @Override
    public boolean notify(Notification notification) {
        NotificationMetric notificationAsMetrics = notification.getNotificationAsMetrics(Timestamp.fromMillis(System.currentTimeMillis()));
        if (notificationAsMetrics == null) {
            return false;
        }

        for (String[] attributesFlatArray: notificationAsMetrics.getAttributes()) {
            // Increment metric
            metric.increment("athenz_notification", attributesFlatArray);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Notification Metric sent: {}", String.join(",", attributesFlatArray));
            }
        }

        return true;
    }
}
