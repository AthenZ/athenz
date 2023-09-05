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
import com.yahoo.athenz.common.metrics.MetricFactory;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.yahoo.athenz.common.ServerCommonConsts.METRIC_DEFAULT_FACTORY_CLASS;

public class MetricNotificationServiceFactory implements NotificationServiceFactory {

    public static final String NOTIFICATION_PROP_METRIC_FACTORY_CLASS = "athenz.notification.metric_factory_class";

    private final static Logger LOG = LoggerFactory.getLogger(MetricNotificationServiceFactory.class);

    @Override
    public NotificationService create() {
        return new MetricNotificationService(loadMetricObject());
    }

    Metric loadMetricObject() {

        String metricFactoryClass = System.getProperty(NOTIFICATION_PROP_METRIC_FACTORY_CLASS,
                METRIC_DEFAULT_FACTORY_CLASS);
        MetricFactory metricFactory;
        try {
            metricFactory = (MetricFactory) Class.forName(metricFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOG.error("Invalid MetricFactory class: {}", metricFactoryClass, ex);
            throw new IllegalArgumentException("Invalid metric class", ex);
        }

        LOG.info("Loaded MetricFactory for receiving notification metrics: {}", metricFactoryClass);
        // create our metric
        return metricFactory.create();
    }

}
