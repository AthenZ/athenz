/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.metrics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.yahoo.athenz.common.ServerCommonConsts.METRIC_DEFAULT_FACTORY_CLASS;

public class Utils {

    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

    public static final String PROP_METRIC_FACTORY_CLASS = "athenz.jetty.container.metric_factory_class";

    public static Metric getMetric() {
        final String metricFactoryClass = System.getProperty(PROP_METRIC_FACTORY_CLASS,
                METRIC_DEFAULT_FACTORY_CLASS);

        MetricFactory metricFactory;
        try {
            metricFactory = (MetricFactory) Class.forName(metricFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOGGER.error("Invalid MetricFactory class: {}", metricFactoryClass, ex);
            throw new IllegalArgumentException("Invalid metric class", ex);
        }

        return metricFactory.create();
    }
}


