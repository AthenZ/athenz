/*
 * Copyright 2016 Yahoo Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.common.metrics.impl;

import static org.testng.Assert.*;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;
import com.yahoo.athenz.common.metrics.impl.NoOpMetricFactory;

public class MetricsTest {

    @Test
    public void testFactoryNoOpMetric() throws Exception {

        MetricFactory factory = new NoOpMetricFactory();
        Metric metric = factory.create();
        
        assertEquals(metric.getClass().getName(), Class.forName("com.yahoo.athenz.common.metrics.impl.NoOpMetric").getName());

        metric.increment("metric1");
        metric.increment("metric1", "athenz");
        metric.increment("metric1", "athenz", 3);
        metric.increment("metric1", "athenz", "sports");
        metric.increment("metric1", "athenz", "sports", 3);

        assertNull(metric.startTiming("metric1", "athenz"));
        assertNull(metric.startTiming("metric1", "athenz", "sports"));

        metric.stopTiming("metric1");
        metric.stopTiming("metric1", "athenz", "sports");

        metric.flush();
        metric.quit();
    }

    @Test
    public void testMetricInterface() {

        Metric metric = new Metric() {

            @Override
            public void increment(String metric) {
            }

            @Override
            public void increment(String metric, String requestDomainName) {
            }

            @Override
            public void increment(String metric, String requestDomainName, int count) {
            }

            @Override
            public Object startTiming(String metric, String requestDomainName) {
                return null;
            }

            @Override
            public void stopTiming(Object timerMetric) {
            }

            @Override
            public void flush() {
            }

            @Override
            public void quit() {
            }
        };

        metric.increment("metric1");
        //metric.increment("metric1", "athenz");
        metric.increment("metric1", "athenz", 3);
        metric.increment("metric1", "athenz", "sports");
        metric.increment("metric1", "athenz", "sports", 3);

        //assertNull(metric.startTiming("metric1", "athenz"));
        assertNull(metric.startTiming("metric1", "athenz", "sports"));

        //metric.stopTiming("metric1");
        metric.stopTiming("metric1", "athenz", "sports");
        metric.flush();
        metric.quit();
    }
}
