/*
 * Copyright The Athenz Authors
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

import com.yahoo.athenz.common.metrics.Metric;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class OpenTelemetryMetricFactoryTest {
    private OpenTelemetryMetricFactory factory;

    @BeforeMethod
    public void setUp() {
        factory = new OpenTelemetryMetricFactory();
    }

    @Test
    public void testCreate() {
        Metric metric = factory.create();
        assertNotNull(metric);
        assertTrue(metric instanceof OpenTelemetryMetric);
    }

    @Test
    public void testGetInstance() {
        Metric metric = factory.create();
        assertNotNull(metric);
        assertTrue(metric instanceof OpenTelemetryMetric);

        Metric anotherMetric = OpenTelemetryMetricFactory.getInstance();
        assertTrue(anotherMetric instanceof OpenTelemetryMetric);

        assertTrue(metric == anotherMetric);
    }
}
