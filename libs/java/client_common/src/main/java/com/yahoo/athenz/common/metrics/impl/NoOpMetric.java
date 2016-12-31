/**
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

import com.yahoo.athenz.common.metrics.Metric;

public class NoOpMetric implements Metric {

    /**
     * Constructs a new NoOpMetric object in which all methods are stubs.
     * No metrics are recorded with this implementation.
     */
    public NoOpMetric() {
    }

    @Override
    public void increment(String metric) {
    }

    @Override
    public void increment(String metric, String domainName) {
    }

    @Override
    public void increment(String metric, String domainName, int count) {
    }

    @Override
    public Object startTiming(String metric, String domainName) {
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
}
