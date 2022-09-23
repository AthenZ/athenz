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
    public void increment(String metric, String requestDomainName) {
    }

    @Override
    public void increment(String metric, String requestDomainName, String principalDomainName) {
    }

    @Override
    public void increment(String metric, String requestDomainName, int count) {
    }

    @Override
    public void increment(String metric, String requestDomainName, String principalDomainName, int count) {
    }

    @Override
    public void increment(String metric, String requestDomainName, String principalDomainName, String httpMethod, int httpStatus, String apiName) {
    }

    @Override
    public void increment(String metric, final String... attributes) {
    }

    @Override
    public void increment(String metric, long change, final String... attributes) {
    }

    @Override
    public Object startTiming(String metric, String requestDomainName) {
        return null;
    }

    @Override
    public Object startTiming(String metric, String requestDomainName, String principalDomainName) {
        return null;
    }

    @Override
    public Object startTiming(String metric, String requestDomainName, String principalDomainName, String httpMethod, String apiName) {
        return null;
    }

    @Override
    public void stopTiming(Object timerMetric) {
    }

    @Override
    public void stopTiming(Object timerMetric, String requestDomainName, String principalDomainName) {
    }

    @Override
    public void stopTiming(Object timerMetric, String requestDomainName, String principalDomainName, String httpMethod, int httpStatus, String apiName) {
    }

    @Override
    public void flush() {
    }

    @Override
    public void quit() {
    }
}
