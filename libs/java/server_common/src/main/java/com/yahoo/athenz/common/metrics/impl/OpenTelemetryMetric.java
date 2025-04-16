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
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.common.Attributes;

public class OpenTelemetryMetric implements Metric {
    final Meter meter;
    final DoubleHistogram histogram;

    private static final String REQUEST_DOMAIN_NAME = "requestDomainName";
    private static final String PRINCIPAL_DOMAIN_NAME = "principalDomainName";
    private static final String HTTP_METHOD_NAME = "httpMethodName";
    private static final String HTTP_STATUS = "httpStatus";
    private static final String API_NAME = "apiName";

    public OpenTelemetryMetric(OpenTelemetry openTelemetry, final String histogramName) {
        meter = openTelemetry.getMeter("meter");
        histogram = meter.histogramBuilder(histogramName).build();
    }

    @Override
    public void increment(String metric) {
        LongCounter counter = meter.counterBuilder(metric).build();
        counter.add(1);
    }

    @Override
    public void increment(String metric, String requestDomainName) {
        increment(metric, requestDomainName, 1);
    }

    @Override
    public void increment(String metric, String requestDomainName, int count) {
        LongCounter counter = meter.counterBuilder(metric).build();
        Attributes attributes = Attributes.builder()
                .put(REQUEST_DOMAIN_NAME, requestDomainName)
                .build();
        counter.add(count, attributes);
    }

    @Override
    public void increment(String metric, String requestDomainName, String principalDomainName) {
        increment(metric, requestDomainName, principalDomainName, 1);
    }

    @Override
    public void increment(String metric, String requestDomainName, String principalDomainName, String httpMethod,
                          int httpStatus, String apiName) {
        LongCounter counter = meter.counterBuilder(metric).build();
        Attributes attributes = Attributes.builder()
                .put(REQUEST_DOMAIN_NAME, requestDomainName)
                .put(PRINCIPAL_DOMAIN_NAME, principalDomainName)
                .put(HTTP_METHOD_NAME, httpMethod)
                .put(HTTP_STATUS, Integer.toString(httpStatus))
                .put(API_NAME, apiName)
                .build();
        counter.add(1, attributes);
    }

    @Override
    public void increment(String metric, String requestDomainName, String principalDomainName, int count) {
        LongCounter counter = meter.counterBuilder(metric).build();
        Attributes attributes = Attributes.builder()
                .put(REQUEST_DOMAIN_NAME, requestDomainName)
                .put(PRINCIPAL_DOMAIN_NAME, principalDomainName)
                .build();
        counter.add(count, attributes);
    }

    @Override
    public void increment(String metric, String ...attributes) {
        LongCounter counter = meter.counterBuilder(metric).build();
        io.opentelemetry.api.common.AttributesBuilder attributesBuilder = Attributes.builder();
        for (int i = 0; i < attributes.length; i += 2) {
            if (i + 1 >= attributes.length) {
                break;
            }
            attributesBuilder.put(attributes[i], attributes[i + 1]);
        }
        counter.add(1, attributesBuilder.build());
    }

    @Override
    public Object startTiming(String metric, String requestDomainName) {
        return new Timer(System.currentTimeMillis());
    }

    @Override
    public Object startTiming(String metric, String requestDomainName, String principalDomainName,
                              String httpMethod, String apiName) {
        return new Timer(System.currentTimeMillis());
    }

    @Override
    public void stopTiming(Object timerMetric) {
        //not necessary method
    }

    @Override
    public void stopTiming(Object timerMetric, String requestDomainName, String principalDomainName) {
        stopTiming(timerMetric, requestDomainName, principalDomainName, null, -1, null);
    }

    @Override
    public void stopTiming(Object timerMetric, String requestDomainName, String principalDomainName,
                           String httpMethod, int httpStatus, String apiName) {
        Timer timer = (Timer) timerMetric;
        long duration = System.currentTimeMillis() - timer.getStart();
        AttributesBuilder builder = Attributes.builder()
                .put(REQUEST_DOMAIN_NAME, requestDomainName)
                .put(PRINCIPAL_DOMAIN_NAME, principalDomainName);
        if (httpMethod != null) {
            builder.put(HTTP_METHOD_NAME, httpMethod);
        }
        if (httpStatus != -1) {
            builder.put(HTTP_STATUS, Integer.toString(httpStatus));
        }
        if (apiName != null) {
            builder.put(API_NAME, apiName);
        }
        histogram.record(duration, builder.build());
    }

    @Override
    public void flush() {
        //doesn't require flushing
    }

    @Override
    public void quit() {
        //don't need to quit anything
    }

    static class Timer {
        private final long start;

        public Timer(long start) {
            this.start = start;
        }
        public long getStart() {
            return start;
        }
    }
}
