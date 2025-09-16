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
import io.opentelemetry.api.metrics.LongGauge;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.common.Attributes;
import org.eclipse.jetty.util.StringUtil;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class OpenTelemetryMetric implements Metric {
    final Meter meter;
    final DoubleHistogram histogram;
    boolean separateDomainMetrics;

    private static final String TIMER_METRIC_NAME = "timerMetricName";
    private static final String REQUEST_DOMAIN_NAME = "requestDomainName";
    private static final String REQUEST_SERVICE_NAME = "requestServiceName";
    private static final String PRINCIPAL_DOMAIN_NAME = "principalDomainName";
    private static final String HTTP_METHOD_NAME = "httpMethodName";
    private static final String HTTP_STATUS = "httpStatus";
    private static final String API_NAME = "apiName";
    private final Map<String, LongCounter> counters = new ConcurrentHashMap<>();
    private final Map<String, LongGauge> gaugeCounter = new ConcurrentHashMap<>();

    public OpenTelemetryMetric(OpenTelemetry openTelemetry, final String histogramName, boolean separateDomainMetrics) {
        meter = openTelemetry.getMeter("meter");
        histogram = meter.histogramBuilder(histogramName).build();
        this.separateDomainMetrics = separateDomainMetrics;
    }

    @Override
    public void increment(String metric) {
        increment(metric, null, null, null, -1, null, 1);
    }

    @Override
    public void increment(String metric, String requestDomainName) {
        increment(metric, requestDomainName, null, null, -1, null, 1);
    }

    @Override
    public void increment(String metric, String requestDomainName, int count) {
        increment(metric, requestDomainName, null, null, -1, null, count);
    }

    @Override
    public void increment(String metric, String requestDomainName, String principalDomainName) {
        increment(metric, requestDomainName, principalDomainName, null, -1, null, 1);
    }

    @Override
    public void increment(String metric, String requestDomainName, String principalDomainName, String httpMethod,
            int httpStatus, String apiName) {
        increment(metric, requestDomainName, principalDomainName, httpMethod, httpStatus, apiName, 1);
    }

    @Override
    public void increment(String metric, String requestDomainName, String principalDomainName, int count) {
        increment(metric, requestDomainName, principalDomainName, null, -1, null, count);
    }

    void increment(final String metric, final String requestDomainName, final String principalDomainName,
            final String httpMethod, int httpStatus, final String apiName, int count) {
        if (separateDomainMetrics) {
            if (!StringUtil.isEmpty(requestDomainName)) {
                incrementSingleMetric(metric + "_requestDomain", requestDomainName, null, null, -1, null, count);
            }
            if (!StringUtil.isEmpty(principalDomainName)) {
                incrementSingleMetric(metric + "_principalDomain", null, principalDomainName, null, -1, null, count);
            }
            incrementSingleMetric(metric, null, null, httpMethod, httpStatus, apiName, count);
        } else {
            incrementSingleMetric(metric, requestDomainName, principalDomainName, httpMethod, httpStatus, apiName, count);
        }
    }

    void incrementSingleMetric(final String metric, final String requestDomainName, final String principalDomainName,
            final String httpMethod, final int httpStatus, final String apiName, final int count) {
        LongCounter counter = counters.computeIfAbsent(metric, name -> meter.counterBuilder(metric).build());
        AttributesBuilder builder = Attributes.builder();
        addAttributeIfNotNull(builder, REQUEST_DOMAIN_NAME, requestDomainName);
        addAttributeIfNotNull(builder, PRINCIPAL_DOMAIN_NAME, principalDomainName);
        addAttributeIfNotNull(builder, HTTP_METHOD_NAME, httpMethod);
        addAttributeIfNotNull(builder, API_NAME, apiName);
        addAttributeIfNotMinusOne(builder, HTTP_STATUS, httpStatus);
        counter.add(count, builder.build());
    }

    void addAttributeIfNotNull(AttributesBuilder builder, String key, String value) {
        if (!StringUtil.isEmpty(value)) {
            builder.put(key, value);
        }
    }

    void addAttributeIfNotMinusOne(AttributesBuilder builder, String key, int value) {
        if (value != -1) {
            builder.put(key, Integer.toString(value));
        }
    }

    @Override
    public void increment(String metric, String ...attributes) {
        LongCounter counter = counters.computeIfAbsent(metric, name -> meter.counterBuilder(metric).build());
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
    public void setGauge(String metric, String requestDomainName, String requestServiceName, long value) {
        LongGauge longGauge = gaugeCounter.computeIfAbsent(metric, name -> meter.gaugeBuilder(metric).ofLongs().build());
        Attributes attributes = Attributes.builder()
                .put(REQUEST_DOMAIN_NAME, requestDomainName)
                .put(REQUEST_SERVICE_NAME, requestServiceName)
                .build();
        longGauge.set(value, attributes);
    }

    @Override
    public Object startTiming(String metricName, String requestDomainName) {
        return new Timer(metricName, System.currentTimeMillis());
    }

    @Override
    public Object startTiming(String metricName, String requestDomainName, String principalDomainName,
                              String httpMethod, String apiName) {
        return new Timer(metricName, System.currentTimeMillis());
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
        final String metricName = timer.getMetricName();
        if (separateDomainMetrics) {
            if (!StringUtil.isEmpty(requestDomainName)) {
                stopTimingSingleMetric(metricName + "_requestDomain", duration, requestDomainName,
                        null, null, -1, null);
            }
            if (!StringUtil.isEmpty(principalDomainName)) {
                stopTimingSingleMetric(metricName + "_principalDomain", duration, null,
                        principalDomainName, null, -1, null);
            }
            stopTimingSingleMetric(metricName, duration, null, null, httpMethod, httpStatus, apiName);
        } else {
            stopTimingSingleMetric(metricName, duration, requestDomainName,
                    principalDomainName, httpMethod, httpStatus, apiName);
        }
    }

    void stopTimingSingleMetric(final String metricName, long duration, final String requestDomainName,
            final String principalDomainName, final String httpMethod, int httpStatus, final String apiName) {
        AttributesBuilder builder = Attributes.builder().put(TIMER_METRIC_NAME, metricName);
        addAttributeIfNotNull(builder, REQUEST_DOMAIN_NAME, requestDomainName);
        addAttributeIfNotNull(builder, PRINCIPAL_DOMAIN_NAME, principalDomainName);
        addAttributeIfNotNull(builder, HTTP_METHOD_NAME, httpMethod);
        addAttributeIfNotNull(builder, API_NAME, apiName);
        addAttributeIfNotMinusOne(builder, HTTP_STATUS, httpStatus);
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
        private final String metricName;

        public Timer(final String metricName, long start) {
            this.metricName = metricName;
            this.start = start;
        }
        public long getStart() {
            return start;
        }
        public String getMetricName() {
            return metricName;
        }
    }
}
