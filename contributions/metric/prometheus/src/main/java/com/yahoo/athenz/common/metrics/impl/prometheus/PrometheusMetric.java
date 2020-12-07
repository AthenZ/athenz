/*
 * Copyright 2019 Yahoo Inc.
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
package com.yahoo.athenz.common.metrics.impl.prometheus;

import java.util.*;
import java.util.concurrent.ConcurrentMap;

import io.prometheus.client.Collector;
import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.Counter;
import io.prometheus.client.SimpleCollector;
import io.prometheus.client.Summary;

import com.yahoo.athenz.common.metrics.Metric;

public class PrometheusMetric implements Metric {

    public static final String REQUEST_DOMAIN_LABEL_NAME = "domain";
    public static final String PRINCIPAL_DOMAIN_LABEL_NAME = "principal";
    public static final String REQUEST_HTTP_METHOD_LABEL_NAME = "httpmethod";
    public static final String REQUEST_HTTP_STATUS_LABEL_NAME = "httpstatus";
    public static final String REQUEST_API_LABEL_NAME = "apimethod";


    public static final String METRIC_NAME_DELIMITER = "_";
    public static final String COUNTER_SUFFIX = "total";
    public static final String TIMER_UNIT = "seconds";

    private final Utils utils = new Utils();

    private final CollectorRegistry registry;
    private final ConcurrentMap<String, Collector> namesToCollectors;
    private final PrometheusExporter exporter;
    private String namespace;
    private boolean isLabelRequestDomainNameEnable;
    private boolean isLabelPrincipalDomainNameEnable;
    private boolean isLabelHttpMethodNameEnable;
    private boolean isLabelHttpStatusNameEnable;
    private boolean isLabelApiNameEnable;

    /**
     * @param registry CollectorRegistry of all metrics
     * @param exporter Prometheus metrics exporter
     * @param namespace prefix of all metrics
     */
    public PrometheusMetric(CollectorRegistry registry, ConcurrentMap<String, Collector> namesToCollectors, PrometheusExporter exporter, String namespace) {
        this(registry, namesToCollectors, exporter, namespace, false, false, false, false, false);
    }

    /**
     * @param registry CollectorRegistry of all metrics
     * @param exporter Prometheus metrics exporter
     * @param namespace prefix of all metrics
     * @param isLabelRequestDomainNameEnable enable requestDomainName label
     * @param isLabelPrincipalDomainNameEnable enable principalDomainName label
     * @param isLabelHttpMethodNameEnable enable httpMethod label
     * @param isLabelHttpStatusNameEnable enable httpStatus label
     * @param isLabelApiNameEnable enable httpApi label
     */
    public PrometheusMetric(CollectorRegistry registry,
                            ConcurrentMap<String, Collector> namesToCollectors,
                            PrometheusExporter exporter,
                            String namespace,
                            boolean isLabelRequestDomainNameEnable,
                            boolean isLabelPrincipalDomainNameEnable,
                            boolean isLabelHttpMethodNameEnable,
                            boolean isLabelHttpStatusNameEnable,
                            boolean isLabelApiNameEnable) {
        this.registry = registry;
        this.namesToCollectors = namesToCollectors;
        this.exporter = exporter;
        this.namespace = namespace;

        this.isLabelRequestDomainNameEnable = isLabelRequestDomainNameEnable;
        this.isLabelPrincipalDomainNameEnable = isLabelPrincipalDomainNameEnable;
        this.isLabelHttpMethodNameEnable = isLabelHttpMethodNameEnable;
        this.isLabelHttpStatusNameEnable = isLabelHttpStatusNameEnable;
        this.isLabelApiNameEnable = isLabelApiNameEnable;
    }

    @Override
    public void increment(String metricName) {
        increment(metricName, null, 1);
    }

    @Override
    public void increment(String metricName, String requestDomainName) {
        increment(metricName, requestDomainName, 1);
    }

    @Override
    public void increment(String metricName, String requestDomainName, String principalDomainName) {
        increment(metricName, requestDomainName, principalDomainName, 1);
    }

    @Override
    public void increment(String metricName, String requestDomainName, int count) {
        increment(metricName, requestDomainName, null, count);
    }

    @Override
    public void increment(String metricName, String requestDomainName, String principalDomainName, int count) {
        // prometheus does not allow null labels
        requestDomainName = (this.isLabelRequestDomainNameEnable) ? Objects.toString(requestDomainName, "") : "";
        principalDomainName = (this.isLabelPrincipalDomainNameEnable) ? Objects.toString(principalDomainName, "") : "";

        metricName = this.normalizeCounterMetricName(metricName);
        Counter counter = (Counter) createOrGetCollector(metricName, Counter.build());
        counter.labels(requestDomainName, principalDomainName, "", "", "").inc(count);
    }

    @Override
    public void increment(String metricName, String requestDomainName, String principalDomainName, String httpMethod, int httpStatus, String apiName) {
        // prometheus does not allow null labels
        requestDomainName = (this.isLabelRequestDomainNameEnable) ? Objects.toString(requestDomainName, "") : "";
        principalDomainName = (this.isLabelPrincipalDomainNameEnable) ? Objects.toString(principalDomainName, "") : "";
        httpMethod = (this.isLabelHttpMethodNameEnable) ? Objects.toString(httpMethod, "") : "";
        String httpStatusStr = Integer.toString(httpStatus);
        httpStatusStr = (this.isLabelHttpStatusNameEnable) ? httpStatusStr : "";
        apiName = (this.isLabelApiNameEnable) ? Objects.toString(apiName, "") : "";

        metricName = this.normalizeCounterMetricName(metricName);
        Counter counter = (Counter) createOrGetCollector(metricName, Counter.build());
        counter.labels(requestDomainName, principalDomainName, httpMethod, httpStatusStr, apiName).inc(1);
    }

    @Override
    public void increment(String metricName, final String... attributes) {
        metricName = this.normalizeCounterMetricName(metricName);
        Map<String, String[]> attributesMap = utils.flatArrayToMap(attributes);

        Counter counter = (Counter) createOrGetCollector(metricName, Counter.build(), attributesMap.get(Utils.ATTRIBUTES_KEYS));
        counter.labels(attributesMap.get(Utils.ATTRIBUTES_VALUES)).inc(1);
    }

    @Override
    public Object startTiming(String metricName, String requestDomainName) {
        return startTiming(metricName, requestDomainName, null);
    }

    @Override
    public Object startTiming(String metricName, String requestDomainName, String principalDomainName) {
        // prometheus does not allow null labels
        requestDomainName = (this.isLabelRequestDomainNameEnable) ? Objects.toString(requestDomainName, "") : "";
        principalDomainName = (this.isLabelPrincipalDomainNameEnable) ? Objects.toString(principalDomainName, "") : "";

        metricName = this.normalizeTimerMetricName(metricName);
        Summary summary = (Summary) createOrGetCollector(metricName, Summary.build()
        // .quantile(0.5, 0.05)
        // .quantile(0.9, 0.01)
        );
        return summary.labels(requestDomainName, principalDomainName, "", "", "").startTimer();
    }

    @Override
    public Object startTiming(String metricName, String requestDomainName, String principalDomainName, String httpMethod, String apiName) {
        // prometheus does not allow null labels
        requestDomainName = (this.isLabelRequestDomainNameEnable) ? Objects.toString(requestDomainName, "") : "";
        principalDomainName = (this.isLabelPrincipalDomainNameEnable) ? Objects.toString(principalDomainName, "") : "";
        httpMethod = (this.isLabelHttpMethodNameEnable) ? Objects.toString(httpMethod, "") : "";
        apiName = (this.isLabelApiNameEnable) ? Objects.toString(apiName, "") : "";

        metricName = this.normalizeTimerMetricName(metricName);
        Summary summary = (Summary) createOrGetCollector(metricName, Summary.build());

        return summary.labels(requestDomainName, principalDomainName, httpMethod, "", apiName).startTimer();
    }

    @Override
    public void stopTiming(Object timerObj) {
        if (timerObj == null) {
            return;
        }
        Summary.Timer timer = (Summary.Timer) timerObj;
        timer.observeDuration();
    }

    @Override
    public void stopTiming(Object timerObj, String requestDomainName, String principalDomainName) {
        stopTiming(timerObj);
    }

    @Override
    public void flush() {
        if (this.exporter != null) {
            this.exporter.flush();
        }
    }

    @Override
    public void quit() {
        if (this.exporter != null) {
            this.exporter.flush();
            this.exporter.quit();
        }
    }

    /**
     * Create collector and register it to the registry.
     * This is needed since Athenz metric names are defined on runtime and we need the same collector object to record the data.
     * @param metricName Name of the metric
     * @param builder Prometheus Collector Builder
     */
    private Collector createOrGetCollector(String metricName, SimpleCollector.Builder<?, ?> builder) {
        String[] labels = new String[] { REQUEST_DOMAIN_LABEL_NAME, PRINCIPAL_DOMAIN_LABEL_NAME, REQUEST_HTTP_METHOD_LABEL_NAME, REQUEST_HTTP_STATUS_LABEL_NAME, REQUEST_API_LABEL_NAME };
        return createOrGetCollector(metricName, builder, labels);
    }

    private Collector createOrGetCollector(String metricName, SimpleCollector.Builder<?, ?> builder, String[] labels) {
        String key = metricName;
        ConcurrentMap<String, Collector> map = this.namesToCollectors;
        Collector collector = map.get(key);

        // double checked locking
        if (collector == null) {
            synchronized (map) {
                if (!map.containsKey(key)) {
                    // create
                    builder = builder
                            .namespace(this.namespace)
                            .name(metricName)
                            .help(metricName)
                            .labelNames(labels);
                    collector = builder.register(this.registry);
                    // put
                    map.put(key, collector);
                } else {
                    // get
                    collector = map.get(key);
                }
            }
        }

        return collector;
    }

    /**
     * Create counter metric name that follows prometheus standard
     * @param metricName Name of the counter metric
     */
    private String normalizeCounterMetricName(String metricName) {
        return metricName + METRIC_NAME_DELIMITER + COUNTER_SUFFIX;
    }

    /**
     * Create timer metric name that follows prometheus standard
     * @param metricName Name of the timer metric
     */
    private String normalizeTimerMetricName(String metricName) {
        return metricName + METRIC_NAME_DELIMITER + TIMER_UNIT;
    }
}
