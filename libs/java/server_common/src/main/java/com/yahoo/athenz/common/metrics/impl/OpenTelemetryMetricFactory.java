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
import com.yahoo.athenz.common.metrics.MetricFactory;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk;

/**
 * In order to use the otlp exporters you need to configure the environment variables.
 * You need to set the endpoint (OTEL_EXPORTER_OTLP_ENDPOINT) which is defaulted to
 * "http:://localhost:4317" and the attributes (OTEL_RESOURCE_ATTRIBUTES) which is defaulted
 * to "service.name=my-service." AutoConfiguredOpenTelemetrySdk automatically reads the
 * configuration and sets up the exporter.
*/
public class OpenTelemetryMetricFactory implements MetricFactory {

    private static final String PROP_HISTOGRAM_NAME    = "athenz.otel_histogram_name";
    private static final String HISTOGRAM_DEFAULT_NAME = "athenz_api_request_duration_msecs";

    private static final String HISTOGRAM_NAME = System.getProperty(PROP_HISTOGRAM_NAME, HISTOGRAM_DEFAULT_NAME);
    private static final OpenTelemetryMetric INSTANCE = new OpenTelemetryMetric(initialize(), HISTOGRAM_NAME);

    @Override
    public Metric create() {
        return INSTANCE;
    }

    public static OpenTelemetry initialize() {
        return AutoConfiguredOpenTelemetrySdk.initialize().getOpenTelemetrySdk();
    }

    public static Metric getInstance() {
        return INSTANCE;
    }
}
