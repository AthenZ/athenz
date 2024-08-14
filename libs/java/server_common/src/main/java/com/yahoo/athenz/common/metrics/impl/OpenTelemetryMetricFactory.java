package com.yahoo.athenz.common.metrics.impl;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk;

/*
   In order to use the otlp exporters you need to configure the environment variables.
   You need to set the endpoint (OTEL_EXPORTER_OTLP_ENDPOINT) which is defaulted to
   "http:://localhost:4317" and the attributes (OTEL_RESOURCE_ATTRIBUTES) which is defaulted
   to "service.name=my-service." AutoConfiguredOpenTelemetrySdk automatically reads the
   configuration and sets up the exporter.
*/

public class OpenTelemetryMetricFactory implements MetricFactory {
  @Override
  public Metric create() {
    OpenTelemetry openTelemetry = initialize();
    return new OpenTelemetryMetric(openTelemetry);
  }

  public OpenTelemetry initialize() {
    return AutoConfiguredOpenTelemetrySdk.initialize().getOpenTelemetrySdk();
  }
}
