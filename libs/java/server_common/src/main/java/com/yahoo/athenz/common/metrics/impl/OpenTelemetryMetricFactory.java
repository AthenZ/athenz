package com.yahoo.athenz.common.metrics.impl;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.exporter.logging.LoggingMetricExporter;
import io.opentelemetry.exporter.logging.LoggingSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.export.MetricReader;
import io.opentelemetry.sdk.metrics.export.PeriodicMetricReader;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.time.Duration;

public class OpenTelemetryMetricFactory implements MetricFactory {
  @Override
  public Metric create() {
    return new OpenTelemetryMetric();
  }

  public OpenTelemetry initialize() {
    final long interval = 800L;
    MetricReader reader = PeriodicMetricReader.builder(LoggingMetricExporter.create())
        .setInterval(Duration.ofMillis(interval))
        .build();
    SdkMeterProvider meterProvider = SdkMeterProvider.builder().registerMetricReader(reader).build();
    SdkTracerProvider tracerProvider = SdkTracerProvider.builder().
        addSpanProcessor(SimpleSpanProcessor.create(LoggingSpanExporter.create())).build();
    return OpenTelemetrySdk.builder().setMeterProvider(meterProvider)
        .setTracerProvider(tracerProvider).buildAndRegisterGlobal();
  }
}

