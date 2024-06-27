package com.yahoo.athenz.common.metrics.impl;

import com.yahoo.athenz.common.metrics.Metric;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Context;

public class OpenTelemetryMetric implements Metric {
  final Meter meter;
  final Tracer tracer;

  private static final String REQUEST_DOMAIN_NAME = "requestDomainName";
  private static final String PRINCIPAL_DOMAIN_NAME = "principalDomainName";
  private static final String HTTP_METHOD_NAME = "httpMethodName";
  private static final String HTTP_STATUS = "httpStatus";
  private static final String API_NAME = "apiName";

  public OpenTelemetryMetric(OpenTelemetryMetricFactory factory) {
    //OpenTelemetryMetricFactory factory = new OpenTelemetryMetricFactory();
    OpenTelemetry openTelemetry = factory.initialize();
    meter = openTelemetry.getMeter("meter");
    tracer = openTelemetry.getTracer("tracer");
  }

  public OpenTelemetryMetric(Meter meter, Tracer tracer) {
    this.meter = meter;
    this.tracer = tracer;
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
  public void increment(String metric, String requestDomainName, String principalDomainName, String httpMethod, int httpStatus, String apiName) {
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
  public Object startTiming(String metric, String requestDomainName) {
    Span span = tracer.spanBuilder(metric).startSpan();
    Context context = Context.current().with(span);
    return new Timer(context, System.currentTimeMillis(), span, 0);
  }

  @Override
  public void stopTiming(Object timerMetric) {
    Timer timer = (Timer) timerMetric;
    timer.duration = System.currentTimeMillis() - timer.getStart();
    timer.getSpan().end();
  }

  @Override
  public void stopTiming(Object timerMetric, String requestDomainName, String principalDomainName) {
    Timer timer = (Timer) timerMetric;
    long duration = System.currentTimeMillis() - timer.start;
    timer.duration = duration;
    timer.getSpan().end();
    LongCounter counter = meter.counterBuilder("timing").build();
    Attributes attributes = Attributes.builder().put(REQUEST_DOMAIN_NAME, requestDomainName)
        .put(PRINCIPAL_DOMAIN_NAME, principalDomainName).build();
    counter.add(duration, attributes);
  }

  @Override
  public void stopTiming(Object timerMetric, String requestDomainName, String principalDomainName,
      String httpMethod, int httpStatus, String apiName) {
    Timer timer = (Timer) timerMetric;
    long duration = System.currentTimeMillis() - timer.start;
    timer.duration = duration;
    timer.getSpan().end();
    LongCounter counter = meter.counterBuilder("timing").build();
    Attributes attributes = Attributes.builder().put(REQUEST_DOMAIN_NAME, requestDomainName)
        .put(PRINCIPAL_DOMAIN_NAME, principalDomainName)
        .put(HTTP_METHOD_NAME, httpMethod) .put(HTTP_STATUS, Integer.toString(httpStatus))
        .put(API_NAME, apiName) .build();
    counter.add(duration, attributes);
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
    private final Context context;
    private final long start;
    private final Span span;
    private long duration;
    public Timer(Context context, long start, Span span, long duration) {
      this.context = context;
      this.start = start;
      this.span = span;
      this.duration = duration;
    }
    public long getStart() {
      return start;
    }
    public Span getSpan() {
      return span;
    }
  }
}
