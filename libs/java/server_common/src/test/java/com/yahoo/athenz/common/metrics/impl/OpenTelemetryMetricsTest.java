package com.yahoo.athenz.common.metrics.impl;

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.LongCounterBuilder;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanBuilder;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Context;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.mockito.ArgumentCaptor;

public class OpenTelemetryMetricsTest {

  private Meter meter;
  private Tracer tracer;
  private LongCounter counter;
  private Span span;
  private OpenTelemetryMetric metric;

  @BeforeMethod
  public void setUp() {
    meter = mock(Meter.class);
    tracer = mock(Tracer.class);
    counter = mock(LongCounter.class);
    span = mock(Span.class);
    metric = new OpenTelemetryMetric(meter, tracer);
  }

  @Test
  public void testIncrementWithMetric() {
    metric.increment("testMetric");

    verify(counter).add(1);
  }

  @Test
  public void testStartTiming() {
    Object timerMetric = metric.startTiming("testMetric", "testRequestDomain");
    assertNotNull(timerMetric);
    assertTrue(timerMetric instanceof OpenTelemetryMetric.Timer);
    OpenTelemetryMetric.Timer timer = (OpenTelemetryMetric.Timer) timerMetric;
    assertEquals(span, timer.getSpan());
  }

  @Test
  public void testStopTiming() {
    OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer(Context.current(), System.currentTimeMillis(), span, 0);
    metric.stopTiming(timer);
    verify(span).end();
  }

  @Test
  public void testStopTimingWithAttributes() {
    OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer(Context.current(), System.currentTimeMillis(), span, 0);

    metric.stopTiming(timer, "testRequestDomain", "testPrincipalDomain");

    verify(span).end();
    verify(counter).add(anyLong(), any(Attributes.class));
  }

  @Test
  public void testStopTimingWithAllAttributes() {
    OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer(Context.current(), System.currentTimeMillis(), span, 0);

    metric.stopTiming(timer, "testRequestDomain", "testPrincipalDomain", "GET", 200, "testAPI");

    verify(span).end();
    verify(counter).add(anyLong(), any(Attributes.class));
  }
}




/*import static org.mockito.Mockito.*;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import com.yahoo.athenz.common.server.util.PrincipalUtils;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.MeterProvider;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.TracerProvider;
import io.opentelemetry.context.Context;

import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;


public class OpenTelemetryMetricsTest {


  private Meter meter;
  private Tracer tracer;
  private OpenTelemetryMetric metric;

  private Meter meter;
  private Tracer tracer;
  private LongCounter counter;
  private Span span;
  private OpenTelemetryMetric metric;

  @BeforeMethod
  public void initial() {
      meter = mock(Meter.class);
      tracer = mock(Tracer.class);
      counter = mock(LongCounter.class);
      span = mock(Span.class);

      when(meter.counterBuilder(anyString())).thenReturn(mock(LongCounter.Builder.class));
      when(meter.counterBuilder(anyString()).build()).thenReturn(counter);
      when(tracer.spanBuilder(anyString())).thenReturn(mock(Span.Builder.class));
      when(tracer.spanBuilder(anyString()).startSpan()).thenReturn(span);

      metric = new OpenTelemetryMetric(meter, tracer);

      MeterProvider meterProvider = mock(MeterProvider.class);
      TracerProvider tracerProvider = mock(TracerProvider.class);
      OpenTelemetry openTelemetry = mock(OpenTelemetry.class);

      when(openTelemetry.getMeterProvider()).thenReturn(meterProvider);
      when(openTelemetry.getTracerProvider()).thenReturn(tracerProvider);
      when(openTelemetry.getMeter("meter")).thenReturn(meter);
      when(openTelemetry.getTracer("tracer")).thenReturn(tracer);
      GlobalOpenTelemetry.set(openTelemetry);
      metric = new OpenTelemetryMetric(meter, tracer);
    }

    @Test
    public void testIncrement() {
      LongCounter counter = mock(LongCounter.class);
      when(meter.counterBuilder("testMetric").build()).thenReturn(counter);
      metric.increment("testMetric");
      verify(counter).add(1);
    }

    public void testIncrementMultiple() {
      LongCounter counter = mock(LongCounter.class);
      when(meter.counterBuilder("testMetric").build()).thenReturn(counter);
      metric.increment("testMetric", "requestDomain", "principalDomain",
          "GET", 200, "testAPI");
    }

    public void testStartTiming() {
      Span span = mock(Span.class);
      when(tracer.spanBuilder("testMetric").startSpan()).thenReturn(span);
      Object Timer = metric.startTiming("testMetric", "requestDomain");
      metric.stopTiming(Timer);
      verify(span).end();
    }
} */
