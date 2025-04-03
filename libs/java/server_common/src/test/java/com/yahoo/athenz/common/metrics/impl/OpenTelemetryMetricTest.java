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

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
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

import java.util.List;

public class OpenTelemetryMetricTest {
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
        OpenTelemetry openTelemetry = mock(OpenTelemetry.class);

        LongCounterBuilder counterBuilder = mock(LongCounterBuilder.class);
        when(meter.counterBuilder(anyString())).thenReturn(counterBuilder);
        when(counterBuilder.build()).thenReturn(counter);

        SpanBuilder spanBuilder = mock(SpanBuilder.class);
        when(tracer.spanBuilder(anyString())).thenReturn(spanBuilder);
        when(spanBuilder.startSpan()).thenReturn(span);

        when(openTelemetry.getMeter("meter")).thenReturn(meter);
        when(openTelemetry.getTracer("tracer")).thenReturn(tracer);

        metric = new OpenTelemetryMetric(openTelemetry);
    }

    @Test
    public void testIncrementMetric() {
        metric.increment("testIncrement");
        verify(counter).add(1L);
    }

    @Test
    public void testIncrementMetricRequest() {
        metric.increment("testMetric", "testRequestDomain");
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(counter).add(eq(1L), captor.capture());
        Attributes attributes = captor.getValue();
        assertEquals(attributes.get(AttributeKey.stringKey("requestDomainName")), "testRequestDomain");
    }

    @Test
    public void testIncrementMetricRequestCount() {
        metric.increment("testMetric", "testRequestDomain", 3);
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(counter).add(eq(3L), captor.capture());
        Attributes attributes = captor.getValue();
        assertEquals(attributes.get(AttributeKey.stringKey("requestDomainName")), "testRequestDomain");
    }

    @Test
    public void testIncrementMetricRequestPrincipal() {
        metric.increment("testMetric", "testRequestDomain", "testPrincipalDomain");
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(counter).add(eq(1L), captor.capture());
        Attributes attributes = captor.getValue();
        assertEquals(attributes.get(AttributeKey.stringKey("requestDomainName")), "testRequestDomain");
        assertEquals(attributes.get(AttributeKey.stringKey("principalDomainName")), "testPrincipalDomain");
    }

    @Test
    public void testIncrementMetricRequestPrincipalCount() {
        metric.increment("testMetric", "testRequestDomain",
                "testPrincipalDomain", 5);
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(counter).add(eq(5L), captor.capture());
        Attributes attributes = captor.getValue();
        assertEquals(attributes.get(AttributeKey.stringKey("requestDomainName")), "testRequestDomain");
        assertEquals(attributes.get(AttributeKey.stringKey("principalDomainName")), "testPrincipalDomain");
    }

    @Test
    public void testIncrementAllAttributes() {
        metric.increment("testMetric", "testRequestDomain",
                "testPrincipalDomain", "GET", 200, "testAPI");
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(counter).add(eq(1L), captor.capture());
        Attributes attributes = captor.getValue();
        assertEquals(attributes.get(AttributeKey.stringKey("requestDomainName")), "testRequestDomain");
        assertEquals(attributes.get(AttributeKey.stringKey("principalDomainName")), "testPrincipalDomain");
        assertEquals(attributes.get(AttributeKey.stringKey("httpMethodName")), "GET");
        assertEquals(attributes.get(AttributeKey.stringKey("httpStatus")), "200");
        assertEquals(attributes.get(AttributeKey.stringKey("apiName")), "testAPI");
    }

    @Test
    public void testIncrementMetricRequestWithAttributes() {
        String[] inputAttributes = {
                "DOMAIN", "testRequestDomain",
                "PROFILE", "stage",
                "API_NAME", "testAPI",
                "METHOD", "GET",
                "STATUS", "200",
                "INVALID"  // this should be ignored, since it is odd numbered attribute without a value
        };

        metric.increment("testMetric", inputAttributes);

        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(counter).add(eq(1L), captor.capture());
        Attributes attributes = captor.getValue();
        assertEquals(attributes.get(AttributeKey.stringKey("DOMAIN")), "testRequestDomain");
        assertEquals(attributes.get(AttributeKey.stringKey("PROFILE")), "stage");
        assertEquals(attributes.get(AttributeKey.stringKey("API_NAME")), "testAPI");
        assertEquals(attributes.get(AttributeKey.stringKey("METHOD")), "GET");
        assertEquals(attributes.get(AttributeKey.stringKey("STATUS")), "200");
        assertNull(attributes.get(AttributeKey.stringKey("INVALID")));
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
    public void testStopTimingTimer() {
        OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer(Context.current(),
                System.currentTimeMillis(), span);
        metric.stopTiming(timer);
        verifyNoInteractions(meter, tracer, counter, span);
    }

    @Test
    public void testStopTimingTimerRequestPrincipal() {
        OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer(Context.current(),
                System.currentTimeMillis(), span);
        metric.stopTiming(timer, "testRequestDomain", "testPrincipalDomain");
        verify(span).setAttribute("requestDomainName", "testRequestDomain");
        verify(span).setAttribute("principalDomainName", "testPrincipalDomain");
        verify(span).setAttribute(eq("duration"), anyLong());
        verify(span).end();
    }

    @Test
    public void testStopTimingAllAttributes() {
        OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer(Context.current(),
                System.currentTimeMillis(), span);
        metric.stopTiming(timer, "testRequestDomain",
                "testPrincipalDomain", "GET", 200, "testAPI");
        verify(span).setAttribute("requestDomainName", "testRequestDomain");
        verify(span).setAttribute("principalDomainName", "testPrincipalDomain");
        verify(span).setAttribute("httpMethodName", "GET");
        verify(span).setAttribute("httpStatus", "200");
        verify(span).setAttribute("apiName", "testAPI");
        verify(span).setAttribute(eq("duration"), anyLong());
        verify(span).end();
    }


    @Test
    public void testFlush() {
        metric.flush();
        verifyNoInteractions(meter, tracer, counter, span);
    }

    @Test
    public void testQuit() {
        metric.quit();
        verifyNoInteractions(meter, tracer, counter, span);
    }
}
