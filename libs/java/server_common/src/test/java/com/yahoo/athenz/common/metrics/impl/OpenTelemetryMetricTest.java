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

import com.yahoo.athenz.common.metrics.Metric;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.metrics.*;
import io.opentelemetry.api.common.Attributes;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

public class OpenTelemetryMetricTest {
    private LongCounter counter;
    private LongGauge gaugeCounter;
    private DoubleHistogram histogram;
    private OpenTelemetryMetric metric;

    @BeforeMethod
    public void setUp() {
        Meter meter = mock(Meter.class);
        counter = mock(LongCounter.class);
        gaugeCounter = mock(LongGauge.class);
        histogram = mock(DoubleHistogram.class);
        OpenTelemetry openTelemetry = mock(OpenTelemetry.class);

        LongCounterBuilder counterBuilder = mock(LongCounterBuilder.class);
        when(meter.counterBuilder(anyString())).thenReturn(counterBuilder);
        when(counterBuilder.build()).thenReturn(counter);

        LongGaugeBuilder gaugeBuilder = mock(LongGaugeBuilder.class);
        DoubleGaugeBuilder doubleGaugeBuilder = mock(DoubleGaugeBuilder.class);
        when(meter.gaugeBuilder(anyString())).thenReturn(doubleGaugeBuilder);
        when(doubleGaugeBuilder.ofLongs()).thenReturn(gaugeBuilder);
        when(gaugeBuilder.build()).thenReturn(gaugeCounter);

        DoubleHistogramBuilder histogramBuilder = mock(DoubleHistogramBuilder.class);
        when(meter.histogramBuilder(anyString())).thenReturn(histogramBuilder);
        when(histogramBuilder.build()).thenReturn(histogram);

        when(openTelemetry.getMeter("meter")).thenReturn(meter);

        metric = new OpenTelemetryMetric(openTelemetry, "athenz-histogram", false, false, false, false);
    }

    @Test
    public void testIncrementMetric() {
        metric.increment("testIncrement");
        verify(counter).add(1L, Attributes.builder().build());
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
    public void testIncrementAllAttributesWithDomainMetrics() {
        metric.separateDomainCounterMetrics = true;
        metric.increment("testMetric", "athenz", "sports", "GET", 200, "getMetric");
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(counter, times(3)).add(eq(1L), captor.capture());

        List<Attributes> capturedValues = captor.getAllValues();
        assertEquals(capturedValues.size(), 3);

        Attributes attributes = capturedValues.get(0);
        assertEquals(attributes.get(AttributeKey.stringKey("requestDomainName")), "athenz");
        assertNull(attributes.get(AttributeKey.stringKey("principalDomainName")));
        assertNull(attributes.get(AttributeKey.stringKey("httpMethodName")));
        assertNull(attributes.get(AttributeKey.stringKey("httpStatus")));
        assertNull(attributes.get(AttributeKey.stringKey("apiName")));

        attributes = capturedValues.get(1);
        assertEquals(attributes.get(AttributeKey.stringKey("principalDomainName")), "sports");
        assertNull(attributes.get(AttributeKey.stringKey("requestDomainName")));
        assertNull(attributes.get(AttributeKey.stringKey("httpMethodName")));
        assertNull(attributes.get(AttributeKey.stringKey("httpStatus")));
        assertNull(attributes.get(AttributeKey.stringKey("apiName")));

        attributes = capturedValues.get(2);
        assertNull(attributes.get(AttributeKey.stringKey("requestDomainName")));
        assertNull(attributes.get(AttributeKey.stringKey("principalDomainName")));
        assertEquals(attributes.get(AttributeKey.stringKey("httpMethodName")), "GET");
        assertEquals(attributes.get(AttributeKey.stringKey("httpStatus")), "200");
        assertEquals(attributes.get(AttributeKey.stringKey("apiName")), "getMetric");

        metric.separateDomainCounterMetrics = false;
    }

    @Test
    public void testIncrementAllAttributesWithSkipDomainCounterMetrics() {
        metric.separateDomainCounterMetrics = true;
        metric.skipDomainCounterMetrics = true;
        metric.increment("testMetric", "athenz", "sports", "GET", 200, "getMetric");
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(counter, times(1)).add(eq(1L), captor.capture());

        List<Attributes> capturedValues = captor.getAllValues();
        assertEquals(capturedValues.size(), 1);

        Attributes attributes = capturedValues.get(0);
        assertNull(attributes.get(AttributeKey.stringKey("requestDomainName")));
        assertNull(attributes.get(AttributeKey.stringKey("principalDomainName")));
        assertEquals(attributes.get(AttributeKey.stringKey("httpMethodName")), "GET");
        assertEquals(attributes.get(AttributeKey.stringKey("httpStatus")), "200");
        assertEquals(attributes.get(AttributeKey.stringKey("apiName")), "getMetric");

        metric.separateDomainCounterMetrics = false;
        metric.skipDomainCounterMetrics = false;
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
    public void testSetGauge() {
        metric.setGauge("test-gauge", "testRequestDomain", "testRequestService", 100);
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(gaugeCounter).set(eq(100L), captor.capture());
        Attributes attributes = captor.getValue();
        assertEquals(attributes.get(AttributeKey.stringKey("requestDomainName")), "testRequestDomain");
        assertEquals(attributes.get(AttributeKey.stringKey("requestServiceName")), "testRequestService");
    }

    @Test
    public void testStartTiming() {
        Object timerMetric = metric.startTiming("testMetric", "testRequestDomain");
        assertNotNull(timerMetric);
        assertTrue(timerMetric instanceof OpenTelemetryMetric.Timer);
        OpenTelemetryMetric.Timer timer = (OpenTelemetryMetric.Timer) timerMetric;
        assertTrue(timer.getStart() > 0);
    }

    @Test
    public void testStartTimingFullAttrs() {
        Object timerMetric = metric.startTiming("testMetric", "testRequestDomain", "principalDomain", "GET", "testAPI");
        assertNotNull(timerMetric);
        assertTrue(timerMetric instanceof OpenTelemetryMetric.Timer);
        OpenTelemetryMetric.Timer timer = (OpenTelemetryMetric.Timer) timerMetric;
        assertTrue(timer.getStart() > 0);
    }

    @Test
    public void testStopTimingTimer() {
        OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer("providerTiming",
                System.currentTimeMillis(), Metric.TimerMetricType.PROVIDER_LATENCY);
        // this api does nothing so we'll make sure there
        // are no interactions with the histogram
        metric.stopTiming(timer);
        verifyNoInteractions(histogram);
    }

    @Test
    public void testStopTimingTimerRequestPrincipal() {
        OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer("providerTiming",
                System.currentTimeMillis(),  Metric.TimerMetricType.PROVIDER_LATENCY);
        metric.stopTiming(timer, "testRequestDomain", "testPrincipalDomain");
        verify(histogram).record(anyDouble(), any(Attributes.class));
    }

    @Test
    public void testStopTimingAllAttributes() {
        OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer("apiTiming",
                System.currentTimeMillis(), Metric.TimerMetricType.API_LATENCY);
        metric.stopTiming(timer, "testRequestDomain", "testPrincipalDomain", "GET", 200, "testAPI");
        verify(histogram).record(anyDouble(), any(Attributes.class));
    }

    @Test
    public void testStopTimingAllAttributesWithDomainMetrics() {
        OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer("apiTiming",
                System.currentTimeMillis(), Metric.TimerMetricType.API_LATENCY);
        metric.separateDomainHistogramMetrics = true;
        metric.separateDomainCounterMetrics = true;
        metric.stopTiming(timer, "athenz", "sports", "GET", 200, "testAPI");
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(histogram, times(3)).record(anyDouble(), captor.capture());

        List<Attributes> capturedValues = captor.getAllValues();
        assertEquals(capturedValues.size(), 3);

        Attributes attributes = capturedValues.get(0);
        assertEquals(attributes.get(AttributeKey.stringKey("timerMetricName")), "apiTiming_requestDomain");
        assertEquals(attributes.get(AttributeKey.stringKey("requestDomainName")), "athenz");
        assertNull(attributes.get(AttributeKey.stringKey("principalDomainName")));
        assertNull(attributes.get(AttributeKey.stringKey("httpMethodName")));
        assertNull(attributes.get(AttributeKey.stringKey("httpStatus")));
        assertNull(attributes.get(AttributeKey.stringKey("apiName")));

        attributes = capturedValues.get(1);
        assertEquals(attributes.get(AttributeKey.stringKey("timerMetricName")), "apiTiming_principalDomain");
        assertEquals(attributes.get(AttributeKey.stringKey("principalDomainName")), "sports");
        assertNull(attributes.get(AttributeKey.stringKey("requestDomainName")));
        assertNull(attributes.get(AttributeKey.stringKey("httpMethodName")));
        assertNull(attributes.get(AttributeKey.stringKey("httpStatus")));
        assertNull(attributes.get(AttributeKey.stringKey("apiName")));

        attributes = capturedValues.get(2);
        assertEquals(attributes.get(AttributeKey.stringKey("timerMetricName")), "apiTiming");
        assertNull(attributes.get(AttributeKey.stringKey("requestDomainName")));
        assertNull(attributes.get(AttributeKey.stringKey("principalDomainName")));
        assertEquals(attributes.get(AttributeKey.stringKey("httpMethodName")), "GET");
        assertEquals(attributes.get(AttributeKey.stringKey("httpStatus")), "200");
        assertEquals(attributes.get(AttributeKey.stringKey("apiName")), "testAPI");

        metric.separateDomainHistogramMetrics = false;
        metric.separateDomainCounterMetrics = false;
    }

    @Test
    public void testStopTimingAllAttributesWithSkipDomainHistogramMetrics() {
        OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer("apiTiming",
                System.currentTimeMillis(), Metric.TimerMetricType.API_LATENCY);
        metric.separateDomainHistogramMetrics = true;
        metric.skipDomainHistogramMetrics = true;
        metric.stopTiming(timer, "athenz", "sports", "GET", 200, "testAPI");
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(histogram, times(1)).record(anyDouble(), captor.capture());

        List<Attributes> capturedValues = captor.getAllValues();
        assertEquals(capturedValues.size(), 1);

        Attributes attributes = capturedValues.get(0);
        assertEquals(attributes.get(AttributeKey.stringKey("timerMetricName")), "apiTiming");
        assertNull(attributes.get(AttributeKey.stringKey("requestDomainName")));
        assertNull(attributes.get(AttributeKey.stringKey("principalDomainName")));
        assertEquals(attributes.get(AttributeKey.stringKey("httpMethodName")), "GET");
        assertEquals(attributes.get(AttributeKey.stringKey("httpStatus")), "200");
        assertEquals(attributes.get(AttributeKey.stringKey("apiName")), "testAPI");

        metric.separateDomainHistogramMetrics = false;
        metric.skipDomainHistogramMetrics = false;
    }

    @Test
    public void testStopProviderTimingAllAttributesWithDomainMetrics() {
        OpenTelemetryMetric.Timer timer = new OpenTelemetryMetric.Timer("providerTiming",
                System.currentTimeMillis(), Metric.TimerMetricType.PROVIDER_LATENCY);
        metric.separateDomainHistogramMetrics = true;
        metric.separateDomainCounterMetrics = true;
        metric.stopTiming(timer, "athenz.provider", "sports", "POST", 200, "testAPI");
        ArgumentCaptor<Attributes> captor = ArgumentCaptor.forClass(Attributes.class);
        verify(histogram, times(1)).record(anyDouble(), captor.capture());

        List<Attributes> capturedValues = captor.getAllValues();
        assertEquals(capturedValues.size(), 1);

        Attributes attributes = capturedValues.get(0);
        assertEquals(attributes.get(AttributeKey.stringKey("timerMetricName")), "providerTiming");
        assertEquals(attributes.get(AttributeKey.stringKey("providerServiceName")), "athenz.provider");
        assertEquals(attributes.get(AttributeKey.stringKey("httpStatus")), "200");
        assertNull(attributes.get(AttributeKey.stringKey("requestDomainName")));
        assertNull(attributes.get(AttributeKey.stringKey("principalDomainName")));
        // http method and api name are not passed
        assertNull(attributes.get(AttributeKey.stringKey("httpMethodName")));
        assertNull(attributes.get(AttributeKey.stringKey("apiName")));

        metric.separateDomainHistogramMetrics = false;
        metric.separateDomainCounterMetrics = false;
    }

    @Test
    public void testFlush() {
        metric.flush();
        verifyNoInteractions(counter, histogram);
    }

    @Test
    public void testQuit() {
        metric.quit();
        verifyNoInteractions(counter, histogram);
    }
}
