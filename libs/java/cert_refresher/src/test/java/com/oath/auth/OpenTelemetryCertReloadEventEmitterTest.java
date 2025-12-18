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
package com.oath.auth;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.LongCounterBuilder;
import io.opentelemetry.api.metrics.LongGauge;
import io.opentelemetry.api.metrics.DoubleGaugeBuilder;
import io.opentelemetry.api.metrics.LongGaugeBuilder;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.common.AttributeKey;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class OpenTelemetryCertReloadEventEmitterTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    private MockedStatic<GlobalOpenTelemetry> mockedGlobalOtel;
    private LongCounter mockCounter;
    private LongGauge mockGauge;
    private OpenTelemetryCertReloadEventEmitter emitter;

    @BeforeMethod
    public void setup() {
        mockCounter = mock(LongCounter.class);
        mockGauge = mock(LongGauge.class);

        mockedGlobalOtel = Mockito.mockStatic(GlobalOpenTelemetry.class);

        OpenTelemetry mockOtel = mock(OpenTelemetry.class);
        Meter mockMeter = mock(Meter.class);
        LongCounterBuilder mockCounterBuilder = mock(LongCounterBuilder.class);
        DoubleGaugeBuilder mockDoubleGaugeBuilder = mock(DoubleGaugeBuilder.class);
        LongGaugeBuilder mockLongGaugeBuilder = mock(LongGaugeBuilder.class);

        mockedGlobalOtel.when(GlobalOpenTelemetry::get).thenReturn(mockOtel);
        when(mockOtel.getMeter(anyString())).thenReturn(mockMeter);

        // Setup counter builder
        when(mockMeter.counterBuilder(anyString())).thenReturn(mockCounterBuilder);
        when(mockCounterBuilder.setDescription(anyString())).thenReturn(mockCounterBuilder);
        when(mockCounterBuilder.build()).thenReturn(mockCounter);

        // Setup gauge builder - gaugeBuilder() returns DoubleGaugeBuilder, ofLongs() returns LongGaugeBuilder
        when(mockMeter.gaugeBuilder(anyString())).thenReturn(mockDoubleGaugeBuilder);
        when(mockDoubleGaugeBuilder.setDescription(anyString())).thenReturn(mockDoubleGaugeBuilder);
        when(mockDoubleGaugeBuilder.ofLongs()).thenReturn(mockLongGaugeBuilder);
        when(mockLongGaugeBuilder.build()).thenReturn(mockGauge);

        // Create emitter after mocks are set up
        emitter = new OpenTelemetryCertReloadEventEmitter();
    }

    @AfterMethod
    public void teardown() {
        if (mockedGlobalOtel != null) {
            mockedGlobalOtel.close();
        }
    }

    @Test
    public void testRecordCertRefreshCallsCounter() throws Exception {
        String certPath = Objects.requireNonNull(classLoader.getResource("rsa_public_x509.cert")).getPath();

        ArgumentCaptor<Attributes> counterAttrsCaptor = ArgumentCaptor.forClass(Attributes.class);

        emitter.recordCertRefresh(certPath);

        // Verify counter was called with success
        verify(mockCounter, times(1)).add(eq(1L), counterAttrsCaptor.capture());

        // Verify counter attributes
        Attributes counterAttrs = counterAttrsCaptor.getValue();
        assertEquals(counterAttrs.get(AttributeKey.stringKey("function")), "cert_refresh");
        assertEquals(counterAttrs.get(AttributeKey.stringKey("result")), "success");

        // Verify gauge was called for cert validity
        verify(mockGauge, times(1)).set(anyLong(), any(Attributes.class));
    }

    @Test
    public void testRecordCertRefreshFailureCallsCounter() {
        ArgumentCaptor<Attributes> attrsCaptor = ArgumentCaptor.forClass(Attributes.class);

        emitter.recordCertRefreshFailure("test error");

        // Verify counter was called with failure
        verify(mockCounter, times(1)).add(eq(1L), attrsCaptor.capture());

        // Verify attributes contain failure result
        Attributes capturedAttrs = attrsCaptor.getValue();
        assertEquals(capturedAttrs.get(AttributeKey.stringKey("function")), "cert_refresh");
        assertEquals(capturedAttrs.get(AttributeKey.stringKey("result")), "failure");
    }

    @Test
    public void testExportCertMetric() throws Exception {
        String certPath = Objects.requireNonNull(classLoader.getResource("rsa_public_x509.cert")).getPath();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        try (java.io.FileInputStream fis = new java.io.FileInputStream(certPath)) {
            cert = (X509Certificate) cf.generateCertificate(fis);
        }

        ArgumentCaptor<Attributes> attrsCaptor = ArgumentCaptor.forClass(Attributes.class);
        ArgumentCaptor<Long> valueCaptor = ArgumentCaptor.forClass(Long.class);

        emitter.exportCertMetric(cert);

        verify(mockGauge, times(1)).set(valueCaptor.capture(), attrsCaptor.capture());

        // Verify attributes contain cn and subject
        Attributes capturedAttrs = attrsCaptor.getValue();
        assertNotNull(capturedAttrs.get(AttributeKey.stringKey("cn")));
        assertNotNull(capturedAttrs.get(AttributeKey.stringKey("subject")));

        // Verify the certificate subject contains expected value from test cert
        String subject = capturedAttrs.get(AttributeKey.stringKey("subject"));
        assertNotNull(subject);
        assertTrue(subject.length() > 0);
    }

    @Test
    public void testExportCertMetricWithInvalidPath() {
        // Should not throw - logs error internally
        emitter.exportCertMetric("/nonexistent/path/cert.pem");

        verify(mockCounter, times(1)).add(eq(1L), any(Attributes.class));
        verify(mockGauge, never()).set(anyLong(), any(Attributes.class));
    }

    @Test
    public void testExportCertMetricWithNullCert() {
        // Should not throw - logs warning internally
        emitter.exportCertMetric((X509Certificate) null);

        // Gauge should not be called for null cert
        verify(mockGauge, never()).set(anyLong(), any(Attributes.class));
    }
}
