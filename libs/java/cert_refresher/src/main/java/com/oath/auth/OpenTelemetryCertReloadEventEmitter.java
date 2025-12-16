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

import com.yahoo.athenz.auth.util.Crypto;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.LongGauge;
import io.opentelemetry.api.metrics.Meter;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * OpenTelemetry metrics for X.509 certificate refresh events.
 * 
 * Metrics:
 * - athenz_cert_refresher.refresh.result_total: Counter with result attribute (success/failure)
 * - athenz_cert_refresher.cert.validity.remaining_secs: Gauge - seconds until cert expires
 */
public class OpenTelemetryCertReloadEventEmitter {

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(OpenTelemetryCertReloadEventEmitter.class);

    private static final String SCOPE_NAME = "athenz.cert_refresher";

    private static final String COUNTER_NAME = "athenz_cert_refresher.refresh.result_total";
    private static final String COUNTER_DESC = "Counts the total number of certificate refresh operations by result";

    private static final String GAUGE_VALIDITY_NAME = "athenz_cert_refresher.cert.validity.remaining_secs";
    private static final String GAUGE_VALIDITY_DESC = "Number of seconds remaining before the current TLS certificate expires";

    public static final String RESULT_SUCCESS = "success";
    public static final String RESULT_FAILURE = "failure";

    private final LongCounter refreshResultCounter;
    private final LongGauge certValidityRemainingSecs;

    /**
     * Create OpenTelemetry X.509 cert refresh metrics.
     *
     */
    public OpenTelemetryCertReloadEventEmitter() {
        Meter meter = GlobalOpenTelemetry.get().getMeter(SCOPE_NAME);

        this.refreshResultCounter = meter.counterBuilder(COUNTER_NAME)
                .setDescription(COUNTER_DESC)
                .build();

        this.certValidityRemainingSecs = meter.gaugeBuilder(GAUGE_VALIDITY_NAME)
                .setDescription(GAUGE_VALIDITY_DESC)
                .ofLongs()
                .build();
        
        LOGGER.info("OpenTelemetry cert refresh metrics initialized");
    }

    /**
     * Record a successful certificate refresh (result: success).
     *
     * @param certPath path to the certificate file
     */
    public void recordCertRefresh(String certPath) {
        recordRefreshResult(true);
        exportCertMetric(certPath);
    }

    /**
     * Record a failed certificate refresh (result: failure).
     *
     * @param errorMessage error description
     */
    public void recordCertRefreshFailure(String errorMessage) {
        recordRefreshResult( false);
        LOGGER.error("Certificate refresh failed: {}", errorMessage);
    }

    /**
     * Record refresh result with counter.
     */
    private void recordRefreshResult(boolean success) {
        String result = success ? RESULT_SUCCESS : RESULT_FAILURE;
        
        Attributes attrs = Attributes.builder()
                .put("function", "cert_refresh")
                .put("result", result)
                .build();
        
        refreshResultCounter.add(1, attrs);
    }

    /**
     * Export certificate validity metric
     *
     * @param certPath path to the certificate file
     */
    public void exportCertMetric(String certPath) {
        try (FileInputStream fis = new FileInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            exportCertMetric(cert);
        } catch (Exception e) {
            LOGGER.error("Failed to read certificate from {}: {}", certPath, e.getMessage());
        }
    }

    /**
     * Export certificate validity metric
     *
     * @param cert the X.509 certificate
     */
    public void exportCertMetric(X509Certificate cert) {
        if (cert == null) {
            LOGGER.warn("exportCertMetric: called with null cert");
            return;
        }
        
        String cn = Crypto.extractX509CertCommonName(cert);
        String subject = cert.getSubjectX500Principal().getName();
        long secsUntilExpiry = (cert.getNotAfter().getTime() - System.currentTimeMillis()) / 1000;

        Attributes attrs = Attributes.builder()
                .put("cn", cn != null ? cn : "")
                .put("subject", subject != null ? subject : "")
                .build();
        
        certValidityRemainingSecs.set(secsUntilExpiry, attrs);
    }
}
