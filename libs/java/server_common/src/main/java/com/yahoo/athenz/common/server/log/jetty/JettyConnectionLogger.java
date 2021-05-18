/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.log.jetty;

import com.yahoo.athenz.common.metrics.Metric;
import org.eclipse.jetty.io.ssl.SslHandshakeListener;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.yahoo.athenz.common.server.log.jetty.ExceptionCauseFetcher.getInnerCause;

public class JettyConnectionLogger extends AbstractLifeCycle implements SslHandshakeListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(JettyConnectionLogger.class);

    public static final String GENERAL_SSL_ERROR = "General SSLEngine problem";
    public static final String CONNECTION_LOGGER_METRIC_DEFAULT_NAME = "ssl_error";
    public static final String ATHENZ_PROP_SSL_LOGGER_METRIC_NAME = "athenz.jetty.container.ssl_logger_metric";

    private final ConnectionLog connectionLog;
    private final Metric metric;
    private final String metricName;

    public JettyConnectionLogger(ConnectionLog connectionLog, Metric metric) {
        this.connectionLog = connectionLog;
        this.metric = metric;
        metricName = System.getProperty(ATHENZ_PROP_SSL_LOGGER_METRIC_NAME, CONNECTION_LOGGER_METRIC_DEFAULT_NAME);
        LOGGER.info("Jetty connection logger is running");
    }

    //
    // AbstractLifeCycle methods start
    //
    @Override
    protected void doStop() {
        handleListenerInvocation("AbstractLifeCycle", "doStop", "", Collections.emptyList(), () -> {
            LOGGER.info("Jetty connection logger is stopped");
        });
    }

    @Override
    protected void doStart() {
        handleListenerInvocation("AbstractLifeCycle", "doStart", "", Collections.emptyList(), () -> {
            LOGGER.info("Jetty connection logger is started");
        });
    }
    //
    // AbstractLifeCycle methods stop
    //

    @Override
    public void handshakeFailed(Event event, Throwable failure) {
        SSLEngine sslEngine = event.getSSLEngine();
        handleListenerInvocation("SslHandshakeListener", "handshakeFailed", "sslEngine=%h,failure=%s", Stream.of(sslEngine, failure).collect(Collectors.toList()), () -> {
            ConnectionInfo info = ConnectionInfo.from(sslEngine);
            info.setSslHandshakeFailure(failure);
            connectionLog.log(info.toLogEntry());
            metric.increment(metricName, info.toMetric());
        });
    }

    private void handleListenerInvocation(
            String listenerType, String methodName, String methodArgumentsFormat, List<Object> methodArguments, ListenerHandler handler) {
        try {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(String.format(listenerType + "." + methodName + "(" + methodArgumentsFormat + ")", methodArguments.toArray()));
            }
            handler.run();
        } catch (Exception e) {
            LOGGER.warn(String.format("Exception in %s.%s listener: %s", listenerType, methodName, e.getMessage()), e);
        }
    }


    @FunctionalInterface
    private interface ListenerHandler {
        void run() throws Exception;
    }

    private static class ConnectionInfo {
        private final UUID uuid;
        private final String peerHost;
        private final int peerPort;

        private String sslHandshakeFailureException;
        private String sslHandshakeFailureMessage;
        private String sslHandshakeFailureCause;
        private String sslHandshakeFailureType;

        private ConnectionInfo(UUID uuid, String peerHost, int peerPort) {
            this.uuid = uuid;
            this.peerHost = peerHost;
            this.peerPort = peerPort;
        }

        static ConnectionInfo from(SSLEngine sslEngine) {
            return new ConnectionInfo(
                    UUID.randomUUID(),
                    sslEngine.getPeerHost(),
                    sslEngine.getPeerPort());
        }

        synchronized ConnectionInfo setSslHandshakeFailure(Throwable exception) {
            SSLHandshakeException sslHandshakeException = (SSLHandshakeException) exception;
            this.sslHandshakeFailureException = sslHandshakeException.getClass().getName();
            this.sslHandshakeFailureMessage = sslHandshakeException.getMessage();
            // If the error isn't clear, try to get it from the exception inner cause
            if (exception.getCause() != null) {
                this.sslHandshakeFailureCause = getInnerCause(exception, sslHandshakeException.getMessage());
                // If the cause is identical to the message, no need to print it so we'll set it to null
                if (this.sslHandshakeFailureCause != null && this.sslHandshakeFailureCause.equals(this.sslHandshakeFailureMessage)) {
                    this.sslHandshakeFailureCause = null;
                }
            }
            this.sslHandshakeFailureType = SslHandshakeFailure.fromSslHandshakeException(sslHandshakeException)
                    .map(SslHandshakeFailure::failureType)
                    .orElse("UNKNOWN");
            return this;
        }

        synchronized ConnectionLogEntry toLogEntry() {
            ConnectionLogEntry.Builder builder = ConnectionLogEntry.builder(uuid, Instant.now());
            if (peerHost != null) {
                builder.withPeerAddress(peerHost);
                builder.withPeerPort(peerPort);
            }
            if (sslHandshakeFailureException != null && sslHandshakeFailureMessage != null && sslHandshakeFailureType != null) {
                builder.withSslHandshakeFailureException(sslHandshakeFailureException)
                        .withSslHandshakeFailureMessage(sslHandshakeFailureMessage)
                        .withSslHandshakeFailureType(sslHandshakeFailureType);
                if (sslHandshakeFailureCause != null) {
                    builder.withSslHandshakeFailureCause(sslHandshakeFailureCause);
                }
            }
            return builder.build();
        }

        synchronized String[] toMetric() {
            String failureTypeKey = "failureType";
            String failureTypeValue = "unknown";
            if (sslHandshakeFailureType != null) {
                failureTypeValue = sslHandshakeFailureType;
            }
            return new String[] {
                    failureTypeKey, failureTypeValue
            };
        }
    }
}
