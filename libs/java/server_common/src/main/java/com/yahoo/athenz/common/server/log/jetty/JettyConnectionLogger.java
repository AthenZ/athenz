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
import org.eclipse.jetty.io.Connection;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.io.SocketChannelEndPoint;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.eclipse.jetty.io.ssl.SslHandshakeListener;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.yahoo.athenz.common.server.log.jetty.ExceptionCauseFetcher.getInnerCause;

public class JettyConnectionLogger extends AbstractLifeCycle implements Connection.Listener, HttpChannel.Listener, SslHandshakeListener {

    public static final String GENERAL_SSL_ERROR = "General SSLEngine problem";
    public static final String METRIC_NAME = "ssl_error";
    private static final Logger LOGGER = LoggerFactory.getLogger(JettyConnectionLogger.class.getName());

    private final ConcurrentMap<SocketChannelEndPoint, ConnectionInfo> connectionInfo = new ConcurrentHashMap<>();
    private final ConcurrentMap<SSLEngine, ConnectionInfo> sslToConnectionInfo = new ConcurrentHashMap<>();

    private final ConnectionLog connectionLog;
    private final Metric metric;

    public JettyConnectionLogger(ConnectionLog connectionLog, Metric metric) {
        this.connectionLog = connectionLog;
        this.metric = metric;
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

    //
    // Connection.Listener methods start
    //
    @Override
    public void onOpened(Connection connection) {
        handleListenerInvocation("Connection.Listener", "onOpened", "%h", Stream.of(connection).collect(Collectors.toList()), () -> {
            SocketChannelEndPoint endpoint = findUnderlyingSocketEndpoint(connection.getEndPoint());
            ConnectionInfo info = connectionInfo.get(endpoint);
            if (info == null) {
                info = ConnectionInfo.from(endpoint);
                connectionInfo.put(endpoint, info);
            }
            if (connection instanceof SslConnection) {
                SSLEngine sslEngine = ((SslConnection) connection).getSSLEngine();
                sslToConnectionInfo.put(sslEngine, info);
            }
            if (connection.getEndPoint() instanceof ProxyConnectionFactory.ProxyEndPoint) {
                InetSocketAddress remoteAddress = connection.getEndPoint().getRemoteAddress();
                info.setRemoteAddress(remoteAddress);
            }
        });
    }

    @Override
    public void onClosed(Connection connection) {
        handleListenerInvocation("Connection.Listener", "onClosed", "%h", Stream.of(connection).collect(Collectors.toList()), () -> {
            SocketChannelEndPoint endpoint = findUnderlyingSocketEndpoint(connection.getEndPoint());
            ConnectionInfo info = connectionInfo.get(endpoint);
            if (info == null) {
                return; // Closed connection already handled
            }
            if (!endpoint.isOpen()) {
                info.setClosedAt(System.currentTimeMillis());
                // Only print / report failed connections
                if (info.sslHandshakeFailureException != null) {
                    connectionLog.log(info.toLogEntry());
                    metric.increment(METRIC_NAME, info.toMetric());
                }
                connectionInfo.remove(endpoint);
                if (connection instanceof SslConnection) {
                    SSLEngine sslEngine = ((SslConnection) connection).getSSLEngine();
                    sslToConnectionInfo.remove(sslEngine);
                }
            }
        });
    }
    //
    // Connection.Listener methods end
    //

    //
    // SslHandshakeListener methods start
    //
    @Override
    public void handshakeSucceeded(Event event) {
        SSLEngine sslEngine = event.getSSLEngine();
        handleListenerInvocation("SslHandshakeListener", "handshakeSucceeded", "sslEngine=%h", Stream.of(sslEngine).collect(Collectors.toList()), () -> {
            sslToConnectionInfo.remove(sslEngine);
        });
    }

    @Override
    public void handshakeFailed(Event event, Throwable failure) {
        SSLEngine sslEngine = event.getSSLEngine();
        handleListenerInvocation("SslHandshakeListener", "handshakeFailed", "sslEngine=%h,failure=%s", Stream.of(sslEngine, failure).collect(Collectors.toList()), () -> {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(failure.getMessage());
            }
            ConnectionInfo info = sslToConnectionInfo.remove(sslEngine);
            if (info != null) {
                info.setSslHandshakeFailure(failure);
            }
        });
    }
    //
    // SslHandshakeListener methods end
    //

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

    /**
     * Protocol layers are connected through each {@link Connection}'s {@link EndPoint} reference.
     * This methods iterates through the endpoints recursively to find the underlying socket endpoint.
     */
    private static SocketChannelEndPoint findUnderlyingSocketEndpoint(EndPoint endpoint) {
        if (endpoint instanceof SocketChannelEndPoint) {
            return (SocketChannelEndPoint) endpoint;
        } else if (endpoint instanceof SslConnection.DecryptedEndPoint) {
            SslConnection.DecryptedEndPoint decryptedEndpoint = (SslConnection.DecryptedEndPoint) endpoint;
            return findUnderlyingSocketEndpoint(decryptedEndpoint.getSslConnection().getEndPoint());
        } else if (endpoint instanceof ProxyConnectionFactory.ProxyEndPoint) {
            ProxyConnectionFactory.ProxyEndPoint proxyEndpoint = (ProxyConnectionFactory.ProxyEndPoint) endpoint;
            return findUnderlyingSocketEndpoint(proxyEndpoint.unwrap());
        } else {
            throw new IllegalArgumentException("Unknown connection endpoint type: " + endpoint.getClass().getName());
        }
    }

    @FunctionalInterface
    private interface ListenerHandler {
        void run() throws Exception;
    }

    private static class ConnectionInfo {
        private final UUID uuid;
        private final long createdAt;
        private final InetSocketAddress localAddress;
        private final InetSocketAddress peerAddress;

        private long closedAt = 0;
        private InetSocketAddress remoteAddress;
        private String sslHandshakeFailureException;
        private String sslHandshakeFailureMessage;
        private String sslHandshakeFailureCause;
        private String sslHandshakeFailureType;

        private ConnectionInfo(UUID uuid, long createdAt, InetSocketAddress localAddress, InetSocketAddress peerAddress) {
            this.uuid = uuid;
            this.createdAt = createdAt;
            this.localAddress = localAddress;
            this.peerAddress = peerAddress;
        }

        static ConnectionInfo from(SocketChannelEndPoint endpoint) {
            return new ConnectionInfo(
                    UUID.randomUUID(),
                    endpoint.getCreatedTimeStamp(),
                    endpoint.getLocalAddress(),
                    endpoint.getRemoteAddress());
        }

        synchronized ConnectionInfo setClosedAt(long closedAt) {
            this.closedAt = closedAt;
            return this;
        }

        synchronized ConnectionInfo setRemoteAddress(InetSocketAddress remoteAddress) {
            this.remoteAddress = remoteAddress;
            return this;
        }

        synchronized ConnectionInfo setSslHandshakeFailure(Throwable exception) {
            SSLHandshakeException sslHandshakeException = (SSLHandshakeException) exception;
            this.sslHandshakeFailureException = sslHandshakeException.getClass().getName();
            this.sslHandshakeFailureMessage = sslHandshakeException.getMessage();
            // If the error isn't clear, try to get it from the exception inner cause
            if (exception.getCause() != null && this.sslHandshakeFailureMessage == GENERAL_SSL_ERROR) {
                this.sslHandshakeFailureCause = getInnerCause(exception, sslHandshakeException.getMessage());
            }
            this.sslHandshakeFailureType = SslHandshakeFailure.fromSslHandshakeException(sslHandshakeException)
                    .map(SslHandshakeFailure::failureType)
                    .orElse("UNKNOWN");
            return this;
        }

        synchronized ConnectionLogEntry toLogEntry() {
            ConnectionLogEntry.Builder builder = ConnectionLogEntry.builder(uuid, Instant.ofEpochMilli(createdAt));
            if (closedAt > 0) {
                builder.withDuration((closedAt - createdAt) / 1000D);
            }
            if (peerAddress != null) {
                builder.withPeerAddress(peerAddress.getHostString())
                        .withPeerPort(peerAddress.getPort());
            }
            if (localAddress != null) {
                builder.withLocalAddress(localAddress.getHostString())
                        .withLocalPort(localAddress.getPort());
            }
            if (remoteAddress != null) {
                builder.withRemoteAddress(remoteAddress.getHostString())
                        .withRemotePort(remoteAddress.getPort());
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
            String peerAddressKey = "peerAddress";
            String peerAddressValue = "unknown";
            String failureTypeKey = "failureType";
            String failureTypeValue = "unknown";
            if (peerAddress != null) {
                peerAddressValue = peerAddress.getHostString();
            }
            if (sslHandshakeFailureType != null) {
                failureTypeValue = sslHandshakeFailureType;
            }
            return new String[] {
                    peerAddressKey, peerAddressValue,
                    failureTypeKey, failureTypeValue
            };
        }
    }
}
