/*
 *
 *  Copyright The Athenz Authors
 *  
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package com.yahoo.athenz.common.server.log.jetty;

import org.eclipse.jetty.io.ssl.SslConnection;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import java.time.Instant;
import java.util.UUID;

import static com.yahoo.athenz.common.server.log.jetty.ExceptionCauseFetcher.getInnerCause;

/**
 * The life-cycle of the SSL connection is made of 3 steps.
 * A {@link ConnectionData} instance is attached to every SSL connection, and is known at any step, as follows:
 * <p>
 *    1. {@link AthenzConnectionListener#onOpened} is called when the connection is opened (before the SSL handshake).
 *       At this point, extracts the {@link SSLEngine} instance from the {@link SslConnection} and create a new 
 *       {@link ConnectionData} instance. 
 *       it is accessible by the {@link SSLEngine} instances, using {@link AthenzConnectionListener#getConnectionDataBySslEngine}.
 * <p>
 *    2. {@link JettyConnectionLogger} implements the {@link org.eclipse.jetty.io.ssl.SslHandshakeListener} and provides the
 *       {@link JettyConnectionLogger#handshakeFailed} that is being called after a failed handshake.
 *       At this point, the {@link SSLEngine} instance is known and we are able to use it to get the {@link ConnectionData} from step-1
 *        (using {@link AthenzConnectionListener#getConnectionDataBySslEngine}).
 * <p>
 *    3. {@link AthenzConnectionListener#onClosed} is called when the connection is closed.
 *       At this point, extracts the {@link SSLEngine} instance from the {@link SslConnection} and 
 *       use it to remove the map entries from OPENED_SSL_ENGINES_MAP.
 *
 */
public class ConnectionData {

    /** The {@link SslConnection} object that this instance is referring to */
    public final SslConnection sslConnection;

    /** The {@link SSLEngine} object that is managing the SSL for this connection */
    public final SSLEngine sslEngine;

    public String athenzPrincipal;

    private final UUID uuid;
    private final String peerHost;
    private final int peerPort;

    private String sslHandshakeFailureException;
    private String sslHandshakeFailureMessage;
    private String sslHandshakeFailureCause;
    private String sslHandshakeFailureType;
    
    public ConnectionData(SslConnection sslConnection) {
        this.sslConnection = sslConnection;
        this.sslEngine = sslConnection.getSSLEngine();
        this.uuid = UUID.randomUUID();
        this.peerHost = sslConnection.getSSLEngine().getPeerHost();
        this.peerPort = sslConnection.getSSLEngine().getPeerPort();
    }

    synchronized ConnectionData setSslHandshakeFailure(Throwable exception) {
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
        if (athenzPrincipal != null) {
            builder.withAthenzPrincipal(athenzPrincipal);
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
        String athenzPrincipalKey = "athenzPrincipal";
        String athenzPrincipalValue = "unknown";

        if (sslHandshakeFailureType != null) {
            failureTypeValue = sslHandshakeFailureType;
        }
        if (athenzPrincipal != null) {
            athenzPrincipalValue = athenzPrincipal;
        }
        return new String[] {
                failureTypeKey, failureTypeValue,
                athenzPrincipalKey, athenzPrincipalValue
        };
    }
    
    @Override
    public String toString() {
        return "ConnectionData{" +
                "athenzPrincipal='" + athenzPrincipal + '\'' +
                ", uuid=" + uuid +
                ", peerHost='" + peerHost + '\'' +
                ", peerPort=" + peerPort +
                ", sslHandshakeFailureException='" + sslHandshakeFailureException + '\'' +
                ", sslHandshakeFailureMessage='" + sslHandshakeFailureMessage + '\'' +
                ", sslHandshakeFailureCause='" + sslHandshakeFailureCause + '\'' +
                ", sslHandshakeFailureType='" + sslHandshakeFailureType + '\'' +
                '}';
    }
}
