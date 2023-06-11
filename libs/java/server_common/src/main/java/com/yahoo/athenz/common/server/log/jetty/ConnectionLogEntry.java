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

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public class ConnectionLogEntry {
    private final UUID id;
    private final Instant timestamp;
    private final Double durationSeconds;
    private final String peerAddress;
    private final Integer peerPort;
    private final String sslHandshakeFailureException;
    private final String sslHandshakeFailureMessage;
    private final String sslHandshakeFailureCause;
    private final String sslHandshakeFailureType;
    private final String athenzPrincipal;

    private ConnectionLogEntry(Builder builder) {
        this.id = builder.id;
        this.timestamp = builder.timestamp;
        this.durationSeconds = builder.durationSeconds;
        this.peerAddress = builder.peerAddress;
        this.peerPort = builder.peerPort;
        this.sslHandshakeFailureException = builder.sslHandshakeFailureException;
        this.sslHandshakeFailureMessage = builder.sslHandshakeFailureMessage;
        this.sslHandshakeFailureCause = builder.sslHandshakeFailureCause;
        this.sslHandshakeFailureType = builder.sslHandshakeFailureType;
        this.athenzPrincipal = builder.athenzPrincipal;
    }

    public static Builder builder(UUID id, Instant timestamp) {
        return new Builder(id, timestamp);
    }

    public String id() {
        return id.toString();
    }

    public Instant timestamp() {
        return timestamp;
    }

    public Optional<Double> durationSeconds() {
        return Optional.ofNullable(durationSeconds);
    }

    public Optional<String> peerAddress() {
        return Optional.ofNullable(peerAddress);
    }

    public Optional<Integer> peerPort() {
        return Optional.ofNullable(peerPort);
    }

    public Optional<String> sslHandshakeFailureException() {
        return Optional.ofNullable(sslHandshakeFailureException);
    }

    public Optional<String> sslHandshakeFailureMessage() {
        return Optional.ofNullable(sslHandshakeFailureMessage);
    }

    public Optional<String> sslHandshakeFailureCause() {
        return Optional.ofNullable(sslHandshakeFailureCause);
    }

    public Optional<String> sslHandshakeFailureType() {
        return Optional.ofNullable(sslHandshakeFailureType);
    }

    public Optional<String> athenzPrincipal() {
        return Optional.ofNullable(athenzPrincipal);
    }
    
    public static class Builder {
        private final UUID id;
        private final Instant timestamp;
        private Double durationSeconds;
        private String peerAddress;
        private Integer peerPort;
        private Integer remotePort;
        private String sslHandshakeFailureException;
        private String sslHandshakeFailureMessage;
        private String sslHandshakeFailureCause;
        private String sslHandshakeFailureType;
        private String athenzPrincipal;

        Builder(UUID id, Instant timestamp) {
            this.id = id;
            this.timestamp = timestamp;
        }

        public Builder withDuration(double durationSeconds) {
            this.durationSeconds = durationSeconds;
            return this;
        }

        public Builder withPeerAddress(String peerAddress) {
            this.peerAddress = peerAddress;
            return this;
        }

        public Builder withPeerPort(int peerPort) {
            this.peerPort = peerPort;
            return this;
        }

        public Builder withSslHandshakeFailureException(String exception) {
            this.sslHandshakeFailureException = exception;
            return this;
        }

        public Builder withSslHandshakeFailureMessage(String message) {
            this.sslHandshakeFailureMessage = message;
            return this;
        }

        public Builder withSslHandshakeFailureCause(String message) {
            this.sslHandshakeFailureCause = message;
            return this;
        }

        public Builder withSslHandshakeFailureType(String type) {
            this.sslHandshakeFailureType = type;
            return this;
        }

        public Builder withAthenzPrincipal(String athenzPrincipal) {
            this.athenzPrincipal = athenzPrincipal;
            return this;
        }
        
        public ConnectionLogEntry build() {
            return new ConnectionLogEntry(this);
        }
    }
}
