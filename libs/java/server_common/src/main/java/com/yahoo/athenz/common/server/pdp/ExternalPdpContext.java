/*
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
 */

package com.yahoo.athenz.common.server.pdp;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.RolesProvider;

import javax.net.ssl.SSLContext;
import java.util.concurrent.ExecutorService;

/**
 * Immutable set of server facilities passed to an
 * {@link ExternalPolicyDecisionPoint} during initialization.
 */
public final class ExternalPdpContext {

    private final String endpoint;
    private final SSLContext sslContext;
    private final RolesProvider rolesProvider;
    private final PrivateKeyStore privateKeyStore;
    private final ExecutorService executor;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int maxConnections;

    private ExternalPdpContext(final Builder builder) {
        this.endpoint = builder.endpoint;
        this.sslContext = builder.sslContext;
        this.rolesProvider = builder.rolesProvider;
        this.privateKeyStore = builder.privateKeyStore;
        this.executor = builder.executor;
        this.connectTimeoutMs = builder.connectTimeoutMs;
        this.readTimeoutMs = builder.readTimeoutMs;
        this.maxConnections = builder.maxConnections;
    }

    /**
     * @return configured PDP endpoint (class:// or https:// URI)
     */
    public String getEndpoint() {
        return endpoint;
    }

    /**
     * @return client SSL context with the server identity for mTLS
     */
    public SSLContext getSslContext() {
        return sslContext;
    }

    /**
     * @return read-only access to the server's domain role data
     */
    public RolesProvider getRolesProvider() {
        return rolesProvider;
    }

    /**
     * @return private key store for retrieving PDP credentials
     */
    public PrivateKeyStore getPrivateKeyStore() {
        return privateKeyStore;
    }

    /**
     * @return bounded executor for implementations that fan out calls
     */
    public ExecutorService getExecutor() {
        return executor;
    }

    public int getConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public int getReadTimeoutMs() {
        return readTimeoutMs;
    }

    public int getMaxConnections() {
        return maxConnections;
    }

    /**
     * Builder for {@link ExternalPdpContext}.
     */
    public static final class Builder {

        private String endpoint;
        private SSLContext sslContext;
        private RolesProvider rolesProvider;
        private PrivateKeyStore privateKeyStore;
        private ExecutorService executor;
        private int connectTimeoutMs;
        private int readTimeoutMs;
        private int maxConnections;

        public Builder endpoint(final String value) {
            endpoint = value;
            return this;
        }

        public Builder sslContext(final SSLContext value) {
            sslContext = value;
            return this;
        }

        public Builder rolesProvider(final RolesProvider value) {
            rolesProvider = value;
            return this;
        }

        public Builder privateKeyStore(final PrivateKeyStore value) {
            privateKeyStore = value;
            return this;
        }

        public Builder executor(final ExecutorService value) {
            executor = value;
            return this;
        }

        public Builder connectTimeoutMs(final int value) {
            connectTimeoutMs = value;
            return this;
        }

        public Builder readTimeoutMs(final int value) {
            readTimeoutMs = value;
            return this;
        }

        public Builder maxConnections(final int value) {
            maxConnections = value;
            return this;
        }

        public ExternalPdpContext build() {
            return new ExternalPdpContext(this);
        }
    }
}
