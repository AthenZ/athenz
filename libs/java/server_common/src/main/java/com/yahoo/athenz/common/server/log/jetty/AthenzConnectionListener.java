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

import org.eclipse.jetty.io.Connection;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.net.ssl.SSLEngine;
import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AthenzConnectionListener implements Connection.Listener {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final Map<SSLEngine, ConnectionData> OPENED_SSL_ENGINES_MAP = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduledExecutor;

    public static final String ATHENZ_PROP_CLEANUP_CLOSED_CONNECTION_INTERVAL = "athenz.cleanup_closed_connection_interval";

    /** Get the {@link ConnectionData} for a given {@link SSLEngine} */
    public static @Nullable ConnectionData getConnectionDataBySslEngine(SSLEngine sslEngine) {
        return OPENED_SSL_ENGINES_MAP.get(sslEngine);
    }
    
    public AthenzConnectionListener() {
        LOG.debug("AthenzConnectionListener is created");
        int cleanupClosedConnectionsRefreshInterval = Integer.parseInt(System.getProperty(ATHENZ_PROP_CLEANUP_CLOSED_CONNECTION_INTERVAL, "60000"));

        // Add a cleaner thread to remove closed connections who were not deleted from the map.
        // this map should not grow at all since we are removing the entries when the connection is closed.
        // but in case of a bug, we want to make sure that we are not leaking memory.
        scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        scheduledExecutor.scheduleAtFixedRate(
                this::cleanupClosedConnections,
                cleanupClosedConnectionsRefreshInterval,
                cleanupClosedConnectionsRefreshInterval,
                TimeUnit.MILLISECONDS);
    }

    void cleanupClosedConnections() {

        int mapSize = OPENED_SSL_ENGINES_MAP.size();
        if (mapSize > 0) {
            
            LOG.info("OPENED_SSL_ENGINES_MAP size is: {}", OPENED_SSL_ENGINES_MAP.size());
            OPENED_SSL_ENGINES_MAP.entrySet().removeIf(entry -> {
                boolean openConnection = entry.getValue().sslConnection.getEndPoint().isOpen();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("connection data: {} is open: {}", entry.getValue(), openConnection);
                }
                return !openConnection;
            });
        }
    }

    /**
     * Shutdown hook for the scheduler
     */
    public void shutdown() {
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdownNow();
        }
    }

    @Override
    public void onOpened(Connection connection) {
        try {
            // Ignore non-SSL connections.
            if (!(connection instanceof SslConnection)) {
                return;
            }
            
            ConnectionData connectionData = new ConnectionData((SslConnection) connection);

            OPENED_SSL_ENGINES_MAP.put(connectionData.sslEngine, connectionData);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Adding connection data: {} to OPENED_SSL_ENGINES_MAP", connectionData);
            }

        } catch (Exception exception) {
            LOG.error("AthenzConnectionListener.onOpened: ", exception);
        }
    }

    @Override
    public void onClosed(Connection connection) {
        try {
            // Ignore non-SSL connections.
            if (!(connection instanceof SslConnection)) {
                return;
            }

            ConnectionData connectionData = OPENED_SSL_ENGINES_MAP.remove(((SslConnection) connection).getSSLEngine());

            if (LOG.isDebugEnabled()) {
                LOG.debug("Removed connection data: {} from OPENED_SSL_ENGINES_MAP", connectionData);
            }
            
        } catch (Exception exception) {
            LOG.error("AthenzConnectionListener.onClosed exception: ", exception);
        }
    }

}
