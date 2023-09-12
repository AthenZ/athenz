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
package com.yahoo.athenz.common.server.db;

import org.apache.commons.dbcp2.PoolableConnection;
import org.apache.commons.dbcp2.PoolingDataSource;
import org.apache.commons.pool2.ObjectPool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

public class AthenzDataSource extends PoolingDataSource<PoolableConnection> implements PoolableDataSource {

    private static final Logger LOG = LoggerFactory.getLogger(AthenzDataSource.class);

    public static final String ATHENZ_PROP_DATASTORE_NETWORK_TIMEOUT = "athenz.datastore.network_timeout";
    public static final String ATHENZ_PROP_DATASTORE_TIMEOUT_THREADS = "athenz.datastore.timeout_threads";

    private final ScheduledExecutorService timeoutThreadPool;
    private final int networkTimeout;

    public AthenzDataSource(ObjectPool<PoolableConnection> pool) {

        super(pool);

        int timeoutThreads = Integer.parseInt(System.getProperty(ATHENZ_PROP_DATASTORE_TIMEOUT_THREADS, "8"));
        if (timeoutThreads <= 0) {
            timeoutThreads = 1;
        }
        networkTimeout = Integer.parseInt(System.getProperty(ATHENZ_PROP_DATASTORE_NETWORK_TIMEOUT, "0"));

        // create our executors pool

        timeoutThreadPool = Executors.newScheduledThreadPool(timeoutThreads);
    }

    @Override
    synchronized public void clearPoolConnections() {
        ObjectPool<PoolableConnection> pool = getPool();
        try {
            LOG.info("Clearing all active/idle ({}/{}) connections from the pool",
                    pool.getNumActive(), pool.getNumIdle());
            pool.clear();
        } catch (Exception ex) {
            LOG.error("Unable to clear connections from the pool", ex);
        }
    }

    @Override
    public Connection getConnection() throws SQLException {
        Connection conn = super.getConnection();
        if (networkTimeout > 0) {
            conn.setNetworkTimeout(timeoutThreadPool, networkTimeout);
        }
        return conn;
    }
}
