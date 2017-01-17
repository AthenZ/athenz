/**
 * Copyright 2016 Yahoo Inc.
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

public class AthenzDataSource extends PoolingDataSource<PoolableConnection> implements PoolableDataSource {

    private static final Logger LOG = LoggerFactory.getLogger(AthenzDataSource.class);
    
    public AthenzDataSource(ObjectPool<PoolableConnection> pool) {
        super(pool);
    }

    @Override
    synchronized public void clearPoolConnections() {
        ObjectPool<PoolableConnection> pool = getPool();
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Clearing all active/idle (" + pool.getNumActive() + "/" +
                        pool.getNumIdle() + ") connections from the pool");
            }
            pool.clear();
        } catch (Exception ex) {
            LOG.error("Unable to clear connections from the pool: " + ex.getMessage());
        }
    }
}
