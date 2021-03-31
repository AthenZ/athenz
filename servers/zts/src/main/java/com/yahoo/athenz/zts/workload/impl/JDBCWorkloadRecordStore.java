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
package com.yahoo.athenz.zts.workload.impl;

import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import com.yahoo.athenz.zts.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;

public class JDBCWorkloadRecordStore implements WorkloadRecordStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(JDBCWorkloadRecordStore.class);
    PoolableDataSource src;
    private int opTimeout = 10; //in seconds

    public JDBCWorkloadRecordStore(PoolableDataSource src) {
        this.src = src;
    }

    @Override
    public WorkloadRecordStoreConnection getConnection() {
        try {
            JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(src.getConnection());
            jdbcConn.setOperationTimeout(opTimeout);
            return jdbcConn;
        } catch (SQLException ex) {
            LOGGER.error("getConnection: {}", ex.getMessage());
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, ex.getMessage());
        }
    }

    @Override
    public void setOperationTimeout(int opTimeout) {
        this.opTimeout = opTimeout;
    }

    @Override
    public void clearConnections() {
        src.clearPoolConnections();
    }
}
