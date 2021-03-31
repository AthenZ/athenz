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
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.sql.Connection;
import java.sql.SQLException;

import static org.testng.Assert.*;

public class JDBCWorkloadRecordStoreTest {
    @Test
    public void testGetConnection() throws SQLException {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        Connection mockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        JDBCWorkloadRecordStore store = new JDBCWorkloadRecordStore(mockDataSrc);
        assertNotNull(store.getConnection());
        store.setOperationTimeout(20);
        store.clearConnections();
    }

    @Test
    public void testGetConnectionException() throws SQLException {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        Mockito.doThrow(new SQLException()).when(mockDataSrc).getConnection();
        try {
            JDBCWorkloadRecordStore store = new JDBCWorkloadRecordStore(mockDataSrc);
            store.getConnection();
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
    }

}