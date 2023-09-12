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
package com.yahoo.athenz.zms.store.impl.jdbc;

import java.sql.Connection;
import java.sql.SQLException;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.db.PoolableDataSource;

import static org.testng.Assert.*;

public class JDBCObjectStoreTest {

    @Test
    public void testGetConnection() throws SQLException {
        
        PoolableDataSource mockDataRwSrc = Mockito.mock(PoolableDataSource.class);
        Connection rwMockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(rwMockConn).when(mockDataRwSrc).getConnection();
        
        PoolableDataSource mockDataRoSrc = Mockito.mock(PoolableDataSource.class);
        Connection roMockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(roMockConn).when(mockDataRoSrc).getConnection();

        JDBCObjectStore store = new JDBCObjectStore(mockDataRwSrc, mockDataRoSrc);
        
        JDBCConnection jdbcConn = (JDBCConnection) store.getConnection(true, true);
        assertEquals(jdbcConn.con, rwMockConn);
        
        jdbcConn = (JDBCConnection) store.getConnection(true, false);
        assertEquals(jdbcConn.con, roMockConn);
    }
    
    @Test
    public void testGetConnectionReadWriteOnly() throws SQLException {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        Connection mockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        JDBCObjectStore store = new JDBCObjectStore(mockDataSrc, null);
        store.setOperationTimeout(60);
        assertNotNull(store.getConnection(true, true));
        
        // without read store we should also get a connection for a read
        // only operation
        assertNotNull(store.getConnection(true, true));

        store.clearConnections();
    }
    
    @Test
    public void testGetConnectionReadOnly() throws SQLException {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        Connection mockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        JDBCObjectStore store = new JDBCObjectStore(null, mockDataSrc);
        assertNotNull(store.getConnection(true, false));
    }
    
    @Test
    public void testGetConnectionException() throws SQLException {
        PoolableDataSource mockDataRwSrc = Mockito.mock(PoolableDataSource.class);
        Mockito.doThrow(new SQLException()).when(mockDataRwSrc).getConnection();
        PoolableDataSource mockDataRoSrc = Mockito.mock(PoolableDataSource.class);
        Mockito.doThrow(new SQLException()).when(mockDataRoSrc).getConnection();
        try {
            JDBCObjectStore store = new JDBCObjectStore(mockDataRwSrc, mockDataRoSrc);
            store.getConnection(true, true);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
        try {
            JDBCObjectStore store = new JDBCObjectStore(mockDataRwSrc, mockDataRoSrc);
            store.getConnection(true, true);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testGetReadWriteConnectionException() throws SQLException {
        PoolableDataSource mockDataRwSrc = Mockito.mock(PoolableDataSource.class);
        Connection mockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(mockConn).when(mockDataRwSrc).getConnection();
        PoolableDataSource mockDataRoSrc = Mockito.mock(PoolableDataSource.class);
        Mockito.doThrow(new SQLException()).when(mockDataRoSrc).getConnection();
        JDBCObjectStore store = new JDBCObjectStore(mockDataRwSrc, mockDataRoSrc);
        
        // we should get back same read-write connection for both cases
        
        JDBCConnection jdbcConn = (JDBCConnection) store.getConnection(true, true);
        assertEquals(jdbcConn.con, mockConn);
        
        jdbcConn = (JDBCConnection) store.getConnection(true, false);
        assertEquals(jdbcConn.con, mockConn);
    }
}
