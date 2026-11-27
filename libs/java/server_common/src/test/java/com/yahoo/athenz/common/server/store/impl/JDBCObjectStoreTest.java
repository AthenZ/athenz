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
package com.yahoo.athenz.common.server.store.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.zms.DomainOptions;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.db.PoolableDataSource;

import static org.testng.Assert.*;

public class JDBCObjectStoreTest {

    @Test
    public void testResourceAccessRolePairsPerQueryProperty() throws Exception {
        String property = JDBCConsts.ZMS_PROP_JDBC_RESOURCE_ACCESS_ROLE_PAIRS_PER_QUERY;
        String original = System.getProperty(property);
        try {
            System.setProperty(property, "2");
            PoolableDataSource source = Mockito.mock(PoolableDataSource.class);
            Connection connection = Mockito.mock(Connection.class);
            PreparedStatement statement = Mockito.mock(PreparedStatement.class);
            ResultSet resultSet = Mockito.mock(ResultSet.class);
            Mockito.when(source.getConnection()).thenReturn(connection);
            Mockito.when(connection.prepareStatement(Mockito.anyString())).thenReturn(statement);
            Mockito.when(statement.executeQuery()).thenReturn(resultSet);

            JDBCObjectStore store = new JDBCObjectStore(source, null);
            JDBCConnection jdbcConn = (JDBCConnection) store.getConnection(true, true);
            assertTrue(jdbcConn.getRoleAssertions(Set.of("101:role1", "101:role2", "102:role3"),
                    null, "getRoleAssertions").isEmpty());
            Mockito.verify(connection, Mockito.times(2)).prepareStatement(Mockito.anyString());
            jdbcConn.close();

            System.setProperty(property, "32768");
            new JDBCObjectStore(source, null);

            for (String invalid : new String[] { "0", "-1", "invalid" }) {
                System.setProperty(property, invalid);
                Mockito.clearInvocations(connection);
                JDBCConnection fallbackConn = (JDBCConnection) new JDBCObjectStore(source, null).getConnection(true, true);
                assertTrue(fallbackConn.getRoleAssertions(Set.of("101:role1", "101:role2", "102:role3"),
                        null, "getRoleAssertions").isEmpty());
                Mockito.verify(connection).prepareStatement(Mockito.anyString());
                fallbackConn.close();
            }
        } finally {
            if (original == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, original);
            }
        }
    }

    @Test
    public void testGetConnection() throws Exception {
        
        PoolableDataSource mockDataRwSrc = Mockito.mock(PoolableDataSource.class);
        Connection rwMockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(rwMockConn).when(mockDataRwSrc).getConnection();
        
        PoolableDataSource mockDataRoSrc = Mockito.mock(PoolableDataSource.class);
        Connection roMockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(roMockConn).when(mockDataRoSrc).getConnection();

        JDBCObjectStore store = new JDBCObjectStore(mockDataRwSrc, mockDataRoSrc);
        store.setDomainOptions(new DomainOptions());
        store.setTagLimit(100, 25, 25, 25, 25);
        
        JDBCConnection jdbcConn = (JDBCConnection) store.getConnection(true, true);
        assertEquals(jdbcConn.con, rwMockConn);
        
        jdbcConn = (JDBCConnection) store.getConnection(true, false);
        assertEquals(jdbcConn.con, roMockConn);
    }
    
    @Test
    public void testGetConnectionReadWriteOnly() throws Exception {
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
    public void testGetConnectionReadOnly() throws Exception {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        Connection mockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        JDBCObjectStore store = new JDBCObjectStore(null, mockDataSrc);
        assertNotNull(store.getConnection(true, false));
    }
    
    @Test
    public void testGetConnectionException() throws Exception {
        PoolableDataSource mockDataRwSrc = Mockito.mock(PoolableDataSource.class);
        Mockito.doThrow(new SQLException()).when(mockDataRwSrc).getConnection();
        PoolableDataSource mockDataRoSrc = Mockito.mock(PoolableDataSource.class);
        Mockito.doThrow(new SQLException()).when(mockDataRoSrc).getConnection();
        try {
            JDBCObjectStore store = new JDBCObjectStore(mockDataRwSrc, mockDataRoSrc);
            store.getConnection(true, true);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof ServerResourceException);
        }
        try {
            JDBCObjectStore store = new JDBCObjectStore(mockDataRwSrc, mockDataRoSrc);
            store.getConnection(true, true);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof ServerResourceException);
        }
    }
    
    @Test
    public void testGetReadWriteConnectionException() throws Exception {
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

    @Test
    public void testObjectStoreInterface() throws ServerResourceException {
        ObjectStore store = new ObjectStore() {
            @Override
            public JDBCConnection getConnection(boolean readWrite, boolean checkOperationTimeout) {
                return null;
            }

            @Override
            public void setOperationTimeout(int opTimeout) {
            }

            @Override
            public void setTagLimit(int domainLimit, int roleLimit, int groupLimit, int policyLimit, int serviceLimit) {
            }

            @Override
            public void clearConnections() {
            }
        };

        // call/test default object store methods

        store.setOperationTimeout(120);
        store.setTagLimit(100, 20, 20, 20, 20);
        store.clearConnections();
        store.setDomainOptions(new DomainOptions());
        assertNull(store.getConnection(false, false));
    }
}
