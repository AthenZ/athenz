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
import org.apache.commons.pool2.ObjectPool;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.testng.Assert.assertNotNull;

public class AthenzDataSourceTest {

    @Test
    public void testClearPoolConnections() {
        Properties props = new Properties();
        props.setProperty("user", "user");
        props.setProperty("password", "password");

        PoolableDataSource src = DataSourceFactory.create("jdbc:mysql:localhost:3306/athenz", props);
        assertNotNull(src);
        src.clearPoolConnections();
    }

    @Test
    public void testClearPoolConnectionsException() throws Exception {

        ObjectPool<PoolableConnection> pool = Mockito.mock(ObjectPool.class);
        Mockito.doThrow(new SQLException()).when(pool).clear();
        AthenzDataSource dataSource = new AthenzDataSource(pool);
        dataSource.clearPoolConnections();
    }

    @Test
    public void testGetConnection() throws Exception {

        System.setProperty("athenz.db.pool_validation_query", "");
        System.setProperty("athenz.datastore.timeout_threads", "-3");

        MockConnectionFactory connectionFactory = new MockConnectionFactory();
        Connection connection = Mockito.mock(Connection.class);
        Mockito.when(connection.isValid(anyInt())).thenReturn(true);
        connectionFactory.setConnection(connection);

        PoolableDataSource src = DataSourceFactory.create(connectionFactory);
        assertNotNull(src);

        Connection conn = src.getConnection();
        assertNotNull(conn);

        System.clearProperty("athenz.db.pool_validation_query");
        System.clearProperty("athenz.datastore.timeout_threads");
    }

    @Test
    public void testGetConnectionWithNetorkOption() throws Exception {

        System.setProperty("athenz.db.pool_validation_query", "");
        System.setProperty("athenz.datastore.network_timeout", "20000");

        MockConnectionFactory connectionFactory = new MockConnectionFactory();
        Connection connection = Mockito.mock(Connection.class);
        Mockito.when(connection.isValid(anyInt())).thenReturn(true);
        connectionFactory.setConnection(connection);

        PoolableDataSource src = DataSourceFactory.create(connectionFactory);
        assertNotNull(src);

        Connection conn = src.getConnection();
        assertNotNull(conn);

        System.clearProperty("athenz.db.pool_validation_query");
        System.clearProperty("athenz.datastore.network_timeout");
    }
}
