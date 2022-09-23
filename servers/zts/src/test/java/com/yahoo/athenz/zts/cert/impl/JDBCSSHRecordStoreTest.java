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
package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.sql.Connection;
import java.sql.SQLException;

import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertFalse;

public class JDBCSSHRecordStoreTest {

    @Test
    public void testGetConnection() throws SQLException {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        Connection mockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        JDBCSSHRecordStore store = new JDBCSSHRecordStore(mockDataSrc);
        assertNotNull(store.getConnection());
        store.clearConnections();
    }
    
    @Test
    public void testGetConnectionException() throws SQLException {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        Mockito.doThrow(new SQLException()).when(mockDataSrc).getConnection();
        try {
            JDBCSSHRecordStore store = new JDBCSSHRecordStore(mockDataSrc);
            store.getConnection();
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testLog() {

        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        JDBCSSHRecordStore store = new JDBCSSHRecordStore(mockDataSrc);

        Principal principal = SimplePrincipal.create("user", "joe", "creds");

        // make sure no exceptions are thrown when processing log request

        store.log(principal, "10.11.12.13", "athenz.api", "1234");
    }

    @Test
    public void testEnableNotifications() {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        JDBCSSHRecordStore store = new JDBCSSHRecordStore(mockDataSrc);
        boolean isEnabled = store.enableNotifications(null, null, null);
        assertFalse(isEnabled);

        NotificationManager notificationManager = Mockito.mock(NotificationManager.class);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        String serverName = "testServer";
        isEnabled = store.enableNotifications(notificationManager, rolesProvider, serverName);
        assertFalse(isEnabled); // Not supported for FileCertStore even if all dependencies provided
    }
}
