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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.SQLException;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.db.PoolableDataSource;

import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertFalse;

public class JDBCCertRecordStoreTest {

    @Test
    public void testGetConnection() throws SQLException {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        Connection mockConn = Mockito.mock(Connection.class);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        JDBCCertRecordStore store = new JDBCCertRecordStore(mockDataSrc);
        assertNotNull(store.getConnection());
        store.clearConnections();
    }
    
    @Test
    public void testGetConnectionException() throws SQLException {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        Mockito.doThrow(new SQLException()).when(mockDataSrc).getConnection();
        try {
            JDBCCertRecordStore store = new JDBCCertRecordStore(mockDataSrc);
            store.getConnection();
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testLog() {

        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        JDBCCertRecordStore store = new JDBCCertRecordStore(mockDataSrc);

        File file = new File("src/test/resources/cert_log.pem");
        String pem = null;
        try {
            pem = new String(Files.readAllBytes(file.toPath()));
        } catch (IOException ex) {
            fail();
        }
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        Principal principal = SimplePrincipal.create("user", "joe", "creds");

        // make sure no exceptions are thrown when processing log request

        store.log(principal, "10.11.12.13", "athens.provider", "1234", cert);
    }

    @Test
    public void testEnableNotifications() {
        PoolableDataSource mockDataSrc = Mockito.mock(PoolableDataSource.class);
        JDBCCertRecordStore store = new JDBCCertRecordStore(mockDataSrc);
        boolean isEnabled = store.enableNotifications(null, null, null);
        assertFalse(isEnabled);

        NotificationManager notificationManager = Mockito.mock(NotificationManager.class);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        String serverName = "testServer";
        isEnabled = store.enableNotifications(notificationManager, rolesProvider, serverName);
        assertFalse(isEnabled); // Not supported for FileCertStore even if all dependencies provided
    }
}
