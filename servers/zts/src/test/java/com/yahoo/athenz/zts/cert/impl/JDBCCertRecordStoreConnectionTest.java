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

import static org.mockito.Mockito.times;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.zts.ResourceException;

public class JDBCCertRecordStoreConnectionTest {
    
    @Mock private PoolableDataSource mockDataSrc;
    @Mock private Statement mockStmt;
    @Mock private PreparedStatement mockPrepStmt;
    @Mock private Connection mockConn;
    @Mock private ResultSet mockResultSet;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        Mockito.doReturn(mockStmt).when(mockConn).createStatement();
        Mockito.doReturn(mockResultSet).when(mockPrepStmt).executeQuery();
        Mockito.doReturn(mockPrepStmt).when(mockConn).prepareStatement(ArgumentMatchers.isA(String.class));
        Mockito.doReturn(true).when(mockStmt).execute(ArgumentMatchers.isA(String.class));
    }
    
    @Test
    public void testGetX509CertRecord() throws Exception {

        Date now = new Date();
        Timestamp tstamp = new Timestamp(now.getTime());
        Mockito.when(mockResultSet.next()).thenReturn(true);
        mockNonNullableColumns(now);
        Mockito.doReturn(tstamp).when(mockResultSet).getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_LAST_NOTIFIED_TIME);
        Mockito.doReturn("last-notified-server").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_LAST_NOTIFIED_SERVER);
        Mockito.doReturn(tstamp).when(mockResultSet).getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_EXPIRY_TIME);
        Mockito.doReturn("hostname").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_HOSTNAME);

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        X509CertRecord certRecord = jdbcConn.getX509CertRecord("ostk", "instance-id", "cn");

        assertNonNullableColumns(now, certRecord);
        assertEquals(certRecord.getLastNotifiedTime(), now);
        assertEquals(certRecord.getLastNotifiedServer(), "last-notified-server");
        assertEquals(certRecord.getExpiryTime(), now);
        assertEquals(certRecord.getHostName(), "hostname");

        jdbcConn.close();
    }

    @Test
    public void testGetX509CertRecordNullableColumns() throws Exception {

        Date now = new Date();
        Mockito.when(mockResultSet.next()).thenReturn(true);
        mockNonNullableColumns(now);
        Mockito.doReturn(null).when(mockResultSet).getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_LAST_NOTIFIED_TIME);
        Mockito.doReturn(null).when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_LAST_NOTIFIED_SERVER);
        Mockito.doReturn(null).when(mockResultSet).getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_EXPIRY_TIME);
        Mockito.doReturn(null).when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_HOSTNAME);

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        X509CertRecord certRecord = jdbcConn.getX509CertRecord("ostk", "instance-id", "cn");

        assertNonNullableColumns(now, certRecord);
        assertNull(certRecord.getLastNotifiedTime());
        assertNull(certRecord.getLastNotifiedServer());
        assertNull(certRecord.getExpiryTime());
        assertNull(certRecord.getHostName());

        jdbcConn.close();
    }

    @Test
    public void testGetX509CertRecordNotFound() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        X509CertRecord certRecord = jdbcConn.getX509CertRecord("ostk", "instance-id-not-found", "cn");
        assertNull(certRecord);
        jdbcConn.close();
    }

    @Test
    public void testGetX509CertRecordException() throws Exception {

        Mockito.when(mockResultSet.next()).thenThrow(new SQLException("test", "state", 500));

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        try {
            jdbcConn.getX509CertRecord("ostk", "exception", "cn");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertX509Record() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Date now = new Date();
        X509CertRecord certRecord = getRecordWithNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);
        certRecord.setHostName("hostname");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        verifyInsertNonNullableColumns(now);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(11, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(12, "hostname");

        jdbcConn.close();
    }

    @Test
    public void testInsertX509RecordNullableColumns() throws Exception {

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Date now = new Date();
        X509CertRecord certRecord = getRecordWithNonNullableColumns(now);
        certRecord.setLastNotifiedTime(null);
        certRecord.setLastNotifiedServer(null);
        certRecord.setExpiryTime(null);
        certRecord.setHostName(null);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        verifyInsertNonNullableColumns(now);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(11, null);
        Mockito.verify(mockPrepStmt, times(1)).setString(12, null);

        jdbcConn.close();
    }

    @Test
    public void testInsertX509RecordAlreadyExists() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Date now = new Date();
        X509CertRecord certRecord = getRecordWithNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);
        certRecord.setHostName("hostname");

        Mockito.doThrow(new SQLException("entry already exits", "state", 1062))
            .doReturn(1).when(mockPrepStmt).executeUpdate();
        
        boolean requestSuccess = jdbcConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);
        
        // we should have all operation done once for insert and one for update

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "ostk");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "instance-id");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "cn");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "current-serial");
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "current-ip");
        Mockito.verify(mockPrepStmt, times(1)).setString(7, "prev-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(8, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(9, "prev-ip");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(10, false);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(11, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(12, "hostname");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "current-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(2, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "current-ip");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "prev-serial");
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "prev-ip");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(7, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(8, "hostname");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(9, false);
        Mockito.verify(mockPrepStmt, times(1)).setString(10, "ostk");
        Mockito.verify(mockPrepStmt, times(1)).setString(11, "instance-id");
        Mockito.verify(mockPrepStmt, times(1)).setString(12, "cn");

        // common between insert/update so count is 2 times
        Mockito.verify(mockPrepStmt, times(2)).setTimestamp(5, new java.sql.Timestamp(now.getTime()));
        
        jdbcConn.close();
    }

    @Test
    public void testInsertX509RecordException() throws Exception {

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Date now = new Date();
        X509CertRecord certRecord = getRecordWithNonNullableColumns(now);
        certRecord.setExpiryTime(now);
        certRecord.setHostName("hostname");

        Mockito.doThrow(new SQLException("error", "state", 503))
                .when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.insertX509CertRecord(certRecord);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateX509Record() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Date now = new Date();
        X509CertRecord certRecord = getRecordWithNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);
        certRecord.setHostName("hostname");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        verifyUpdateNonNullableColumns(now);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(7, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(8, "hostname");

        jdbcConn.close();
    }

    @Test
    public void testUpdateX509RecordNullableColumns() throws Exception {

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Date now = new Date();
        X509CertRecord certRecord = getRecordWithNonNullableColumns(now);
        certRecord.setLastNotifiedTime(null);
        certRecord.setLastNotifiedServer(null);
        certRecord.setExpiryTime(null);
        certRecord.setHostName(null);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        verifyUpdateNonNullableColumns(now);
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(7, null);
        Mockito.verify(mockPrepStmt, times(1)).setString(8, null);

        jdbcConn.close();
    }

    private void verifyUpdateNonNullableColumns(Date now) throws SQLException {
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "current-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(2, new Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "current-ip");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "prev-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(5, new Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "prev-ip");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(9, false);

        Mockito.verify(mockPrepStmt, times(1)).setString(10, "ostk");
        Mockito.verify(mockPrepStmt, times(1)).setString(11, "instance-id");
        Mockito.verify(mockPrepStmt, times(1)).setString(12, "cn");
    }

    @Test
    public void testUpdateX509RecordException() throws Exception {

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Date now = new Date();
        X509CertRecord certRecord = getRecordWithNonNullableColumns(now);
        certRecord.setExpiryTime(now);
        certRecord.setHostName("hostname");

        Mockito.doThrow(new SQLException("error", "state", 503))
                .when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updateX509CertRecord(certRecord);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }

        jdbcConn.close();
    }

    @Test
    public void testDeleteX509Record() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.deleteX509CertRecord("ostk", "instance-id", "cn");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "ostk");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "instance-id");
        jdbcConn.close();
    }

    @Test
    public void testDeleteX509RecordException() throws Exception {

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Mockito.doThrow(new SQLException("error", "state", 503)).when(mockPrepStmt).executeUpdate();
        try {
            jdbcConn.deleteX509CertRecord("ostk", "instance-id", "cn");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        jdbcConn.close();
    }

    @Test
    public void testSqlError() throws SQLException {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        SQLException ex = new SQLException("sql-reason", "08S01", 9999);
        ResourceException rEx = (ResourceException) jdbcConn.sqlError(ex, "sqlError");
        assertEquals(ResourceException.INTERNAL_SERVER_ERROR, rEx.getCode());
        
        ex = new SQLException("sql-reason", "40001", 9999);
        rEx = (ResourceException) jdbcConn.sqlError(ex, "sqlError");
        assertEquals(ResourceException.INTERNAL_SERVER_ERROR, rEx.getCode());

        SQLTimeoutException tex = new SQLTimeoutException();
        rEx = (ResourceException) jdbcConn.sqlError(tex, "sqlError");
        assertEquals(ResourceException.SERVICE_UNAVAILABLE, rEx.getCode());

        jdbcConn.close();
    }
    
    @Test
    public void testConnectionNullClose() throws SQLException {
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        jdbcConn.con = null;
        jdbcConn.close();
    }

    @Test
    public void testConnectionCloseException() throws SQLException {
        Mockito.doThrow(new SQLException()).when(mockConn).close();
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        jdbcConn.close();
    }

    @Test
    public void testdeleteExpiredX509CertRecords() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        jdbcConn.deleteExpiredX509CertRecords(360);
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 360);
        jdbcConn.close();
    }
    
    @Test
    public void testdeleteExpiredX509CertRecordsInvalidValue() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        jdbcConn.deleteExpiredX509CertRecords(0);
        
        Mockito.verify(mockPrepStmt, times(0)).setInt(1, 0);
        jdbcConn.close();
    }
    
    @Test
    public void testdeleteExpiredX509CertRecordsException() throws SQLException {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("exc", "exc", 101));
        try {
            jdbcConn.deleteExpiredX509CertRecords(360);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        
        jdbcConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestamp() throws Exception {
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenReturn(3) // 3 members updated
                .thenReturn(0); // On second call, no members were updated
        long currentTime = System.currentTimeMillis();
        Timestamp ts = new Timestamp(currentTime);

        Mockito.when(mockResultSet.getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_LAST_NOTIFIED_TIME))
                .thenReturn(ts)
                .thenReturn(ts)
                .thenReturn(ts);
        Mockito.when(mockResultSet.getString(JDBCCertRecordStoreConnection.DB_COLUMN_LAST_NOTIFIED_SERVER))
                .thenReturn("server0")
                .thenReturn("server1")
                .thenReturn("server2");
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for server1
                .thenReturn(true) // this one is for server2
                .thenReturn(true) // this one is for server3
                .thenReturn(false); // end
        Mockito.when(mockResultSet.getString(JDBCCertRecordStoreConnection.DB_COLUMN_SERVICE)).thenReturn(null);
        Mockito.when(mockResultSet.getString(JDBCCertRecordStoreConnection.DB_COLUMN_HOSTNAME)).thenReturn(null);
        Mockito.when(mockResultSet.getString(JDBCCertRecordStoreConnection.DB_COLUMN_INSTANCE_ID)).thenReturn(null);
        Mockito.when(mockResultSet.getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_EXPIRY_TIME)).thenReturn(ts);
        Mockito.when(mockResultSet.getBoolean(JDBCCertRecordStoreConnection.DB_COLUMN_CLIENT_CERT)).thenReturn(false);
        Mockito.when(mockResultSet.getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_CURRENT_TIME)).thenReturn(ts);
        Mockito.when(mockResultSet.getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_PREV_TIME)).thenReturn(ts);

        List<X509CertRecord> unrefreshedCertificateRecords = jdbcConn.updateUnrefreshedCertificatesNotificationTimestamp("localhost", currentTime, "provider");
        assertNotNull(unrefreshedCertificateRecords);
        assertEquals(unrefreshedCertificateRecords.size(), 3);
        for (int i = 0; i < unrefreshedCertificateRecords.size(); ++i) {
            assertEquals(unrefreshedCertificateRecords.get(i).getLastNotifiedServer(), "server" + i);
            assertEquals(unrefreshedCertificateRecords.get(i).getLastNotifiedTime(), new Date(currentTime));
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestampNoAffectedRows() throws Exception {
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenReturn(0); // no members were updated
        long currentTime = System.currentTimeMillis();

        Mockito.when(mockResultSet.next())
                .thenReturn(false);

        List<X509CertRecord> unrefreshedCertificateRecords = jdbcConn.updateUnrefreshedCertificatesNotificationTimestamp("localhost", currentTime, "provider");
        assertEquals(unrefreshedCertificateRecords, new ArrayList<>());

        jdbcConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestampErrorInUpdate() throws Exception {
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.updateUnrefreshedCertificatesNotificationTimestamp(
                    "localhost",
                    System.currentTimeMillis(),
                    "provider");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestampErrorInGet() throws Exception {
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        Mockito.when(mockPrepStmt.executeUpdate())
                .thenReturn(3) // 3 members updated
                .thenReturn(0); // On second call, no members were updated
        long currentTime = System.currentTimeMillis();
        Timestamp ts = new Timestamp(currentTime);

        Mockito.when(mockResultSet.getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_LAST_NOTIFIED_TIME))
                .thenReturn(ts)
                .thenReturn(ts)
                .thenReturn(ts);
        Mockito.when(mockResultSet.getString(JDBCCertRecordStoreConnection.DB_COLUMN_LAST_NOTIFIED_SERVER))
                .thenReturn("server0")
                .thenReturn("server1")
                .thenReturn("server2");
        Mockito.when(mockResultSet.next())
                .thenReturn(true) // this one is for server1
                .thenThrow(new SQLException("sql error")); // Simulate sql exception on get

        try {
            jdbcConn.updateUnrefreshedCertificatesNotificationTimestamp(
                    "localhost",
                    System.currentTimeMillis(),
                    "provider");
            fail();
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    private void assertNonNullableColumns(Date now, X509CertRecord certRecord) {
        assertNotNull(certRecord);
        assertEquals(certRecord.getService(), "cn");
        assertEquals(certRecord.getCurrentIP(), "current-ip");
        assertEquals(certRecord.getCurrentSerial(), "current-serial");
        assertEquals(certRecord.getCurrentTime(), now);
        assertEquals(certRecord.getInstanceId(), "instance-id");
        assertEquals(certRecord.getPrevIP(), "prev-ip");
        assertEquals(certRecord.getPrevSerial(), "prev-serial");
        assertEquals(certRecord.getPrevTime(), now);
    }

    private void mockNonNullableColumns(Date now) throws SQLException {
        Timestamp tstamp = new Timestamp(now.getTime());
        Mockito.doReturn("cn").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_SERVICE);
        Mockito.doReturn("current-serial").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_CURRENT_SERIAL);
        Mockito.doReturn("current-ip").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_CURRENT_IP);
        Mockito.doReturn(tstamp).when(mockResultSet).getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_CURRENT_TIME);
        Mockito.doReturn("prev-serial").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_PREV_SERIAL);
        Mockito.doReturn("prev-ip").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_PREV_IP);
        Mockito.doReturn(tstamp).when(mockResultSet).getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_PREV_TIME);
        Mockito.doReturn("instance-id").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_INSTANCE_ID);
    }

    private void verifyInsertNonNullableColumns(Date now) throws SQLException {
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "ostk");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "instance-id");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "cn");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "current-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(5, new Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "current-ip");
        Mockito.verify(mockPrepStmt, times(1)).setString(7, "prev-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(8, new Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(9, "prev-ip");
        Mockito.verify(mockPrepStmt, times(1)).setBoolean(10, false);
    }

    private X509CertRecord getRecordWithNonNullableColumns(Date now) {
        X509CertRecord certRecord = new X509CertRecord();

        certRecord.setService("cn");
        certRecord.setProvider("ostk");
        certRecord.setInstanceId("instance-id");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(now);
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevTime(now);
        certRecord.setClientCert(false);
        return certRecord;
    }
}
