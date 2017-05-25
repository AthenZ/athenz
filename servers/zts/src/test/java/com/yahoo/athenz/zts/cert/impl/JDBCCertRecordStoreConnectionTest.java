/**
 * Copyright 2017 Yahoo Inc.
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
import java.util.Date;

import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.cert.X509CertRecord;

import junit.framework.TestCase;

public class JDBCCertRecordStoreConnectionTest extends TestCase {
    
    @Mock PoolableDataSource mockDataSrc;
    @Mock Statement mockStmt;
    @Mock PreparedStatement mockPrepStmt;
    @Mock Connection mockConn;
    @Mock ResultSet mockResultSet;
    @Mock JDBCCertRecordStoreConnection mockJDBCConn;
    
    JDBCCertRecordStore strStore;
    
    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        Mockito.doReturn(mockStmt).when(mockConn).createStatement();
        Mockito.doReturn(mockResultSet).when(mockPrepStmt).executeQuery();
        Mockito.doReturn(mockPrepStmt).when(mockConn).prepareStatement(Matchers.isA(String.class));
        Mockito.doReturn(true).when(mockStmt).execute(Matchers.isA(String.class));
    }
    
    @Test
    public void testGetX509CertRecord() throws Exception {

        Date now = new Date();
        Timestamp tstamp = new Timestamp(now.getTime());
        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("cn").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_SERVICE);
        Mockito.doReturn("current-serial").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_CURRENT_SERIAL);
        Mockito.doReturn("current-ip").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_CURRENT_IP);
        Mockito.doReturn(tstamp).when(mockResultSet).getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_CURRENT_TIME);
        Mockito.doReturn("prev-serial").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_PREV_SERIAL);
        Mockito.doReturn("prev-ip").when(mockResultSet).getString(JDBCCertRecordStoreConnection.DB_COLUMN_PREV_IP);
        Mockito.doReturn(tstamp).when(mockResultSet).getTimestamp(JDBCCertRecordStoreConnection.DB_COLUMN_PREV_TIME);
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        X509CertRecord certRecord = jdbcConn.getX509CertRecord("ostk", "instance-id");
        
        assertNotNull(certRecord);
        assertEquals(certRecord.getService(), "cn");
        assertEquals(certRecord.getCurrentIP(), "current-ip");
        assertEquals(certRecord.getCurrentSerial(), "current-serial");
        assertEquals(certRecord.getCurrentTime(), now);
        assertEquals(certRecord.getInstanceId(), "instance-id");
        assertEquals(certRecord.getPrevIP(), "prev-ip");
        assertEquals(certRecord.getPrevSerial(), "prev-serial");
        assertEquals(certRecord.getPrevTime(), now);
        
        jdbcConn.close();
    }
    
    @Test
    public void testGetX509CertRecordNotFound() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);
        X509CertRecord certRecord = jdbcConn.getX509CertRecord("ostk", "instance-id-not-found");
        assertNull(certRecord);
        jdbcConn.close();
    }
    
    @Test
    public void testInsertX509Record() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();

        certRecord.setService("cn");
        certRecord.setProvider("ostk");
        certRecord.setInstanceId("instance-id");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(now);
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevTime(now);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "ostk");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "instance-id");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "cn");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "current-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(5, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "current-ip");
        Mockito.verify(mockPrepStmt, times(1)).setString(7, "prev-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(8, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(9, "prev-ip");
        jdbcConn.close();
    }
    
    @Test
    public void testInsertX509RecordAlreadyExists() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();

        certRecord.setService("cn");
        certRecord.setProvider("ostk");
        certRecord.setInstanceId("instance-id");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(now);
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevTime(now);

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
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "current-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(2, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "current-ip");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "prev-serial");
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "prev-ip");
        Mockito.verify(mockPrepStmt, times(1)).setString(7, "ostk");
        Mockito.verify(mockPrepStmt, times(1)).setString(8, "instance-id");
        
        // common between insert/update so count is 2 times
        Mockito.verify(mockPrepStmt, times(2)).setTimestamp(5, new java.sql.Timestamp(now.getTime()));
        
        jdbcConn.close();
    }
    
    @Test
    public void testUpdateX509Record() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();
        
        certRecord.setProvider("ostk");
        certRecord.setService("cn");
        certRecord.setInstanceId("instance-id");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(now);
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevTime(now);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "current-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(2, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "current-ip");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "prev-serial");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(5, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(6, "prev-ip");
        Mockito.verify(mockPrepStmt, times(1)).setString(7, "ostk");
        Mockito.verify(mockPrepStmt, times(1)).setString(8, "instance-id");

        jdbcConn.close();
    }
    
    @Test
    public void testDeleteX509Record() throws Exception {
        
        JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(mockConn);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.deleteX509CertRecord("ostk", "instance-id");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "ostk");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "instance-id");
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
}
