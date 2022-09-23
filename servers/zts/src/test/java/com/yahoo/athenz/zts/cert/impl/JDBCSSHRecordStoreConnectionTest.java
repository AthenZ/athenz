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

import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zts.ResourceException;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.sql.*;

import static org.mockito.Mockito.times;
import static org.testng.Assert.*;

public class JDBCSSHRecordStoreConnectionTest {
    
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
    public void testGetSSHCertRecord() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(true);
        Mockito.doReturn("host1,host2").when(mockResultSet).getString(JDBCSSHRecordStoreConnection.DB_COLUMN_PRINCIPALS);
        Mockito.doReturn("10.10.10.11").when(mockResultSet).getString(JDBCSSHRecordStoreConnection.DB_COLUMN_CLIENT_IP);
        Mockito.doReturn("10.10.10.12").when(mockResultSet).getString(JDBCSSHRecordStoreConnection.DB_COLUMN_PRIVATE_IP);

        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);
        SSHCertRecord certRecord = jdbcConn.getSSHCertRecord("instance-id", "athenz.api");

        assertEquals(certRecord.getInstanceId(), "instance-id");
        assertEquals(certRecord.getService(), "athenz.api");
        assertEquals(certRecord.getPrincipals(), "host1,host2");
        assertEquals(certRecord.getClientIP(), "10.10.10.11");
        assertEquals(certRecord.getPrivateIP(), "10.10.10.12");

        jdbcConn.close();
    }

    @Test
    public void testGetSSHCertRecordNotFound() throws Exception {

        Mockito.when(mockResultSet.next()).thenReturn(false);

        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);
        SSHCertRecord certRecord = jdbcConn.getSSHCertRecord("instance-id", "athenz.api");
        assertNull(certRecord);
        jdbcConn.close();
    }

    @Test
    public void testGetSSHCertRecordException() throws Exception {

        Mockito.when(mockResultSet.next()).thenThrow(new SQLException("test", "state", 500));

        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);
        try {
            jdbcConn.getSSHCertRecord("instance-id", "athenz.api");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertSSHRecord() throws Exception {
        
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("id1");
        certRecord.setService("athenz.api");
        certRecord.setPrivateIP("10.10.10.11");
        certRecord.setClientIP("10.10.10.12");
        certRecord.setPrincipals("host1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.insertSSHCertRecord(certRecord);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "id1");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "athenz.api");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "host1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "10.10.10.12");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "10.10.10.11");

        jdbcConn.close();
    }

    @Test
    public void testInsertSSHRecordNullableColumns() throws Exception {

        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("id1");
        certRecord.setService("athenz.api");
        certRecord.setPrivateIP("10.10.10.11");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.insertSSHCertRecord(certRecord);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "id1");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "athenz.api");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "10.10.10.11");

        jdbcConn.close();
    }

    @Test
    public void testInsertSSHRecordAlreadyExists() throws Exception {
        
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("id1");
        certRecord.setService("athenz.api");
        certRecord.setPrivateIP("10.10.10.11");
        certRecord.setClientIP("10.10.10.12");
        certRecord.setPrincipals("host1");

        Mockito.doThrow(new SQLException("entry already exits", "state", 1062))
            .doReturn(1).when(mockPrepStmt).executeUpdate();
        
        boolean requestSuccess = jdbcConn.insertSSHCertRecord(certRecord);
        assertTrue(requestSuccess);
        
        // we should have all operation done once for insert and one for update

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "id1");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "athenz.api");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "host1");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "10.10.10.12");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "10.10.10.11");

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "host1");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "10.10.10.12");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "10.10.10.11");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "id1");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "athenz.api");
        
        jdbcConn.close();
    }

    @Test
    public void testInsertSSHRecordException() throws Exception {

        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("id1");
        certRecord.setService("athenz.api");
        certRecord.setPrivateIP("10.10.10.11");
        certRecord.setClientIP("10.10.10.12");
        certRecord.setPrincipals("host1");

        Mockito.doThrow(new SQLException("error", "state", 503))
                .when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.insertSSHCertRecord(certRecord);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }

        jdbcConn.close();
    }

    @Test
    public void testUpdateSSHRecord() throws Exception {
        
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("id1");
        certRecord.setService("athenz.api");
        certRecord.setPrivateIP("10.10.10.11");
        certRecord.setClientIP("10.10.10.12");
        certRecord.setPrincipals("host1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateSSHCertRecord(certRecord);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "host1");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "10.10.10.12");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "10.10.10.11");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "id1");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "athenz.api");

        jdbcConn.close();
    }

    @Test
    public void testUpdateSSHRecordNullableColumns() throws Exception {

        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("id1");
        certRecord.setService("athenz.api");
        certRecord.setPrincipals("host1");

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateSSHCertRecord(certRecord);
        assertTrue(requestSuccess);

        Mockito.verify(mockPrepStmt, times(1)).setString(1, "host1");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "id1");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "athenz.api");

        jdbcConn.close();
    }

    @Test
    public void testUpdateSSHRecordException() throws Exception {

        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("id1");
        certRecord.setService("athenz.api");
        certRecord.setPrincipals("host1");

        Mockito.doThrow(new SQLException("error", "state", 503))
                .when(mockPrepStmt).executeUpdate();

        try {
            jdbcConn.updateSSHCertRecord(certRecord);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }

        jdbcConn.close();
    }

    @Test
    public void testDeleteSSHRecord() throws Exception {
        
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.deleteSSHCertRecord("instance-id", "athenz.api");
        assertTrue(requestSuccess);
        
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "instance-id");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "athenz.api");
        jdbcConn.close();
    }

    @Test
    public void testDeleteSSHRecordException() throws Exception {

        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        Mockito.doThrow(new SQLException("error", "state", 503)).when(mockPrepStmt).executeUpdate();
        try {
            jdbcConn.deleteSSHCertRecord("instance-id", "athenz.api");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        jdbcConn.close();
    }

    @Test
    public void testSqlError() throws SQLException {
        
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

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
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);
        jdbcConn.con = null;
        jdbcConn.close();
    }

    @Test
    public void testConnectionCloseException() throws SQLException {
        Mockito.doThrow(new SQLException()).when(mockConn).close();
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);
        jdbcConn.close();
    }

    @Test
    public void testdeleteExpiredSSHCertRecords() throws Exception {
        
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        jdbcConn.deleteExpiredSSHCertRecords(360);
        
        Mockito.verify(mockPrepStmt, times(1)).setInt(1, 360);
        jdbcConn.close();
    }
    
    @Test
    public void testdeleteExpiredSSHCertRecordsInvalidValue() throws Exception {
        
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        jdbcConn.deleteExpiredSSHCertRecords(0);
        
        Mockito.verify(mockPrepStmt, times(0)).setInt(1, 0);
        jdbcConn.close();
    }
    
    @Test
    public void testdeleteExpiredSSHCertRecordsException() throws SQLException {
        
        JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(mockConn);

        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("exc", "exc", 101));
        try {
            jdbcConn.deleteExpiredSSHCertRecords(360);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        }
        
        jdbcConn.close();
    }
}
