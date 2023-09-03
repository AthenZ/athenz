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
import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.sql.*;
import java.util.Date;
import java.util.List;

import static org.mockito.Mockito.times;
import static org.testng.Assert.*;

public class JDBCWorkloadRecordStoreConnectionTest {
    @Mock private PoolableDataSource mockDataSrc;
    @Mock private Statement mockStmt;
    @Mock private PreparedStatement mockPrepStmt;
    @Mock private Connection mockConn;
    @Mock private ResultSet mockResultSet;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Mockito.doReturn(mockConn).when(mockDataSrc).getConnection();
        Mockito.doReturn(mockStmt).when(mockConn).createStatement();
        Mockito.doReturn(mockResultSet).when(mockPrepStmt).executeQuery();
        Mockito.doReturn(mockPrepStmt).when(mockConn).prepareStatement(ArgumentMatchers.isA(String.class));
        Mockito.doReturn(true).when(mockStmt).execute(ArgumentMatchers.isA(String.class));
    }

    @Test
    public void testGetWorkloadRecordsByIp() throws Exception {

        Date now = new Date();
        Mockito.when(mockResultSet.next()).thenReturn(true, false);
        mockNonNullableColumns(now);
        Mockito.doReturn("athenz.api").when(mockResultSet).getString(JDBCWorkloadRecordStoreConnection.DB_COLUMN_SERVICE);
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        List<WorkloadRecord> workloadRecordList = jdbcConn.getWorkloadRecordsByIp("10.0.0.1");
        assertNotNull(workloadRecordList);
        assertNonNullableColumns(now, workloadRecordList.get(0));
        assertEquals(workloadRecordList.get(0).getService(), "athenz.api");

        jdbcConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByIpException() throws Exception {

        Mockito.when(mockResultSet.next()).thenThrow(new SQLException("sql error"));
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        try {
            jdbcConn.getWorkloadRecordsByIp("10.0.0.1");
            fail();
        } catch (RuntimeException se) {
            assertTrue(se.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByIpTimeout() throws Exception {

        Mockito.when(mockResultSet.next()).thenThrow(new SQLTimeoutException("sql timeout"));
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        jdbcConn.setOperationTimeout(2);
        try {
            jdbcConn.getWorkloadRecordsByIp("10.0.0.1");
            fail();
        } catch (RuntimeException se) {
            assertTrue(se.getMessage().contains("timeout"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByService() throws Exception {

        Date now = new Date();
        Mockito.when(mockResultSet.next()).thenReturn(true, false);
        mockNonNullableColumns(now);
        Mockito.doReturn("10.0.0.1").when(mockResultSet).getString(JDBCWorkloadRecordStoreConnection.DB_COLUMN_IP);
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        List<WorkloadRecord> workloadRecordList = jdbcConn.getWorkloadRecordsByService("athenz", "api");
        assertNotNull(workloadRecordList);
        assertNonNullableColumns(now, workloadRecordList.get(0));
        assertEquals(workloadRecordList.get(0).getIp(), "10.0.0.1");

        jdbcConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByServiceException() throws Exception {

        Mockito.when(mockResultSet.next()).thenThrow(new SQLException("sql error"));
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        try {
            jdbcConn.getWorkloadRecordsByService("athenz", "api");
            fail();
        } catch (RuntimeException se) {
            assertTrue(se.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByServiceTimeout() throws Exception {

        Mockito.when(mockResultSet.next()).thenThrow(new SQLTimeoutException("sql timeout"));
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        try {
            jdbcConn.getWorkloadRecordsByService("athenz", "api");
            fail();
        } catch (RuntimeException se) {
            assertTrue(se.getMessage().contains("timeout"));
        }
        jdbcConn.close();
    }

    @Test
    public void testInsertWorkloadRecord() throws Exception {
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        Date now = new Date();
        WorkloadRecord workloadRecord = getRecordWithNonNullableColumns(now);
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.insertWorkloadRecord(workloadRecord);
        assertTrue(requestSuccess);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "athenz.api");
        Mockito.verify(mockPrepStmt, times(1)).setString(2, "instance-id");
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "openstack");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "10.0.0.1");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "test-host1.yahoo.cloud");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(6, new java.sql.Timestamp(now.getTime()));
        jdbcConn.close();
    }

    @Test
    public void testInsertWorkloadRecordException() throws Exception {
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        Date now = new Date();
        WorkloadRecord workloadRecord = getRecordWithNonNullableColumns(now);
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.insertWorkloadRecord(workloadRecord);
            fail();
        }catch (RuntimeException se) {
            assertTrue(se.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void testUpdateWorkloadRecord() throws Exception {
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        Date now = new Date();
        WorkloadRecord workloadRecord = getRecordWithNonNullableColumns(now);
        Mockito.doReturn(1).when(mockPrepStmt).executeUpdate();
        boolean requestSuccess = jdbcConn.updateWorkloadRecord(workloadRecord);
        assertTrue(requestSuccess);
        Mockito.verify(mockPrepStmt, times(1)).setString(1, "openstack");
        Mockito.verify(mockPrepStmt, times(1)).setTimestamp(2, new java.sql.Timestamp(now.getTime()));
        Mockito.verify(mockPrepStmt, times(1)).setString(3, "instance-id");
        Mockito.verify(mockPrepStmt, times(1)).setString(4, "athenz.api");
        Mockito.verify(mockPrepStmt, times(1)).setString(5, "10.0.0.1");
        jdbcConn.close();
    }

    @Test
    public void testUpdateWorkloadRecordException() throws Exception {
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        Date now = new Date();
        WorkloadRecord workloadRecord = getRecordWithNonNullableColumns(now);
        Mockito.when(mockPrepStmt.executeUpdate()).thenThrow(new SQLException("sql error"));
        try {
            jdbcConn.updateWorkloadRecord(workloadRecord);
            fail();
        }catch (RuntimeException se) {
            assertTrue(se.getMessage().contains("sql error"));
        }
        jdbcConn.close();
    }

    @Test
    public void closeTest() throws Exception {
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        Mockito.doThrow(new SQLException("connection close error")).when(mockConn).close();
        try {
            jdbcConn.close();
            fail();
        } catch (RuntimeException re) {
            assertTrue(re.getMessage().contains("Internal Server Error"));
        }
        jdbcConn = new JDBCWorkloadRecordStoreConnection(null);
        try {
            jdbcConn.close();
        } catch (RuntimeException ex) {
            fail();
        }
    }

    @Test
    public void processInsertValueTest() throws Exception {
        JDBCWorkloadRecordStoreConnection jdbcConn = new JDBCWorkloadRecordStoreConnection(mockConn);
        assertEquals(jdbcConn.processInsertValue("  "), "");
        assertEquals(jdbcConn.processInsertValue(" abc"), "abc");
        assertEquals(jdbcConn.processInsertValue("xyz "), "xyz");
        assertEquals(jdbcConn.processInsertValue(null), "");
    }

    private void mockNonNullableColumns(Date now) throws SQLException {
        Timestamp tstamp = new Timestamp(now.getTime());
        Mockito.doReturn("openstack").when(mockResultSet).getString(JDBCWorkloadRecordStoreConnection.DB_COLUMN_PROVIDER);
        Mockito.doReturn("instance-id").when(mockResultSet).getString(JDBCWorkloadRecordStoreConnection.DB_COLUMN_INSTANCE_ID);

        Mockito.doReturn(tstamp).when(mockResultSet).getTimestamp(JDBCWorkloadRecordStoreConnection.DB_COLUMN_CREATION_TIME);
        Mockito.doReturn(tstamp).when(mockResultSet).getTimestamp(JDBCWorkloadRecordStoreConnection.DB_COLUMN_UPDATE_TIME);
    }

    private void assertNonNullableColumns(Date now, WorkloadRecord workloadRecord) {
        assertNotNull(workloadRecord);
        assertEquals(workloadRecord.getProvider(), "openstack");
        assertEquals(workloadRecord.getInstanceId(), "instance-id");
        assertEquals(workloadRecord.getCreationTime().getTime(), now.getTime());
        assertEquals(workloadRecord.getUpdateTime().getTime(), now.getTime());
    }


    private WorkloadRecord getRecordWithNonNullableColumns(Date now) {
        WorkloadRecord workloadRecord = new WorkloadRecord();

        workloadRecord.setService("athenz.api");
        workloadRecord.setProvider("openstack");
        workloadRecord.setInstanceId("instance-id");
        workloadRecord.setIp("10.0.0.1");
        workloadRecord.setHostname("test-host1.yahoo.cloud");
        workloadRecord.setCertExpiryTime(now);
        workloadRecord.setCreationTime(now);
        workloadRecord.setUpdateTime(now);

        return workloadRecord;
    }

}