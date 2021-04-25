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

import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import com.yahoo.athenz.zts.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class JDBCWorkloadRecordStoreConnection implements WorkloadRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(JDBCWorkloadRecordStoreConnection.class);

    public static final String DB_COLUMN_INSTANCE_ID    = "instanceId";
    public static final String DB_COLUMN_SERVICE        = "service";
    public static final String DB_COLUMN_PROVIDER       = "provider";
    public static final String DB_COLUMN_IP             = "ip";
    public static final String DB_COLUMN_UPDATE_TIME    = "updateTime";
    public static final String DB_COLUMN_CREATION_TIME    = "creationTime";
    public static final String DB_COLUMN_HOSTNAME   = "hostname";
    public static final String DB_COLUMN_CERT_EXPIRY_TIME    = "certExpiryTime";


    private static final String SQL_GET_WORKLOADS_BY_SERVICE = "SELECT * FROM workloads WHERE service=?;";
    private static final String SQL_GET_WORKLOADS_BY_IP = "SELECT * FROM workloads WHERE ip=?;";
    private static final String SQL_INSERT_WORKLOAD_RECORD = "INSERT INTO workloads (service, instanceId, provider, ip, hostname, certExpiryTime) VALUES (?,?,?,?,?,?);";
    private static final String SQL_UPDATE_WORKLOAD_RECORD = "UPDATE workloads SET updateTime=CURRENT_TIMESTAMP(3), provider=?, certExpiryTime=? WHERE instanceId=? AND service=? AND ip=?;";
    Connection con;
    int queryTimeout = 10;

    public JDBCWorkloadRecordStoreConnection(Connection con) throws SQLException {
        this.con = con;
        if (this.con != null) {
            this.con.setAutoCommit(true);
        }
    }

    @Override
    public void close() {
        if (con == null) {
            return;
        }

        try {
            con.close();
            con = null;
        } catch (SQLException ex) {
            LOGGER.error("Failed to close connection: state - {}, code - {}, message - {}",
                    ex.getSQLState(), ex.getErrorCode(), ex.getMessage());
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public void setOperationTimeout(int opTimeout) {
        this.queryTimeout = opTimeout;
    }

    int executeUpdate(PreparedStatement ps, String caller) throws SQLException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("{}: {}", caller, ps);
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeUpdate();
    }

    ResultSet executeQuery(PreparedStatement ps, String caller) throws SQLException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("{}: {}", caller, ps);
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeQuery();
    }

    String processInsertValue(String value) {
        return (value == null) ? "" : value.trim();
    }

    @Override
    public List<WorkloadRecord> getWorkloadRecordsByService(String domain, String service) {
        final String caller = "getWorkloadRecordsByService";
        List<WorkloadRecord> workloadRecordList = new ArrayList<>();
        WorkloadRecord workloadRecord;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_WORKLOADS_BY_SERVICE)) {
            ps.setString(1, AthenzUtils.getPrincipalName(domain, service));

            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    workloadRecord = new WorkloadRecord();
                    workloadRecord.setInstanceId(rs.getString(DB_COLUMN_INSTANCE_ID));
                    workloadRecord.setProvider(rs.getString(DB_COLUMN_PROVIDER));
                    workloadRecord.setIp(rs.getString(DB_COLUMN_IP));
                    workloadRecord.setCreationTime(rs.getTimestamp(DB_COLUMN_CREATION_TIME));
                    workloadRecord.setHostname(rs.getString(DB_COLUMN_HOSTNAME));
                    workloadRecord.setUpdateTime(rs.getTimestamp(DB_COLUMN_UPDATE_TIME));
                    workloadRecord.setCertExpiryTime(rs.getTimestamp(DB_COLUMN_CERT_EXPIRY_TIME));
                    workloadRecordList.add(workloadRecord);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return workloadRecordList;
    }

    @Override
    public List<WorkloadRecord> getWorkloadRecordsByIp(String ip) {
        final String caller = "getWorkloadRecordsByIp";
        List<WorkloadRecord> workloadRecordList = new ArrayList<>();
        WorkloadRecord workloadRecord;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_WORKLOADS_BY_IP)) {
            ps.setString(1, ip);

            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    workloadRecord = new WorkloadRecord();
                    workloadRecord.setInstanceId(rs.getString(DB_COLUMN_INSTANCE_ID));
                    workloadRecord.setProvider(rs.getString(DB_COLUMN_PROVIDER));
                    workloadRecord.setService(rs.getString(DB_COLUMN_SERVICE));
                    workloadRecord.setCreationTime(rs.getTimestamp(DB_COLUMN_CREATION_TIME));
                    workloadRecord.setHostname(rs.getString(DB_COLUMN_HOSTNAME));
                    workloadRecord.setUpdateTime(rs.getTimestamp(DB_COLUMN_UPDATE_TIME));
                    workloadRecord.setCertExpiryTime(rs.getTimestamp(DB_COLUMN_CERT_EXPIRY_TIME));
                    workloadRecordList.add(workloadRecord);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return workloadRecordList;
    }

    @Override
    public boolean updateWorkloadRecord(WorkloadRecord workloadRecord) {

        int affectedRows;
        final String caller = "updateWorkloadRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_WORKLOAD_RECORD)) {
            ps.setString(1, processInsertValue(workloadRecord.getProvider()));
            ps.setTimestamp(2, new java.sql.Timestamp(workloadRecord.getCertExpiryTime().getTime()));
            ps.setString(3, processInsertValue(workloadRecord.getInstanceId()));
            ps.setString(4, processInsertValue(workloadRecord.getService()));
            ps.setString(5, processInsertValue(workloadRecord.getIp()));
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean insertWorkloadRecord(WorkloadRecord workloadRecord) {
        int affectedRows;
        final String caller = "insertWorkloadRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_WORKLOAD_RECORD)) {
            ps.setString(1, processInsertValue(workloadRecord.getService()));
            ps.setString(2, processInsertValue(workloadRecord.getInstanceId()));
            ps.setString(3, processInsertValue(workloadRecord.getProvider()));
            ps.setString(4, processInsertValue(workloadRecord.getIp()));
            ps.setString(5, processInsertValue(workloadRecord.getHostname()));
            ps.setTimestamp(6, new java.sql.Timestamp(workloadRecord.getCertExpiryTime().getTime()));
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    RuntimeException sqlError(SQLException ex, String caller) {

        String sqlState = ex.getSQLState();
        int code = ResourceException.INTERNAL_SERVER_ERROR;
        String msg;
        if (ex instanceof SQLTimeoutException) {
            code = ResourceException.SERVICE_UNAVAILABLE;
            msg = "Statement cancelled due to timeout";
        } else {
            msg = ex.getMessage() + ", state: " + sqlState + ", code: " + ex.getErrorCode();
        }
        LOGGER.error("SQLError: {} - {}", caller, msg);
        return new ResourceException(code, msg);
    }
}
