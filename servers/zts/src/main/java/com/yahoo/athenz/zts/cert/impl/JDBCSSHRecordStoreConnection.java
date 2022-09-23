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

import com.yahoo.athenz.zts.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;

import java.sql.*;

public class JDBCSSHRecordStoreConnection implements SSHRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(JDBCSSHRecordStoreConnection.class);

    private static final int MYSQL_ER_OPTION_DUPLICATE_ENTRY = 1062;

    private static final String SQL_GET_SSH_RECORD = "SELECT * FROM ssh_certificates WHERE instanceId=? AND service=?;";
    private static final String SQL_INSERT_SSH_RECORD = "INSERT INTO ssh_certificates " +
            "(instanceId, service, principals, clientIP, privateIP) " +
            "VALUES (?,?,?,?,?);";
    private static final String SQL_UPDATE_SSH_RECORD = "UPDATE ssh_certificates SET " +
            "principals=?, clientIP=?, privateIP=?, issueTime=CURRENT_TIMESTAMP(3) " +
            "WHERE instanceId=? AND service=?;";
    private static final String SQL_DELETE_SSH_RECORD = "DELETE from ssh_certificates " +
            "WHERE instanceId=? AND service=?;";
    private static final String SQL_DELETE_EXPIRED_X509_RECORDS = "DELETE FROM ssh_certificates " +
            "WHERE issueTime < ADDDATE(NOW(), INTERVAL -? MINUTE);";

    public static final String DB_COLUMN_INSTANCE_ID    = "instanceId";
    public static final String DB_COLUMN_SERVICE        = "service";
    public static final String DB_COLUMN_CLIENT_IP      = "clientIP";
    public static final String DB_COLUMN_PRIVATE_IP     = "privateIP";
    public static final String DB_COLUMN_PRINCIPALS     = "principals";
    
    Connection con;
    int queryTimeout = 10;

    public JDBCSSHRecordStoreConnection(Connection con) throws SQLException {
        this.con = con;
        con.setAutoCommit(true);
    }

    @Override
    public void setOperationTimeout(int queryTimeout) {
        this.queryTimeout = queryTimeout;
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
        }
    }
    
    int executeUpdate(PreparedStatement ps, String caller) throws SQLException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("{}: {}", caller, ps.toString());
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeUpdate();
    }

    ResultSet executeQuery(PreparedStatement ps, String caller) throws SQLException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("{}: {}", caller, ps.toString());
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeQuery();
    }

    String processInsertValue(String value) {
        return (value == null) ? "" : value.trim();
    }

    @Override
    public SSHCertRecord getSSHCertRecord(String instanceId, String service) {
        
        final String caller = "getSSHCertRecord";

        SSHCertRecord sshCertRecord = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_SSH_RECORD)) {
            ps.setString(1, instanceId);
            ps.setString(2, service);
            
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    sshCertRecord = new SSHCertRecord();
                    sshCertRecord.setInstanceId(instanceId);
                    sshCertRecord.setService(service);
                    sshCertRecord.setClientIP(rs.getString(DB_COLUMN_CLIENT_IP));
                    sshCertRecord.setPrincipals(rs.getString(DB_COLUMN_PRINCIPALS));
                    sshCertRecord.setPrivateIP(rs.getString(DB_COLUMN_PRIVATE_IP));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return sshCertRecord;
    }

    @Override
    public boolean updateSSHCertRecord(SSHCertRecord sshCertRecord) {
        
        int affectedRows;
        final String caller = "updateSSHCertRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_SSH_RECORD)) {
            ps.setString(1, processInsertValue(sshCertRecord.getPrincipals()));
            ps.setString(2, processInsertValue(sshCertRecord.getClientIP()));
            ps.setString(3, processInsertValue(sshCertRecord.getPrivateIP()));
            ps.setString(4, sshCertRecord.getInstanceId());
            ps.setString(5, sshCertRecord.getService());
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean insertSSHCertRecord(SSHCertRecord sshCertRecord) {

        int affectedRows;
        final String caller = "insertSSHCertRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_SSH_RECORD)) {
            ps.setString(1, sshCertRecord.getInstanceId());
            ps.setString(2, sshCertRecord.getService());
            ps.setString(3, processInsertValue(sshCertRecord.getPrincipals()));
            ps.setString(4, processInsertValue(sshCertRecord.getClientIP()));
            ps.setString(5, processInsertValue(sshCertRecord.getPrivateIP()));

            affectedRows = executeUpdate(ps, caller);
            
        } catch (SQLException ex) {
            
            // if the record already exists, we're going to reset
            // the state and convert this into an update operation
            
            if (ex.getErrorCode() == MYSQL_ER_OPTION_DUPLICATE_ENTRY) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("{}: Resetting state for instance {} - {}",
                            caller, sshCertRecord.getService(), sshCertRecord.getInstanceId());
                }
                return updateSSHCertRecord(sshCertRecord);
            }
            
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean deleteSSHCertRecord(String instanceId, String service) {

        int affectedRows;
        final String caller = "deleteSSHCertRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_SSH_RECORD)) {
            ps.setString(1, instanceId);
            ps.setString(2, service);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public int deleteExpiredSSHCertRecords(int expiryTimeMins) {

        int affectedRows;
        final String caller = "deleteExpiredSSHCertRecords";
        
        // make sure we have a valid value specified for expiry time
        
        if (expiryTimeMins <= 0) {
            return 0;
        }
        
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_EXPIRED_X509_RECORDS)) {
            ps.setInt(1, expiryTimeMins);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return affectedRows;
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
