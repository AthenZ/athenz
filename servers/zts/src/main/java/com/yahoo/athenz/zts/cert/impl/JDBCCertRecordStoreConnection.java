/*
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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.cert.CertRecordStoreConnection;
import com.yahoo.athenz.zts.cert.X509CertRecord;

public class JDBCCertRecordStoreConnection implements CertRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(JDBCCertRecordStoreConnection.class);

    private static final int MYSQL_ER_OPTION_DUPLICATE_ENTRY = 1062;

    private static final String SQL_GET_X509_RECORD = "SELECT * FROM certificates WHERE provider=? AND instanceId=? AND service=?;";
    private static final String SQL_INSERT_X509_RECORD = "INSERT INTO certificates " +
            "(provider, instanceId, service, currentSerial, currentTime, currentIP, prevSerial, prevTime, prevIP, clientCert) " +
            "VALUES (?, ?,?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_X509_RECORD = "UPDATE certificates SET " +
            "currentSerial=?, currentTime=?, currentIP=?, prevSerial=?, prevTime=?, prevIP=?" +
            "WHERE provider=? AND instanceId=? AND service=?;";
    private static final String SQL_DELETE_X509_RECORD = "DELETE from certificates " +
            "WHERE provider=? AND instanceId=? AND service=?;";
    private static final String SQL_DELETE_EXPIRED_X509_RECORDS = "DELETE FROM certificates " +
            "WHERE currentTime < ADDDATE(NOW(), INTERVAL -? MINUTE);";
    
    public static final String DB_COLUMN_SERVICE        = "service";
    public static final String DB_COLUMN_CURRENT_IP     = "currentIP";
    public static final String DB_COLUMN_CURRENT_SERIAL = "currentSerial";
    public static final String DB_COLUMN_CURRENT_TIME   = "currentTime";
    public static final String DB_COLUMN_PREV_IP        = "prevIP";
    public static final String DB_COLUMN_PREV_SERIAL    = "prevSerial";
    public static final String DB_COLUMN_PREV_TIME      = "prevTime";
    public static final String DB_COLUMN_CLIENT_CERT    = "clientCert";
    
    Connection con;
    int queryTimeout = 10;

    public JDBCCertRecordStoreConnection(Connection con) throws SQLException {
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
    
    @Override
    public X509CertRecord getX509CertRecord(String provider, String instanceId, String service) {
        
        final String caller = "getX509CertRecord";

        X509CertRecord certRecord = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_X509_RECORD)) {
            ps.setString(1, provider);
            ps.setString(2, instanceId);
            ps.setString(3, service);
            
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    certRecord = new X509CertRecord();
                    certRecord.setProvider(provider);
                    certRecord.setInstanceId(instanceId);
                    certRecord.setService(service);
                    certRecord.setCurrentIP(rs.getString(DB_COLUMN_CURRENT_IP));
                    certRecord.setCurrentSerial(rs.getString(DB_COLUMN_CURRENT_SERIAL));
                    certRecord.setCurrentTime(new Date(rs.getTimestamp(DB_COLUMN_CURRENT_TIME).getTime()));
                    certRecord.setPrevIP(rs.getString(DB_COLUMN_PREV_IP));
                    certRecord.setPrevSerial(rs.getString(DB_COLUMN_PREV_SERIAL));
                    certRecord.setPrevTime(new Date(rs.getTimestamp(DB_COLUMN_PREV_TIME).getTime()));
                    certRecord.setClientCert(rs.getBoolean(DB_COLUMN_CLIENT_CERT));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return certRecord;
    }
    
    @Override
    public boolean updateX509CertRecord(X509CertRecord certRecord) {
        
        int affectedRows;
        final String caller = "updateX509CertRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_X509_RECORD)) {
            ps.setString(1, certRecord.getCurrentSerial());
            ps.setTimestamp(2, new java.sql.Timestamp(certRecord.getCurrentTime().getTime()));
            ps.setString(3, certRecord.getCurrentIP());
            ps.setString(4, certRecord.getPrevSerial());
            ps.setTimestamp(5, new java.sql.Timestamp(certRecord.getPrevTime().getTime()));
            ps.setString(6, certRecord.getPrevIP());
            ps.setString(7, certRecord.getProvider());
            ps.setString(8, certRecord.getInstanceId());
            ps.setString(9, certRecord.getService());
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean insertX509CertRecord(X509CertRecord certRecord) {

        int affectedRows;
        final String caller = "insertX509CertRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_X509_RECORD)) {
            ps.setString(1, certRecord.getProvider());
            ps.setString(2, certRecord.getInstanceId());
            ps.setString(3, certRecord.getService());
            ps.setString(4, certRecord.getCurrentSerial());
            ps.setTimestamp(5, new java.sql.Timestamp(certRecord.getCurrentTime().getTime()));
            ps.setString(6, certRecord.getCurrentIP());
            ps.setString(7, certRecord.getPrevSerial());
            ps.setTimestamp(8, new java.sql.Timestamp(certRecord.getPrevTime().getTime()));
            ps.setString(9, certRecord.getPrevIP());
            ps.setBoolean(10, certRecord.getClientCert());
            affectedRows = executeUpdate(ps, caller);
            
        } catch (SQLException ex) {
            
            // if the record already exists, we're going to reset
            // the state and convert this into an update operation
            
            if (ex.getErrorCode() == MYSQL_ER_OPTION_DUPLICATE_ENTRY) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("{}: Resetting state for instance {} - {}",
                            caller, certRecord.getProvider(), certRecord.getInstanceId());
                }
                return updateX509CertRecord(certRecord);
            }
            
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean deleteX509CertRecord(String provider, String instanceId, String service) {

        int affectedRows;
        final String caller = "deleteX509CertRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_X509_RECORD)) {
            ps.setString(1, provider);
            ps.setString(2, instanceId);
            ps.setString(3, service);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public int deleteExpiredX509CertRecords(int expiryTimeMins) {

        int affectedRows;
        final String caller = "deleteExpiredX509CertRecords";
        
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
        LOGGER.error("SQLError: {}", msg);
        return new ResourceException(code, msg);
    }
}
