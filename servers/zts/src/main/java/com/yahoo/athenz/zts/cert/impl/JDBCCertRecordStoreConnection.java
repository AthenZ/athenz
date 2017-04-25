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

    private static final Logger LOG = LoggerFactory.getLogger(JDBCCertRecordStoreConnection.class);

    private static final String PREFIX = "ZTS-JDBCConnection: ";

    private static final String SQL_GET_X509_RECORD = "SELECT * FROM certificates WHERE provider=? AND instanceId=?;";
    private static final String SQL_INSERT_X509_RECORD = "INSERT INTO certificates " +
            "(provider, instanceId, service, currentSerial, currentTime, currentIP, prevSerial, prevTime, prevIP) " +
            "VALUES (?, ?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_X509_RECORD = "UPDATE certificates SET " +
            "currentSerial=?, currentTime=?, currentIP=?, prevSerial=?, prevTime=?, prevIP=? " +
            "WHERE provider=? AND instanceId=?;";
    private static final String SQL_DELETE_X509_RECORD = "DELETE from certificates " +
            "WHERE provider=? AND instanceId=?;";
    
    public static final String DB_COLUMN_SERVICE        = "service";
    public static final String DB_COLUMN_CURRENT_IP     = "currentIP";
    public static final String DB_COLUMN_CURRENT_SERIAL = "currentSerial";
    public static final String DB_COLUMN_CURRENT_TIME   = "currentTime";
    public static final String DB_COLUMN_PREV_IP        = "prevIP";
    public static final String DB_COLUMN_PREV_SERIAL    = "prevSerial";
    public static final String DB_COLUMN_PREV_TIME      = "prevTime";

    Connection con = null;
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
            LOG.error(PREFIX + "close: state - " + ex.getSQLState() +
                    ", code - " + ex.getErrorCode() + ", message - " + ex.getMessage());
        }
    }
    
    int executeUpdate(PreparedStatement ps, String caller) throws SQLException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(caller + ": " + ps.toString());
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeUpdate();
    }

    ResultSet executeQuery(PreparedStatement ps, String caller) throws SQLException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(caller + ": " + ps.toString());
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeQuery();
    }
    
    @Override
    public X509CertRecord getX509CertRecord(String provider, String instanceId) {
        
        final String caller = "getX509CertRecord";

        X509CertRecord certRecord = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_X509_RECORD)) {
            ps.setString(1, instanceId);
            
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    certRecord = new X509CertRecord();
                    certRecord.setProvider(provider);
                    certRecord.setInstanceId(instanceId);
                    certRecord.setService(rs.getString(DB_COLUMN_SERVICE));
                    certRecord.setCurrentIP(rs.getString(DB_COLUMN_CURRENT_IP));
                    certRecord.setCurrentSerial(rs.getString(DB_COLUMN_CURRENT_SERIAL));
                    certRecord.setCurrentTime(new Date(rs.getTimestamp(DB_COLUMN_CURRENT_TIME).getTime()));
                    certRecord.setPrevIP(rs.getString(DB_COLUMN_PREV_IP));
                    certRecord.setPrevSerial(rs.getString(DB_COLUMN_PREV_SERIAL));
                    certRecord.setPrevTime(new Date(rs.getTimestamp(DB_COLUMN_PREV_TIME).getTime()));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return certRecord;
    }
    
    @Override
    public boolean updateX509CertRecord(X509CertRecord certRecord) {
        
        int affectedRows = 0;
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
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean insertX509CertRecord(X509CertRecord certRecord) {
        
        int affectedRows = 0;
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
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean deleteX509CertRecord(String provider, String instanceId) {
        
        int affectedRows = 0;
        final String caller = "deleteX509CertRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_X509_RECORD)) {
            ps.setString(1, provider);
            ps.setString(2, instanceId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    RuntimeException sqlError(SQLException ex, String caller) {
        
        String sqlState = ex.getSQLState();
        int code = ResourceException.INTERNAL_SERVER_ERROR;
        String msg = null;
        if (ex instanceof SQLTimeoutException) {
            code = ResourceException.SERVICE_UNAVAILABLE;
            msg = "Statement cancelled due to timeout";
        } else {
            msg = ex.getMessage() + ", state: " + sqlState + ", code: " + ex.getErrorCode();
        }
        LOG.error("SQLError: {}", msg);
        return new ResourceException(code, msg);
    }
}
