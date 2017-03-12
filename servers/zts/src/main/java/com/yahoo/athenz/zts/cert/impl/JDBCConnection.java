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
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.cert.ObjectStoreConnection;
import com.yahoo.athenz.zts.cert.X509CertRecord;

public class JDBCConnection implements ObjectStoreConnection {

    private static final Logger LOG = LoggerFactory.getLogger(JDBCConnection.class);

    private static final String PREFIX = "ZTS-JDBCConnection: ";
    private static final int MYSQL_ER_OPTION_PREVENTS_STATEMENT = 1290;
    private static final int MYSQL_ER_OPTION_DUPLICATE_ENTRY = 1062;

    private static final String SQL_GET_X509_RECORD = "SELECT * FROM certificates WHERE instanceId=?;";
    private static final String SQL_INSERT_X509_RECORD = "INSERT INTO certificates " +
            "(instanceId, cn, currentSerial, currentTime, currentIP, prevSerial, prevTime, prevIP) " +
            "VALUES (?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_X509_RECORD = "UPDATE certificates SET " +
            "currentSerial=?, currentTime=?, currentIP=?, prevSerial=?, prevTime=?, prevIP=? " +
            "WHERE instanceId=?;";

    public static final String DB_COLUMN_CN             = "cn";
    public static final String DB_COLUMN_CURRENT_IP     = "currentIP";
    public static final String DB_COLUMN_CURRENT_SERIAL = "currentSerial";
    public static final String DB_COLUMN_CURRENT_TIME   = "currentTime";
    public static final String DB_COLUMN_PREV_IP        = "prevIP";
    public static final String DB_COLUMN_PREV_SERIAL    = "prevSerial";
    public static final String DB_COLUMN_PREV_TIME      = "prevTime";

    Connection con = null;
    boolean transactionCompleted = true;
    
    public JDBCConnection(Connection con, boolean autoCommit) throws SQLException {
        this.con = con;
        con.setAutoCommit(autoCommit);
        transactionCompleted = autoCommit;
    }

    @Override
    public void close() {
        
        if (con == null) {
            return;
        }
        
        // the client is always responsible for properly committing
        // all changes before closing the connection, but in case
        // we missed it, we're going to be safe and commit all
        // changes before closing the connection
        
        try {
            commitChanges();
        } catch (Exception ex) {
            // error is already logged but we have to continue
            // processing so we can close our connection
        }
        
        try {
            con.close();
            con = null;
        } catch (SQLException ex) {
            LOG.error(PREFIX + "close: state - " + ex.getSQLState() +
                    ", code - " + ex.getErrorCode() + ", message - " + ex.getMessage());
        }
    }

    @Override
    public void rollbackChanges() {
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(PREFIX + "rollback transaction changes...");
        }
        
        if (transactionCompleted) {
            return;
        }
        
        try {
            con.rollback();
        } catch (SQLException ex) {
            LOG.error(PREFIX + "rollbackChanges: state - " + ex.getSQLState() +
                    ", code - " + ex.getErrorCode() + ", message - " + ex.getMessage());
        }
        transactionCompleted = true;
        try {
            con.setAutoCommit(true);
        } catch (SQLException ex) {
            LOG.error(PREFIX + "rollback auto-commit after failure: state - " + ex.getSQLState() +
                    ", code - " + ex.getErrorCode() + ", message - " + ex.getMessage());
        }
    }
    
    @Override
    public void commitChanges() {
        
        final String caller = "commitChanges";
        if (transactionCompleted) {
            return;
        }
        
        try {
            con.commit();
            transactionCompleted = true;
            con.setAutoCommit(true);
        } catch (SQLException ex) {
            LOG.error(PREFIX + "commitChanges: state - " + ex.getSQLState() +
                    ", code - " + ex.getErrorCode() + ", message - " + ex.getMessage());
            transactionCompleted = true;
            throw sqlError(ex, caller);
        }
    }
    
    @Override
    public X509CertRecord getX509CertRecord(String instanceId) {
        
        final String caller = "getX509CertRecord";

        X509CertRecord certRecord = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_X509_RECORD)) {
            ps.setString(1, instanceId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(PREFIX + caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    certRecord = new X509CertRecord();
                    certRecord.setInstanceId(instanceId);
                    certRecord.setCn(rs.getString(DB_COLUMN_CN));
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
            ps.setString(7, certRecord.getInstanceId());
            affectedRows = ps.executeUpdate();
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
            ps.setString(1, certRecord.getInstanceId());
            ps.setString(2, certRecord.getCn());
            ps.setString(3, certRecord.getCurrentSerial());
            ps.setTimestamp(4, new java.sql.Timestamp(certRecord.getCurrentTime().getTime()));
            ps.setString(5, certRecord.getCurrentIP());
            ps.setString(6, certRecord.getPrevSerial());
            ps.setTimestamp(7, new java.sql.Timestamp(certRecord.getPrevTime().getTime()));
            ps.setString(8, certRecord.getPrevIP());
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    RuntimeException notFoundError(String caller, String objectType, String objectName) {
        rollbackChanges();
        String message = "unknown " + objectType + " - " + objectName;
        return new ResourceException(ResourceException.NOT_FOUND, message);
    }
    
    RuntimeException requestError(String caller, String message) {
        rollbackChanges();
        return new ResourceException(ResourceException.BAD_REQUEST, message);
    }
    
    RuntimeException internalServerError(String caller, String message) {
        rollbackChanges();
        return new ResourceException(ResourceException.INTERNAL_SERVER_ERROR, message);
    }
    
    RuntimeException sqlError(SQLException ex, String caller) {
        
        // check to see if this is a conflict error in which case
        // we're going to let the server to retry the caller
        // The two SQL states that are 'retry-able' are 08S01
        // for a communications error, and 40001 for deadlock.
        // also check for the error code where the mysql server is
        // in read-mode which could happen if we had a failover
        // and the connections are still going to the old master
        
        String sqlState = ex.getSQLState();
        int code = ResourceException.INTERNAL_SERVER_ERROR;
        String msg = null;
        if ("08S01".equals(sqlState) || "40001".equals(sqlState)) {
            code = ResourceException.CONFLICT;
            msg = "Concurrent update conflict, please retry your operation later.";
        } else if (ex.getErrorCode() == MYSQL_ER_OPTION_PREVENTS_STATEMENT) {
            code = ResourceException.GONE;
            msg = "MySQL Database running in read-only mode";
        } else if (ex.getErrorCode() == MYSQL_ER_OPTION_DUPLICATE_ENTRY) {
            code = ResourceException.BAD_REQUEST;
            msg = "Entry already exists";
        } else {
            msg = ex.getMessage() + ", state: " + sqlState + ", code: " + ex.getErrorCode();
        }
        rollbackChanges();
        return new ResourceException(code, msg);
    }
}
