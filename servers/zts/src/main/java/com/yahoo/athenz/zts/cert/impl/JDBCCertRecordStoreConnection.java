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

import java.sql.*;
import java.util.*;
import java.util.Date;

import com.yahoo.athenz.zts.ZTSConsts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.cert.X509CertRecord;

public class JDBCCertRecordStoreConnection implements CertRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(JDBCCertRecordStoreConnection.class);

    private static final int MYSQL_ER_OPTION_DUPLICATE_ENTRY = 1062;

    // Default grace period - 2 weeks (336 hours)
    private static final Long EXPIRY_HOURS_GRACE = Long.parseLong(
            System.getProperty(ZTSConsts.ZTS_PROP_NOTIFICATION_GRACE_PERIOD_HOURS, "336"));

    private static final String SQL_GET_X509_RECORD = "SELECT * FROM certificates WHERE provider=? AND instanceId=? AND service=?;";
    private static final String SQL_INSERT_X509_RECORD = "INSERT INTO certificates " +
            "(provider, instanceId, service, currentSerial, currentTime, currentIP, prevSerial, prevTime, prevIP, clientCert, " +
            "expiryTime, hostName) " +
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_X509_RECORD = "UPDATE certificates SET " +
            "currentSerial=?, currentTime=?, currentIP=?, prevSerial=?, prevTime=?, prevIP=?, " +
            "expiryTime=?, hostName=?, clientCert=? " +
            "WHERE provider=? AND instanceId=? AND service=?;";
    private static final String SQL_DELETE_X509_RECORD = "DELETE from certificates " +
            "WHERE provider=? AND instanceId=? AND service=?;";
    private static final String SQL_DELETE_EXPIRED_X509_RECORDS = "DELETE FROM certificates " +
            "WHERE currentTime < ADDDATE(NOW(), INTERVAL -? MINUTE);";

    // Get all records that didn't refresh and update notification time.
    // Query explanation:
    // - Group all records with the same hostName / Provider / Service and the most updated "currentTime"
    // - Get all records that need to be notified. This might include rebootstrapped records (instanceId changed).
    // Join them to get only records that appear in both
    private static final String SQL_UPDATE_UNREFRESHED_X509_RECORDS_NOTIFICATION_TIMESTAMP =
            "UPDATE certificates as a " +
            "INNER JOIN (" +
                "SELECT hostName, provider, service, MAX(currentTime) AS date_updated " +
                "FROM certificates " +
                "WHERE hostName IS NOT NULL AND hostName != '' " +
                "GROUP BY hostName, provider, service" +
            ") AS m on (m.hostName=a.hostName AND m.provider=a.provider AND m.service=a.service AND a.currentTime=date_updated) " +
            "SET lastNotifiedTime=?, lastNotifiedServer=? " +
            "WHERE a.currentTime < (CURRENT_DATE - INTERVAL ? HOUR) AND " +
                "a.provider=? AND " +
                "(a.lastNotifiedTime IS NULL || a.lastNotifiedTime < (CURRENT_DATE - INTERVAL 1 DAY))";
    private static final String SQL_LIST_NOTIFY_UNREFRESHED_X509_RECORDS = "SELECT * FROM certificates WHERE lastNotifiedTime=? AND lastNotifiedServer=?;";

    public static final String DB_COLUMN_INSTANCE_ID            = "instanceId";
    public static final String DB_COLUMN_INSTANCE_PROVIDER      = "provider";
    public static final String DB_COLUMN_SERVICE                = "service";
    public static final String DB_COLUMN_CURRENT_IP             = "currentIP";
    public static final String DB_COLUMN_CURRENT_SERIAL         = "currentSerial";
    public static final String DB_COLUMN_CURRENT_TIME           = "currentTime";
    public static final String DB_COLUMN_PREV_IP                = "prevIP";
    public static final String DB_COLUMN_PREV_SERIAL            = "prevSerial";
    public static final String DB_COLUMN_PREV_TIME              = "prevTime";
    public static final String DB_COLUMN_CLIENT_CERT            = "clientCert";
    public static final String DB_COLUMN_LAST_NOTIFIED_TIME     = "lastNotifiedTime";
    public static final String DB_COLUMN_LAST_NOTIFIED_SERVER   = "lastNotifiedServer";
    public static final String DB_COLUMN_EXPIRY_TIME            = "expiryTime";
    public static final String DB_COLUMN_HOSTNAME               = "hostName";
    
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
                    certRecord = setRecordFromResultSet(rs);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return certRecord;
    }

    private X509CertRecord setRecordFromResultSet(ResultSet rs) throws SQLException {
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider(rs.getString(DB_COLUMN_INSTANCE_PROVIDER));
        certRecord.setInstanceId(rs.getString(DB_COLUMN_INSTANCE_ID));
        certRecord.setService(rs.getString(DB_COLUMN_SERVICE));
        certRecord.setCurrentIP(rs.getString(DB_COLUMN_CURRENT_IP));
        certRecord.setCurrentSerial(rs.getString(DB_COLUMN_CURRENT_SERIAL));
        certRecord.setCurrentTime(getDateFromResultSet(rs, DB_COLUMN_CURRENT_TIME));
        certRecord.setPrevIP(rs.getString(DB_COLUMN_PREV_IP));
        certRecord.setPrevSerial(rs.getString(DB_COLUMN_PREV_SERIAL));
        certRecord.setPrevTime(getDateFromResultSet(rs, DB_COLUMN_PREV_TIME));
        certRecord.setClientCert(rs.getBoolean(DB_COLUMN_CLIENT_CERT));
        certRecord.setLastNotifiedTime(getDateFromResultSet(rs, DB_COLUMN_LAST_NOTIFIED_TIME));
        certRecord.setLastNotifiedServer(rs.getString(DB_COLUMN_LAST_NOTIFIED_SERVER));
        certRecord.setExpiryTime(getDateFromResultSet(rs, DB_COLUMN_EXPIRY_TIME));
        certRecord.setHostName(rs.getString(DB_COLUMN_HOSTNAME));
        return certRecord;
    }

    private Date getDateFromResultSet(ResultSet rs, String columnName) throws SQLException {
        Timestamp timestamp = rs.getTimestamp(columnName);
        if (timestamp == null) {
            return null;
        }

        return new Date(timestamp.getTime());
    }

    private Timestamp getTimestampFromDate(Date date) {
        if (date == null) {
            return null;
        }

        return new Timestamp(date.getTime());
    }

    @Override
    public boolean updateX509CertRecord(X509CertRecord certRecord) {
        
        int affectedRows;
        final String caller = "updateX509CertRecord";

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_X509_RECORD)) {
            ps.setString(1, certRecord.getCurrentSerial());
            ps.setTimestamp(2, getTimestampFromDate(certRecord.getCurrentTime()));
            ps.setString(3, certRecord.getCurrentIP());
            ps.setString(4, certRecord.getPrevSerial());
            ps.setTimestamp(5, getTimestampFromDate(certRecord.getPrevTime()));
            ps.setString(6, certRecord.getPrevIP());
            ps.setTimestamp(7, getTimestampFromDate(certRecord.getExpiryTime()));
            ps.setString(8, certRecord.getHostName());
            ps.setBoolean(9, certRecord.getClientCert());
            ps.setString(10, certRecord.getProvider());
            ps.setString(11, certRecord.getInstanceId());
            ps.setString(12, certRecord.getService());
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
            ps.setTimestamp(5, getTimestampFromDate(certRecord.getCurrentTime()));
            ps.setString(6, certRecord.getCurrentIP());
            ps.setString(7, certRecord.getPrevSerial());
            ps.setTimestamp(8, getTimestampFromDate(certRecord.getPrevTime()));
            ps.setString(9, certRecord.getPrevIP());
            ps.setBoolean(10, certRecord.getClientCert());
            ps.setTimestamp(11, getTimestampFromDate(certRecord.getExpiryTime()));
            ps.setString(12, certRecord.getHostName());

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

    @Override
    public List<X509CertRecord> updateUnrefreshedCertificatesNotificationTimestamp(String lastNotifiedServer,
                                                                      long lastNotifiedTime,
                                                                      String provider) {

        final String caller = "updateUnrefreshedCertificatesNotificationTimestamp";
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_UNREFRESHED_X509_RECORDS_NOTIFICATION_TIMESTAMP)) {
            ps.setTimestamp(1, new java.sql.Timestamp(lastNotifiedTime));
            ps.setString(2, lastNotifiedServer);
            ps.setLong(3, EXPIRY_HOURS_GRACE);
            ps.setString(4, provider);

            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        if (affectedRows > 0) {
            return getNotifyUnrefreshedCertificates(lastNotifiedServer, lastNotifiedTime);
        }

        return new ArrayList<>();
    }

    private List<X509CertRecord> getNotifyUnrefreshedCertificates(String lastNotifiedServer, long lastNotifiedTime) {
        final String caller = "listNotifyUnrefreshedCertificates";
        List<X509CertRecord> certRecords = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_NOTIFY_UNREFRESHED_X509_RECORDS)) {
            ps.setTimestamp(1, new java.sql.Timestamp(lastNotifiedTime));
            ps.setString(2, lastNotifiedServer);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    X509CertRecord certRecord = setRecordFromResultSet(rs);
                    certRecords.add(certRecord);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return certRecords;
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
