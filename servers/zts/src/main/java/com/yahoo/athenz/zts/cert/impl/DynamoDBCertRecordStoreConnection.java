/*
 * Copyright 2018 Oath, Inc.
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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.zts.ZTSConsts;


import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.AttributeUpdate;
import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DynamoDBCertRecordStoreConnection implements CertRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBCertRecordStoreConnection.class);

    private static final String KEY_PRIMARY = "primaryKey";
    private static final String KEY_PROVIDER = "provider";
    private static final String KEY_INSTANCE_ID = "instanceId";
    private static final String KEY_SERVICE = "service";
    private static final String KEY_CURRENT_SERIAL = "currentSerial";
    private static final String KEY_CURRENT_TIME = "currentTime";
    private static final String KEY_CURRENT_IP = "currentIP";
    private static final String KEY_PREV_SERIAL = "prevSerial";
    private static final String KEY_PREV_TIME = "prevTime";
    private static final String KEY_PREV_IP = "prevIP";
    private static final String KEY_CLIENT_CERT = "clientCert";
    private static final String KEY_LAST_NOTIFIED_TIME = "lastNotifiedTime";
    private static final String KEY_LAST_NOTIFIED_SERVER = "lastNotifiedServer";
    private static final String KEY_EXPIRY_TIME = "expiryTime";
    private static final String KEY_HOSTNAME = "hostName";
    private static final String KEY_TTL = "ttl";

    // the configuration setting is in hours so we'll automatically
    // convert into seconds since that's what dynamoDB needs
    // we need to expire records in 30 days

    private static long expiryTime = 3660 * Long.parseLong(
            System.getProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_ITEM_TTL_HOURS, "720"));
    private Table table;

    public DynamoDBCertRecordStoreConnection(DynamoDB dynamoDB, final String tableName) {
        table = dynamoDB.getTable(tableName);
    }

    @Override
    public void setOperationTimeout(int queryTimeout) {
    }
    
    @Override
    public void close() {
    }
    
    @Override
    public X509CertRecord getX509CertRecord(String provider, String instanceId, String service) {

        final String primaryKey = getPrimaryKey(provider, instanceId, service);
        try {
            Item item = table.getItem(KEY_PRIMARY, primaryKey);
            if (item == null) {
                LOGGER.error("DynamoDB Get Error for {}: item not found", primaryKey);
                return null;
            }
            X509CertRecord certRecord = new X509CertRecord();
            certRecord.setProvider(provider);
            certRecord.setInstanceId(instanceId);
            certRecord.setService(service);
            certRecord.setCurrentSerial(item.getString(KEY_CURRENT_SERIAL));
            certRecord.setCurrentIP(item.getString(KEY_CURRENT_IP));
            certRecord.setCurrentTime(getDateFromItem(item, KEY_CURRENT_TIME));
            certRecord.setPrevSerial(item.getString(KEY_PREV_SERIAL));
            certRecord.setPrevIP(item.getString(KEY_PREV_IP));
            certRecord.setPrevTime(getDateFromItem(item, KEY_PREV_TIME));
            certRecord.setClientCert(item.getBoolean(KEY_CLIENT_CERT));
            certRecord.setLastNotifiedTime(getDateFromItem(item, KEY_LAST_NOTIFIED_TIME));
            certRecord.setLastNotifiedServer(item.getString(KEY_LAST_NOTIFIED_SERVER));
            certRecord.setExpiryTime(getDateFromItem(item, KEY_EXPIRY_TIME));
            certRecord.setHostName(item.getString(KEY_HOSTNAME));
            return certRecord;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Get Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return null;
        }
    }

    private Date getDateFromItem(Item item, String key) {
        if (item.isNull(key) || item.get(key) == null) {
            return null;
        }

        return new Date(item.getLong(key));
    }

    private Object getLongFromDate(Date date) {
        if (date == null) {
            return null;
        }

        return date.getTime();
    }

    @Override
    public boolean updateX509CertRecord(X509CertRecord certRecord) {

        final String primaryKey = getPrimaryKey(certRecord.getProvider(), certRecord.getInstanceId(),
                certRecord.getService());

        try {
            UpdateItemSpec updateItemSpec = new UpdateItemSpec()
                    .withPrimaryKey(KEY_PRIMARY, primaryKey)
                    .withAttributeUpdate(
                            new AttributeUpdate(KEY_INSTANCE_ID).put(certRecord.getInstanceId()),
                            new AttributeUpdate(KEY_PROVIDER).put(certRecord.getProvider()),
                            new AttributeUpdate(KEY_SERVICE).put(certRecord.getService()),
                            new AttributeUpdate(KEY_CURRENT_SERIAL).put(certRecord.getCurrentSerial()),
                            new AttributeUpdate(KEY_CURRENT_IP).put(certRecord.getCurrentIP()),
                            new AttributeUpdate(KEY_CURRENT_TIME).put(getLongFromDate(certRecord.getCurrentTime())),
                            new AttributeUpdate(KEY_PREV_SERIAL).put(certRecord.getPrevSerial()),
                            new AttributeUpdate(KEY_PREV_IP).put(certRecord.getPrevIP()),
                            new AttributeUpdate(KEY_PREV_TIME).put(getLongFromDate(certRecord.getPrevTime())),
                            new AttributeUpdate(KEY_CLIENT_CERT).put(certRecord.getClientCert()),
                            new AttributeUpdate(KEY_TTL).put(certRecord.getCurrentTime().getTime() / 1000L + expiryTime),
                            new AttributeUpdate(KEY_EXPIRY_TIME).put(getLongFromDate(certRecord.getExpiryTime()))
                    );
            table.updateItem(updateItemSpec);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Update Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public boolean insertX509CertRecord(X509CertRecord certRecord) {

        final String primaryKey = getPrimaryKey(certRecord.getProvider(), certRecord.getInstanceId(),
                certRecord.getService());
        try {
            Item item = new Item()
                    .withPrimaryKey(KEY_PRIMARY, primaryKey)
                    .withString(KEY_INSTANCE_ID, certRecord.getInstanceId())
                    .withString(KEY_PROVIDER, certRecord.getProvider())
                    .withString(KEY_SERVICE, certRecord.getService())
                    .withString(KEY_CURRENT_SERIAL, certRecord.getCurrentSerial())
                    .withString(KEY_CURRENT_IP, certRecord.getCurrentIP())
                    .with(KEY_CURRENT_TIME, getLongFromDate(certRecord.getCurrentTime()))
                    .withString(KEY_PREV_SERIAL, certRecord.getPrevSerial())
                    .withString(KEY_PREV_IP, certRecord.getPrevIP())
                    .with(KEY_PREV_TIME, getLongFromDate(certRecord.getPrevTime()))
                    .withBoolean(KEY_CLIENT_CERT, certRecord.getClientCert())
                    .withLong(KEY_TTL, certRecord.getCurrentTime().getTime() / 1000L + expiryTime)
                    .with(KEY_EXPIRY_TIME, getLongFromDate(certRecord.getExpiryTime()))
                    .with(KEY_HOSTNAME, certRecord.getHostName());
            table.putItem(item);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Insert Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public boolean deleteX509CertRecord(String provider, String instanceId, String service) {

        final String primaryKey = getPrimaryKey(provider, instanceId, service);
        try {
            DeleteItemSpec deleteItemSpec = new DeleteItemSpec()
                    .withPrimaryKey(KEY_PRIMARY, primaryKey);
            table.deleteItem(deleteItemSpec);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Delete Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public int deleteExpiredX509CertRecords(int expiryTimeMins) {

        // with dynamo db there is no need to manually expunge expired
        // record since we have the TTL option enabled for our table
        // and we just need to make sure the attribute is updated with
        // the epoch time + timeout seconds when it should retire

        return 0;
    }

    @Override
    public boolean updateUnrefreshedCertificatesNotificationTimestamp(String lastNotifiedServer,
                                                                      long lastNotifiedTime,
                                                                      String provider) {
        // Currently unimplemented for AWS
        return false;
    }

    @Override
    public List<X509CertRecord> getNotifyUnrefreshedCertificates(String lastNotifiedServer, long lastNotifiedTime) {
        // Currently unimplemented for AWS
        return new ArrayList<>();
    }

    private String getPrimaryKey(final String provider, final String instanceId, final String service) {
        return provider + ":" + service + ":" + instanceId;
    }
}
