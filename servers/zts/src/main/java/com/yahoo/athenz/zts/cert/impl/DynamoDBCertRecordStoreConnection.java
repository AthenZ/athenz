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

import java.util.*;
import java.util.concurrent.TimeUnit;

import com.amazonaws.services.dynamodbv2.document.*;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.amazonaws.services.dynamodbv2.model.ReturnValue;
import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.zts.ZTSConsts;


import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;

import com.yahoo.athenz.zts.utils.DynamoDBUtils;
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
    private static final String KEY_CURRENT_DATE = "currentDate";
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
    private static final String KEY_REGISTER_TIME = "registerTime";
    private static final String KEY_SVC_DATA_UPDATE_TIME = "svcDataUpdateTime";
    private static final int NOTIFICATIONS_GRACE_PERIOD_IN_HOURS = 72;

    // the configuration setting is in hours so we'll automatically
    // convert into seconds since that's what dynamoDB needs
    // we need to expire records in 30 days

    private static final Long EXPIRY_HOURS = Long.parseLong(
            System.getProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_ITEM_TTL_HOURS, "720"));
    private static long expiryTime = 3660 * EXPIRY_HOURS;

    private Table table;
    private Index index;

    public DynamoDBCertRecordStoreConnection(DynamoDB dynamoDB, final String tableName, String indexName) {
        this.table = dynamoDB.getTable(tableName);
        this.index = table.getIndex(indexName);
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
            return itemToX509CertRecord(item);
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Get Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return null;
        }
    }

    private X509CertRecord itemToX509CertRecord(Item item) {
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider(item.getString(KEY_PROVIDER));
        certRecord.setInstanceId(item.getString(KEY_INSTANCE_ID));
        certRecord.setService(item.getString(KEY_SERVICE));
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
        certRecord.setSvcDataUpdateTime(getDateFromItem(item, KEY_SVC_DATA_UPDATE_TIME));
        return certRecord;
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

        // if we don't have a svc update time we'll default to
        // the current time

        if (certRecord.getSvcDataUpdateTime() == null) {
            certRecord.setSvcDataUpdateTime(new Date());
        }

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
                            new AttributeUpdate(KEY_CURRENT_DATE).put(DynamoDBUtils.getIso8601FromDate(certRecord.getCurrentTime())),
                            new AttributeUpdate(KEY_PREV_SERIAL).put(certRecord.getPrevSerial()),
                            new AttributeUpdate(KEY_PREV_IP).put(certRecord.getPrevIP()),
                            new AttributeUpdate(KEY_PREV_TIME).put(getLongFromDate(certRecord.getPrevTime())),
                            new AttributeUpdate(KEY_CLIENT_CERT).put(certRecord.getClientCert()),
                            new AttributeUpdate(KEY_TTL).put(certRecord.getCurrentTime().getTime() / 1000L + expiryTime),
                            new AttributeUpdate(KEY_SVC_DATA_UPDATE_TIME).put(getLongFromDate(certRecord.getSvcDataUpdateTime())),
                            new AttributeUpdate(KEY_EXPIRY_TIME).put(getLongFromDate(certRecord.getExpiryTime()))
                    );
            if (certRecord.getHostName() != null) {
                updateItemSpec.addAttributeUpdate(new AttributeUpdate(KEY_HOSTNAME).put(certRecord.getHostName()));
            }
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
                    .withString(KEY_CURRENT_DATE, DynamoDBUtils.getIso8601FromDate(certRecord.getCurrentTime()))
                    .withString(KEY_PREV_SERIAL, certRecord.getPrevSerial())
                    .withString(KEY_PREV_IP, certRecord.getPrevIP())
                    .with(KEY_PREV_TIME, getLongFromDate(certRecord.getPrevTime()))
                    .withBoolean(KEY_CLIENT_CERT, certRecord.getClientCert())
                    .withLong(KEY_TTL, certRecord.getCurrentTime().getTime() / 1000L + expiryTime)
                    .with(KEY_EXPIRY_TIME, getLongFromDate(certRecord.getExpiryTime()))
                    .with(KEY_SVC_DATA_UPDATE_TIME, getLongFromDate(certRecord.getSvcDataUpdateTime()))
                    .withLong(KEY_REGISTER_TIME, System.currentTimeMillis())
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
    public List<X509CertRecord> updateUnrefreshedCertificatesNotificationTimestamp(String lastNotifiedServer,
                                                                      long lastNotifiedTime,
                                                                      String provider) {
        try {
            List<Item> items = getUnrefreshedCertsRecords(lastNotifiedTime, provider);
            return updateLastNotified(lastNotifiedServer, lastNotifiedTime, items);
        } catch (Exception ex) {
            LOGGER.error("DynamoDB updateUnrefreshedCertificatesNotificationTimestamp Error: {}/{}", ex.getClass(), ex.getMessage());
            return new ArrayList<>();
        }
    }

    private String getPrimaryKey(final String provider, final String instanceId, final String service) {
        return provider + ":" + service + ":" + instanceId;
    }

    private List<X509CertRecord> updateLastNotified(String lastNotifiedServer, long lastNotifiedTime, List<Item> items) {
        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);

        List<X509CertRecord> updatedRecords = new ArrayList<>();
        for (Item item : items) {
            // For each item, update lastNotifiedTime and lastNotifiedServer (unless they were already updated)
            UpdateItemSpec updateItemSpec = new UpdateItemSpec().withPrimaryKey(KEY_PRIMARY, item.getString(KEY_PRIMARY))
                    .withReturnValues(ReturnValue.ALL_NEW)
                    .withUpdateExpression("set lastNotifiedTime = :lastNotifiedTimeVal, lastNotifiedServer = :lastNotifiedServerVal")
                    .withConditionExpression("attribute_not_exists(lastNotifiedTime) OR lastNotifiedTime < :v_yesterday")
                    .withValueMap(new ValueMap()
                            .with(":lastNotifiedTimeVal", lastNotifiedTime)
                            .withNumber(":v_yesterday", yesterday)
                            .withString(":lastNotifiedServerVal", lastNotifiedServer));

            Item updatedItem = table.updateItem(updateItemSpec).getItem();

            if (isRecordUpdatedWithNotificationTimeAndServer(lastNotifiedServer, lastNotifiedTime, updatedItem)) {
                X509CertRecord x509CertRecord = itemToX509CertRecord(updatedItem);
                updatedRecords.add(x509CertRecord);
            }
        }

        return updatedRecords;
    }

    private boolean isRecordUpdatedWithNotificationTimeAndServer(String lastNotifiedServer, long lastNotifiedTime, Item updatedItem) {
        return updatedItem != null &&
                updatedItem.getLong(KEY_LAST_NOTIFIED_TIME) == lastNotifiedTime &&
                updatedItem.getString(KEY_LAST_NOTIFIED_SERVER) != null &&
                updatedItem.getString(KEY_LAST_NOTIFIED_SERVER).equals(lastNotifiedServer);
    }

    private List<Item> getUnrefreshedCertsRecords(long lastNotifiedTime, String provider) {
        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);
        long unrefreshedCertsRangeBegin = lastNotifiedTime - TimeUnit.HOURS.toMillis(EXPIRY_HOURS);
        long unrefreshedCertsRangeEnd = lastNotifiedTime - TimeUnit.HOURS.toMillis(NOTIFICATIONS_GRACE_PERIOD_IN_HOURS);

        List<Item> items = new ArrayList<>();
        List<String> unrefreshedCertDates = DynamoDBUtils.getISODatesByRange(unrefreshedCertsRangeBegin, unrefreshedCertsRangeEnd);

        for (String unrefreshedCertDate : unrefreshedCertDates) {
            items.addAll(getUnrefreshedCertRecordsByDate(provider, index, yesterday, unrefreshedCertDate));
        }

        return items;
    }

    private List<Item> getUnrefreshedCertRecordsByDate(String provider, Index index, long yesterday, String unrefreshedCertDate) {
        QuerySpec spec = new QuerySpec()
                .withKeyConditionExpression("currentDate = :v_current_date")
                .withFilterExpression("provider = :v_provider AND (attribute_not_exists(lastNotifiedTime) OR lastNotifiedTime < :v_last_notified)")
                .withValueMap(new ValueMap()
                        .withString(":v_current_date", unrefreshedCertDate)
                        .withNumber(":v_last_notified", yesterday)
                        .withString(":v_provider", provider));

        ItemCollection<QueryOutcome> outcome = index.query(spec);
        List<Item> items = new ArrayList<>();
        for (Item item : outcome) {
            items.add(item);
        }
        return items;
    }
}
