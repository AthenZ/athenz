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

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.amazonaws.services.dynamodbv2.document.*;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.amazonaws.services.dynamodbv2.model.ConditionalCheckFailedException;
import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.zts.ZTSConsts;


import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;

import com.yahoo.athenz.zts.utils.DynamoDBUtils;
import com.yahoo.athenz.zts.utils.RetryDynamoDBCommand;
import org.eclipse.jetty.util.StringUtil;
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

    // the configuration setting is in hours so we'll automatically
    // convert into seconds since that's what dynamoDB needs
    // we need to expire records in 30 days
    private static final Long EXPIRY_HOURS = Long.parseLong(
            System.getProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_ITEM_TTL_HOURS, "720"));

    // Default grace period - 2 weeks (336 hours)
    private static final Long EXPIRY_HOURS_GRACE = Long.parseLong(
            System.getProperty(ZTSConsts.ZTS_PROP_NOTIFICATION_GRACE_PERIOD_HOURS, "336"));

    private static long expiryTime = 3660 * EXPIRY_HOURS;

    private Table table;
    private final Index currentTimeIndex;
    private final Index hostNameIndex;

    private final DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();
    private final RetryDynamoDBCommand<Item> getItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<UpdateItemOutcome> updateItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<PutItemOutcome> putItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<DeleteItemOutcome> deleteItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<ItemCollection<QueryOutcome>> itemCollectionRetryDynamoDBCommand = new RetryDynamoDBCommand<>();


    public DynamoDBCertRecordStoreConnection(DynamoDB dynamoDB, final String tableName, String currentTimeIndexName, String hostIndexName) {
        this.table = dynamoDB.getTable(tableName);
        this.currentTimeIndex = table.getIndex(currentTimeIndexName);
        this.hostNameIndex = table.getIndex(hostIndexName);
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
            Item item = getItemRetryDynamoDBCommand.run(() -> table.getItem(KEY_PRIMARY, primaryKey));
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
        boolean clientCert;
        try {
            clientCert = item.getBoolean(KEY_CLIENT_CERT);
        } catch (Exception ex) {
            LOGGER.warn("clientCert for item doesn't exist. Will set it to false. Item: {}", item.toString());
            clientCert = false;
        }
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider(item.getString(KEY_PROVIDER));
        certRecord.setInstanceId(item.getString(KEY_INSTANCE_ID));
        certRecord.setService(item.getString(KEY_SERVICE));
        certRecord.setCurrentSerial(item.getString(KEY_CURRENT_SERIAL));
        certRecord.setCurrentIP(item.getString(KEY_CURRENT_IP));
        certRecord.setCurrentTime(DynamoDBUtils.getDateFromItem(item, KEY_CURRENT_TIME));
        certRecord.setPrevSerial(item.getString(KEY_PREV_SERIAL));
        certRecord.setPrevIP(item.getString(KEY_PREV_IP));
        certRecord.setPrevTime(DynamoDBUtils.getDateFromItem(item, KEY_PREV_TIME));
        certRecord.setClientCert(clientCert);
        certRecord.setLastNotifiedTime(DynamoDBUtils.getDateFromItem(item, KEY_LAST_NOTIFIED_TIME));
        certRecord.setLastNotifiedServer(item.getString(KEY_LAST_NOTIFIED_SERVER));
        certRecord.setExpiryTime(DynamoDBUtils.getDateFromItem(item, KEY_EXPIRY_TIME));
        certRecord.setHostName(item.getString(KEY_HOSTNAME));
        certRecord.setSvcDataUpdateTime(DynamoDBUtils.getDateFromItem(item, KEY_SVC_DATA_UPDATE_TIME));
        return certRecord;
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

        String hostName = certRecord.getHostName();
        // Prevent inserting null values in hostName as the hostName-Index will not allow it
        if (StringUtil.isEmpty(hostName)) {
            hostName = primaryKey;
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
                            new AttributeUpdate(KEY_CURRENT_TIME).put(DynamoDBUtils.getLongFromDate(certRecord.getCurrentTime())),
                            new AttributeUpdate(KEY_CURRENT_DATE).put(DynamoDBUtils.getIso8601FromDate(certRecord.getCurrentTime())),
                            new AttributeUpdate(KEY_PREV_SERIAL).put(certRecord.getPrevSerial()),
                            new AttributeUpdate(KEY_PREV_IP).put(certRecord.getPrevIP()),
                            new AttributeUpdate(KEY_PREV_TIME).put(DynamoDBUtils.getLongFromDate(certRecord.getPrevTime())),
                            new AttributeUpdate(KEY_CLIENT_CERT).put(certRecord.getClientCert()),
                            new AttributeUpdate(KEY_TTL).put(certRecord.getCurrentTime().getTime() / 1000L + expiryTime),
                            new AttributeUpdate(KEY_SVC_DATA_UPDATE_TIME).put(DynamoDBUtils.getLongFromDate(certRecord.getSvcDataUpdateTime())),
                            new AttributeUpdate(KEY_EXPIRY_TIME).put(DynamoDBUtils.getLongFromDate(certRecord.getExpiryTime())),
                            new AttributeUpdate(KEY_HOSTNAME).put(hostName)
                            );
            updateItemRetryDynamoDBCommand.run(() -> table.updateItem(updateItemSpec));
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
        String hostName = certRecord.getHostName();
        // Prevent inserting null values in hostName as the hostName-Index will not allow it
        if (StringUtil.isEmpty(hostName)) {
            hostName = primaryKey;
        }
        try {
            Item item = new Item()
                    .withPrimaryKey(KEY_PRIMARY, primaryKey)
                    .withString(KEY_INSTANCE_ID, certRecord.getInstanceId())
                    .withString(KEY_PROVIDER, certRecord.getProvider())
                    .withString(KEY_SERVICE, certRecord.getService())
                    .withString(KEY_CURRENT_SERIAL, certRecord.getCurrentSerial())
                    .withString(KEY_CURRENT_IP, certRecord.getCurrentIP())
                    .with(KEY_CURRENT_TIME, DynamoDBUtils.getLongFromDate(certRecord.getCurrentTime()))
                    .withString(KEY_CURRENT_DATE, DynamoDBUtils.getIso8601FromDate(certRecord.getCurrentTime()))
                    .withString(KEY_PREV_SERIAL, certRecord.getPrevSerial())
                    .withString(KEY_PREV_IP, certRecord.getPrevIP())
                    .with(KEY_PREV_TIME, DynamoDBUtils.getLongFromDate(certRecord.getPrevTime()))
                    .withBoolean(KEY_CLIENT_CERT, certRecord.getClientCert())
                    .withLong(KEY_TTL, certRecord.getCurrentTime().getTime() / 1000L + expiryTime)
                    .with(KEY_EXPIRY_TIME, DynamoDBUtils.getLongFromDate(certRecord.getExpiryTime()))
                    .with(KEY_SVC_DATA_UPDATE_TIME, DynamoDBUtils.getLongFromDate(certRecord.getSvcDataUpdateTime()))
                    .withLong(KEY_REGISTER_TIME, System.currentTimeMillis())
                    .with(KEY_HOSTNAME, hostName);
            putItemRetryDynamoDBCommand.run(() -> table.putItem(item));
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
            deleteItemRetryDynamoDBCommand.run(() -> table.deleteItem(deleteItemSpec));
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
        List<Item> items = getUnrefreshedCertsRecords(lastNotifiedTime, provider);
        return updateLastNotified(lastNotifiedServer, lastNotifiedTime, items);
    }

    private String getPrimaryKey(final String provider, final String instanceId, final String service) {
        return provider + ":" + service + ":" + instanceId;
    }

    private List<X509CertRecord> updateLastNotified(String lastNotifiedServer, long lastNotifiedTime, List<Item> items) {
        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);

        List<X509CertRecord> updatedRecords = new ArrayList<>();
        for (Item item : items) {
            try {
                Item updatedItem = dynamoDBNotificationsHelper.updateLastNotifiedItem(lastNotifiedServer, lastNotifiedTime, yesterday, item, KEY_PRIMARY, table);

                if (isRecordUpdatedWithNotificationTimeAndServer(lastNotifiedServer, lastNotifiedTime, updatedItem)) {
                    X509CertRecord x509CertRecord = itemToX509CertRecord(updatedItem);
                    updatedRecords.add(x509CertRecord);
                }
            } catch (ConditionalCheckFailedException ex) {
                // This error appears when the update didn't work because it was already updated by another server. We can ignore it.
            } catch (Exception ex) {
                LOGGER.error("DynamoDB updateLastNotified failed for item: {}, error: {}", item.toString(), ex.getMessage());
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
        long unrefreshedCertsRangeEnd = lastNotifiedTime - TimeUnit.HOURS.toMillis(EXPIRY_HOURS_GRACE);

        List<Item> items = new ArrayList<>();
        List<String> unrefreshedCertDates = DynamoDBUtils.getISODatesByRange(unrefreshedCertsRangeBegin, unrefreshedCertsRangeEnd);

        for (String unrefreshedCertDate : unrefreshedCertDates) {
            items.addAll(getUnrefreshedCertRecordsByDate(provider, yesterday, unrefreshedCertDate));
        }

        // Filter outdated records from before re-bootstrapping (another record exist with a new uuid)
        items = items.stream()
                .filter(item -> (mostUpdatedHostRecord(item)))
                .collect(Collectors.toList());

        return items;
    }

    private boolean mostUpdatedHostRecord(Item recordToCheck) {
        try {
            // Query all records with the same hostName / provider / service as recordToCheck
            QuerySpec spec = new QuerySpec()
                    .withKeyConditionExpression("hostName = :v_host_name")
                    .withFilterExpression("attribute_exists(provider) AND provider = :v_provider AND attribute_exists(service) AND service = :v_service")
                    .withValueMap(new ValueMap()
                            .withString(":v_host_name", recordToCheck.getString(KEY_HOSTNAME))
                            .withString(":v_provider", recordToCheck.getString(KEY_PROVIDER))
                            .withString(":v_service", recordToCheck.getString(KEY_SERVICE))
                    );

            ItemCollection<QueryOutcome> outcome = itemCollectionRetryDynamoDBCommand.run(() -> hostNameIndex.query(spec));
            List<Item> allRecordsWithHost = new ArrayList<>();
            for (Item item : outcome) {
                allRecordsWithHost.add(item);
            }

            // Verify recordToCheck is the most updated record with this hostName
            return dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(recordToCheck, allRecordsWithHost, KEY_CURRENT_TIME, KEY_PRIMARY);
        } catch (Exception ex) {
            LOGGER.error("DynamoDB mostUpdatedHostRecord failed for item: {}, error: {}", recordToCheck.toString(), ex.getMessage());
            return false;
        }
    }

    private List<Item> getUnrefreshedCertRecordsByDate(String provider, long yesterday, String unrefreshedCertDate) {
        try {
            QuerySpec spec = new QuerySpec()
                    .withKeyConditionExpression("currentDate = :v_current_date")
                    .withFilterExpression("provider = :v_provider AND attribute_exists(hostName) AND (attribute_not_exists(lastNotifiedTime) OR lastNotifiedTime < :v_last_notified)")
                    .withValueMap(new ValueMap()
                            .withString(":v_current_date", unrefreshedCertDate)
                            .withNumber(":v_last_notified", yesterday)
                            .withString(":v_provider", provider));

            ItemCollection<QueryOutcome> outcome = itemCollectionRetryDynamoDBCommand.run(() -> currentTimeIndex.query(spec));
            List<Item> items = new ArrayList<>();
            for (Item item : outcome) {
                items.add(item);
            }
            return items;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB getUnrefreshedCertRecordsByDate failed for provider: {}, date: {} error: {}", provider, unrefreshedCertDate, ex.getMessage());
        }

        return new ArrayList<>();
    }
}
