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
package io.athenz.server.aws.common.cert.impl;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.cert.X509CertRecord;

import io.athenz.server.aws.common.utils.DynamoDBUtils;
import io.athenz.server.aws.common.utils.RetryDynamoDBCommand;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DynamoDBCertRecordStoreConnection implements CertRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBCertRecordStoreConnection.class);

    public static final String ZTS_PROP_CERT_DYNAMODB_ITEM_TTL_HOURS    = "athenz.zts.cert_dynamodb_item_ttl_hours";
    public static final String ZTS_PROP_NOTIFICATION_GRACE_PERIOD_HOURS = "athenz.zts.notification_cert_fail_grace_hours";

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

    // the configuration setting is in hours, so we'll automatically
    // convert into seconds since that's what dynamoDB needs
    // we need to expire records in 30 days
    private static final Long EXPIRY_HOURS = Long.parseLong(
            System.getProperty(ZTS_PROP_CERT_DYNAMODB_ITEM_TTL_HOURS, "720"));

    // Default grace period - 2 weeks (336 hours)
    private static final Long EXPIRY_HOURS_GRACE = Long.parseLong(
            System.getProperty(ZTS_PROP_NOTIFICATION_GRACE_PERIOD_HOURS, "336"));

    private static long expiryTime = 3660 * EXPIRY_HOURS;

    private final String tableName;
    private final String currentTimeIndexName;
    private final String hostNameIndexName;
    private final DynamoDbClient dynamoDB;

    private final DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();
    private final RetryDynamoDBCommand<GetItemResponse> getItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<UpdateItemResponse> updateItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<PutItemResponse> putItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<DeleteItemResponse> deleteItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<QueryResponse> itemCollectionRetryDynamoDBCommand = new RetryDynamoDBCommand<>();

    public DynamoDBCertRecordStoreConnection(DynamoDbClient dynamoDB, final String tableName,
            String currentTimeIndexName, String hostNameIndexName) {
        this.tableName = tableName;
        this.dynamoDB = dynamoDB;
        this.currentTimeIndexName = currentTimeIndexName;
        this.hostNameIndexName = hostNameIndexName;
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

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put(KEY_PRIMARY, AttributeValue.fromS(primaryKey));

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName(tableName)
                .build();

        try {
            GetItemResponse response = getItemRetryDynamoDBCommand.run(() -> dynamoDB.getItem(request));
            Map<String, AttributeValue> item = response.item();
            if (item == null || item.isEmpty()) {
                LOGGER.error("DynamoDB Get Error for {}: item not found", primaryKey);
                return null;
            }
            return itemToX509CertRecord(item);
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Get Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return null;
        }
    }

    private X509CertRecord itemToX509CertRecord(Map<String, AttributeValue> item) {

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider(DynamoDBUtils.getString(item, KEY_PROVIDER));
        certRecord.setInstanceId(DynamoDBUtils.getString(item, KEY_INSTANCE_ID));
        certRecord.setService(DynamoDBUtils.getString(item, KEY_SERVICE));
        certRecord.setCurrentSerial(DynamoDBUtils.getString(item, KEY_CURRENT_SERIAL));
        certRecord.setCurrentIP(DynamoDBUtils.getString(item, KEY_CURRENT_IP));
        certRecord.setCurrentTime(DynamoDBUtils.getDateFromItem(item, KEY_CURRENT_TIME));
        certRecord.setPrevSerial(DynamoDBUtils.getString(item, KEY_PREV_SERIAL));
        certRecord.setPrevIP(DynamoDBUtils.getString(item, KEY_PREV_IP));
        certRecord.setPrevTime(DynamoDBUtils.getDateFromItem(item, KEY_PREV_TIME));
        certRecord.setClientCert(DynamoDBUtils.getBoolean(item, KEY_CLIENT_CERT));
        certRecord.setLastNotifiedTime(DynamoDBUtils.getDateFromItem(item, KEY_LAST_NOTIFIED_TIME));
        certRecord.setLastNotifiedServer(DynamoDBUtils.getString(item, KEY_LAST_NOTIFIED_SERVER));
        certRecord.setExpiryTime(DynamoDBUtils.getDateFromItem(item, KEY_EXPIRY_TIME));
        certRecord.setHostName(DynamoDBUtils.getString(item, KEY_HOSTNAME));
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

        // Prevent inserting null values in hostName as the hostName-Index will not allow it

        String hostName = certRecord.getHostName();
        if (StringUtil.isEmpty(hostName)) {
            hostName = primaryKey;
        }

        HashMap<String, AttributeValue> itemKey = new HashMap<>();
        itemKey.put(KEY_PRIMARY, AttributeValue.fromS(primaryKey));

        try {
            HashMap<String, AttributeValueUpdate> updatedValues = new HashMap<>();
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_INSTANCE_ID, certRecord.getInstanceId());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_PROVIDER, certRecord.getProvider());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_SERVICE, certRecord.getService());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_CURRENT_SERIAL, certRecord.getCurrentSerial());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_CURRENT_IP, certRecord.getCurrentIP());
            DynamoDBUtils.updateItemLongValue(updatedValues, KEY_CURRENT_TIME, certRecord.getCurrentTime());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_CURRENT_DATE, DynamoDBUtils.getIso8601FromDate(certRecord.getCurrentTime()));
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_PREV_SERIAL, certRecord.getPrevSerial());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_PREV_IP, certRecord.getPrevIP());
            DynamoDBUtils.updateItemLongValue(updatedValues, KEY_PREV_TIME, certRecord.getPrevTime());
            DynamoDBUtils.updateItemBoolValue(updatedValues, KEY_CLIENT_CERT, certRecord.getClientCert());
            DynamoDBUtils.updateItemLongValue(updatedValues, KEY_TTL, certRecord.getCurrentTime().getTime() / 1000L + expiryTime);
            DynamoDBUtils.updateItemLongValue(updatedValues, KEY_SVC_DATA_UPDATE_TIME, certRecord.getSvcDataUpdateTime());
            DynamoDBUtils.updateItemLongValue(updatedValues, KEY_EXPIRY_TIME, certRecord.getExpiryTime());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_HOSTNAME, hostName);

            UpdateItemRequest request = UpdateItemRequest.builder()
                    .tableName(tableName)
                    .key(itemKey)
                    .attributeUpdates(updatedValues)
                    .build();

            updateItemRetryDynamoDBCommand.run(() -> dynamoDB.updateItem(request));
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

        // Prevent inserting null values in hostName as the hostName-Index will not allow it

        String hostName = certRecord.getHostName();
        if (StringUtil.isEmpty(hostName)) {
            hostName = primaryKey;
        }
        try {
            HashMap<String, AttributeValue> itemValues = new HashMap<>();
            itemValues.put(KEY_PRIMARY, AttributeValue.fromS(primaryKey));
            itemValues.put(KEY_INSTANCE_ID, AttributeValue.fromS(certRecord.getInstanceId()));
            itemValues.put(KEY_PROVIDER, AttributeValue.fromS(certRecord.getProvider()));
            itemValues.put(KEY_SERVICE, AttributeValue.fromS(certRecord.getService()));
            itemValues.put(KEY_CURRENT_SERIAL, AttributeValue.fromS(certRecord.getCurrentSerial()));
            itemValues.put(KEY_CURRENT_IP, AttributeValue.fromS(certRecord.getCurrentIP()));
            itemValues.put(KEY_CURRENT_TIME, AttributeValue.fromN(DynamoDBUtils.getNumberFromDate(certRecord.getCurrentTime())));
            itemValues.put(KEY_CURRENT_DATE, AttributeValue.fromS(DynamoDBUtils.getIso8601FromDate(certRecord.getCurrentTime())));
            itemValues.put(KEY_PREV_SERIAL, AttributeValue.fromS(certRecord.getPrevSerial()));
            itemValues.put(KEY_PREV_IP, AttributeValue.fromS(certRecord.getPrevIP()));
            itemValues.put(KEY_PREV_TIME, AttributeValue.fromN(DynamoDBUtils.getNumberFromDate(certRecord.getPrevTime())));
            itemValues.put(KEY_CLIENT_CERT, AttributeValue.fromBool(certRecord.getClientCert()));
            itemValues.put(KEY_TTL, AttributeValue.fromN(Long.toString(certRecord.getCurrentTime().getTime() / 1000L + expiryTime)));
            itemValues.put(KEY_EXPIRY_TIME, AttributeValue.fromN(DynamoDBUtils.getNumberFromDate(certRecord.getExpiryTime())));
            itemValues.put(KEY_SVC_DATA_UPDATE_TIME, AttributeValue.fromN(DynamoDBUtils.getNumberFromDate(certRecord.getSvcDataUpdateTime())));
            itemValues.put(KEY_REGISTER_TIME, AttributeValue.fromN(String.valueOf(System.currentTimeMillis())));
            itemValues.put(KEY_HOSTNAME, AttributeValue.fromS(hostName));

            PutItemRequest request = PutItemRequest.builder()
                    .tableName(tableName)
                    .item(itemValues)
                    .build();

            putItemRetryDynamoDBCommand.run(() -> dynamoDB.putItem(request));
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Insert Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public boolean deleteX509CertRecord(String provider, String instanceId, String service) {

        final String primaryKey = getPrimaryKey(provider, instanceId, service);

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put(KEY_PRIMARY, AttributeValue.fromS(primaryKey));

        DeleteItemRequest request = DeleteItemRequest.builder()
                .tableName(tableName)
                .key(keyToGet)
                .build();

        try {
            deleteItemRetryDynamoDBCommand.run(() -> dynamoDB.deleteItem(request));
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Delete Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public int deleteExpiredX509CertRecords(int expiryTimeMins) {

        // with dynamo db there is no need to manually expunge expired
        // record since we have the TTL option enabled for our table,
        // and we just need to make sure the attribute is updated with
        // the epoch time + timeout seconds when it should retire

        return 0;
    }

    @Override
    public List<X509CertRecord> updateUnrefreshedCertificatesNotificationTimestamp(final String lastNotifiedServer,
            long lastNotifiedTime, final String provider) {
        List<Map<String, AttributeValue>> items = getUnrefreshedCertsRecords(lastNotifiedTime, provider);
        return updateLastNotified(lastNotifiedServer, lastNotifiedTime, items);
    }

    private String getPrimaryKey(final String provider, final String instanceId, final String service) {
        return provider + ":" + service + ":" + instanceId;
    }

    private List<X509CertRecord> updateLastNotified(String lastNotifiedServer, long lastNotifiedTime,
            List<Map<String, AttributeValue>> items) {

        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);

        List<X509CertRecord> updatedRecords = new ArrayList<>();
        for (Map<String, AttributeValue> item : items) {
            try {
                Map<String, AttributeValue> updatedItem = dynamoDBNotificationsHelper.updateLastNotifiedItem(
                        lastNotifiedServer, lastNotifiedTime, yesterday, item, KEY_PRIMARY, tableName, dynamoDB);

                if (isRecordUpdatedWithNotificationTimeAndServer(lastNotifiedServer, lastNotifiedTime, updatedItem)) {
                    updatedRecords.add(itemToX509CertRecord(updatedItem));
                }
            } catch (Exception ex) {
                LOGGER.error("DynamoDB updateLastNotified failed for item: {}, error: {}", item.toString(), ex.getMessage());
            }
        }

        return updatedRecords;
    }

    private boolean isRecordUpdatedWithNotificationTimeAndServer(String lastNotifiedServer, long lastNotifiedTime,
                Map<String, AttributeValue> updatedItem) {

        return updatedItem != null &&
                DynamoDBUtils.getLong(updatedItem, KEY_LAST_NOTIFIED_TIME) == lastNotifiedTime &&
                lastNotifiedServer.equals(DynamoDBUtils.getString(updatedItem, KEY_LAST_NOTIFIED_SERVER));
    }

    private List<Map<String, AttributeValue>> getUnrefreshedCertsRecords(long lastNotifiedTime, String provider) {

        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);
        long unrefreshedCertsRangeBegin = lastNotifiedTime - TimeUnit.HOURS.toMillis(EXPIRY_HOURS);
        long unrefreshedCertsRangeEnd = lastNotifiedTime - TimeUnit.HOURS.toMillis(EXPIRY_HOURS_GRACE);

        List<Map<String, AttributeValue>> items = new ArrayList<>();
        List<String> unrefreshedCertDates = DynamoDBUtils.getISODatesByRange(unrefreshedCertsRangeBegin, unrefreshedCertsRangeEnd);

        for (String unrefreshedCertDate : unrefreshedCertDates) {
            items.addAll(getUnrefreshedCertRecordsByDate(provider, yesterday, unrefreshedCertDate));
        }

        // Filter outdated records from before re-bootstrapping
        // (another record exist with a new uuid)

        items = items.stream()
                .filter(this::mostUpdatedHostRecord)
                .collect(Collectors.toList());

        return items;
    }

    private boolean mostUpdatedHostRecord(Map<String, AttributeValue> recordToCheck) {
        try {
            // Set up mapping of the partition name with the value.

            HashMap<String, AttributeValue> attrValues = new HashMap<>();
            attrValues.put(":v_host_name", AttributeValue.fromS(DynamoDBUtils.getString(recordToCheck, KEY_HOSTNAME)));
            attrValues.put(":v_provider", AttributeValue.fromS(DynamoDBUtils.getString(recordToCheck, KEY_PROVIDER)));
            attrValues.put(":v_service", AttributeValue.fromS(DynamoDBUtils.getString(recordToCheck, KEY_SERVICE)));

            QueryRequest request = QueryRequest.builder()
                    .tableName(tableName)
                    .indexName(hostNameIndexName)
                    .keyConditionExpression("hostName = :v_host_name")
                    .filterExpression("attribute_exists(provider) AND provider = :v_provider AND attribute_exists(service) AND service = :v_service")
                    .expressionAttributeValues(attrValues)
                    .build();

            QueryResponse response = itemCollectionRetryDynamoDBCommand.run(() -> dynamoDB.query(request));
            List<Map<String, AttributeValue>> allRecordsWithHost = new ArrayList<>(response.items());

            // Verify recordToCheck is the most updated record with this hostName
            return dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(recordToCheck, allRecordsWithHost,
                    KEY_CURRENT_TIME, KEY_PRIMARY);
        } catch (Exception ex) {
            LOGGER.error("DynamoDB mostUpdatedHostRecord failed for item: {}, error: {}", recordToCheck.toString(), ex.getMessage());
            return false;
        }
    }

    private List<Map<String, AttributeValue>> getUnrefreshedCertRecordsByDate(final String provider, long yesterday,
                final String unrefreshedCertDate) {

        List<Map<String, AttributeValue>> items = new ArrayList<>();
        try {
            // Set up mapping of the partition name with the value.

            HashMap<String, AttributeValue> attrValues = new HashMap<>();
            attrValues.put(":v_current_date", AttributeValue.fromS(unrefreshedCertDate));
            attrValues.put(":v_last_notified", AttributeValue.fromN(String.valueOf(yesterday)));
            attrValues.put(":v_provider", AttributeValue.fromS(provider));

            QueryRequest request = QueryRequest.builder()
                    .tableName(tableName)
                    .indexName(currentTimeIndexName)
                    .keyConditionExpression("currentDate = :v_current_date")
                    .filterExpression("provider = :v_provider AND attribute_exists(hostName) AND (attribute_not_exists(lastNotifiedTime) OR lastNotifiedTime < :v_last_notified)")
                    .expressionAttributeValues(attrValues)
                    .build();

            QueryResponse response = itemCollectionRetryDynamoDBCommand.run(() -> dynamoDB.query(request));
            items.addAll(response.items());
        } catch (Exception ex) {
            LOGGER.error("DynamoDB getUnrefreshedCertRecordsByDate failed for provider: {}, date: {} error: {}",
                    provider, unrefreshedCertDate, ex.getMessage());
        }

        return items;
    }
}
