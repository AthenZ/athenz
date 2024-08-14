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
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.utils.DynamoDBUtils;
import com.yahoo.athenz.zts.utils.RetryDynamoDBCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.util.*;
import java.util.concurrent.TimeoutException;

public class DynamoDBWorkloadRecordStoreConnection implements WorkloadRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBWorkloadRecordStoreConnection.class);
    private final RetryDynamoDBCommand<QueryResponse> itemCollectionRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<UpdateItemResponse> updateItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<PutItemResponse> putItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();

    private static final String KEY_PRIMARY = "primaryKey";
    private static final String KEY_SERVICE = "service";
    private static final String KEY_PROVIDER = "provider";
    private static final String KEY_INSTANCE_ID = "instanceId";
    private static final String KEY_IP = "ip";
    private static final String KEY_HOSTNAME = "hostname";
    private static final String KEY_CREATION_TIME = "creationTime";
    private static final String KEY_UPDATE_TIME = "updateTime";
    private static final String KEY_TTL = "ttl";
    private static final String KEY_EXPIRY_TIME = "certExpiryTime";
    private static final String DEFAULT_HOSTNAME_IF_NULL = "NA";

    // the configuration setting is in hours, so we'll automatically
    // convert into seconds since that's what dynamoDB needs
    // we need to expire records in 30 days

    private static long expiryTime = 3660 * Long.parseLong(
            System.getProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_ITEM_TTL_HOURS, "720"));
    private final String tableName;
    private final String serviceIndexName;
    private final String ipIndexName;
    private final DynamoDbClient dynamoDB;

    public DynamoDBWorkloadRecordStoreConnection(DynamoDbClient dynamoDB, final String tableName,
            final String serviceIndexName, final String ipIndexName) {
        this.dynamoDB = dynamoDB;
        this.tableName = tableName;
        this.serviceIndexName = serviceIndexName;
        this.ipIndexName = ipIndexName;
    }

    @Override
    public void close() {

    }

    @Override
    public void setOperationTimeout(int opTimeout) {

    }

    private String getPrimaryKey(final String service, final String instanceId, final String ip) {
        return service + "#" + instanceId + "#" + ip;
    }

    @Override
    public List<WorkloadRecord> getWorkloadRecordsByService(final String domain, final String service) {

        try {
            HashMap<String, AttributeValue> attrValues = new HashMap<>();
            attrValues.put(":v_service", AttributeValue.fromS(AthenzUtils.getPrincipalName(domain, service)));

            QueryRequest request = QueryRequest.builder()
                    .tableName(tableName)
                    .indexName(serviceIndexName)
                    .keyConditionExpression("service = :v_service")
                    .expressionAttributeValues(attrValues)
                    .build();

            return processWorkloadQuery(request);

        } catch (Exception ex) {
            LOGGER.error("DynamoDB getWorkloadRecordsByService failed for service={}, error={}",
                    AthenzUtils.getPrincipalName(domain, service), ex.getMessage());
        }

        return new ArrayList<>();
    }

    @Override
    public List<WorkloadRecord> getWorkloadRecordsByIp(final String ip) {

        try {
            HashMap<String, AttributeValue> attrValues = new HashMap<>();
            attrValues.put(":v_ip", AttributeValue.fromS(ip));

            QueryRequest request = QueryRequest.builder()
                    .tableName(tableName)
                    .indexName(ipIndexName)
                    .keyConditionExpression("ip = :v_ip")
                    .expressionAttributeValues(attrValues)
                    .build();

            return processWorkloadQuery(request);

        } catch (Exception ex) {
            LOGGER.error("DynamoDB getWorkloadRecordsByIp failed for ip={}, error={}", ip, ex.getMessage());
        }

        return new ArrayList<>();
    }

    private List<WorkloadRecord> processWorkloadQuery(QueryRequest request) throws InterruptedException, TimeoutException {

        QueryResponse response = itemCollectionRetryDynamoDBCommand.run(() -> dynamoDB.query(request));

        List<WorkloadRecord> workloadRecords = new ArrayList<>();
        if (response.hasItems()) {
            for (Map<String, AttributeValue> item : response.items()) {
                workloadRecords.add(itemToWorkloadRecord(item));
            }
        }

        return workloadRecords;
    }

    private WorkloadRecord itemToWorkloadRecord(Map<String, AttributeValue> item) {

        WorkloadRecord workloadRecord = new WorkloadRecord();
        workloadRecord.setInstanceId(DynamoDBUtils.getString(item, KEY_INSTANCE_ID));
        workloadRecord.setService(DynamoDBUtils.getString(item, KEY_SERVICE));
        workloadRecord.setIp(DynamoDBUtils.getString(item, KEY_IP));

        if (item.containsKey(KEY_HOSTNAME)) {
            workloadRecord.setHostname(DynamoDBUtils.getString(item, KEY_HOSTNAME));
        } else {
            workloadRecord.setHostname(DEFAULT_HOSTNAME_IF_NULL);
        }
        workloadRecord.setProvider(DynamoDBUtils.getString(item, KEY_PROVIDER));
        workloadRecord.setCreationTime(DynamoDBUtils.getDateFromItem(item, KEY_CREATION_TIME));
        workloadRecord.setUpdateTime(DynamoDBUtils.getDateFromItem(item, KEY_UPDATE_TIME));
        if (item.containsKey(KEY_EXPIRY_TIME)) {
            workloadRecord.setCertExpiryTime(DynamoDBUtils.getDateFromItem(item, KEY_EXPIRY_TIME));
        } else {
            workloadRecord.setCertExpiryTime(new Date(0)); //setting default date to 01/01/1970.
        }

        return workloadRecord;
    }


    @Override
    public boolean updateWorkloadRecord(WorkloadRecord workloadRecord) {
        // updateItem does not fail on absence of primaryKey, and behaves as insert.
        // So we should set all attributes with update too.

        HashMap<String, AttributeValue> itemKey = new HashMap<>();
        itemKey.put(KEY_PRIMARY, AttributeValue.fromS(getPrimaryKey(workloadRecord.getService(), workloadRecord.getInstanceId(), workloadRecord.getIp())));

        try {
            HashMap<String, AttributeValueUpdate> updatedValues = new HashMap<>();
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_INSTANCE_ID, workloadRecord.getInstanceId());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_PROVIDER, workloadRecord.getProvider());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_SERVICE, workloadRecord.getService());
            DynamoDBUtils.updateItemLongValue(updatedValues, KEY_CREATION_TIME, workloadRecord.getCreationTime());
            DynamoDBUtils.updateItemLongValue(updatedValues, KEY_UPDATE_TIME, workloadRecord.getUpdateTime());
            DynamoDBUtils.updateItemLongValue(updatedValues, KEY_EXPIRY_TIME, workloadRecord.getCertExpiryTime());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_IP, workloadRecord.getIp());
            DynamoDBUtils.updateItemLongValue(updatedValues, KEY_TTL, workloadRecord.getUpdateTime().getTime() / 1000L + expiryTime);
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_HOSTNAME, workloadRecord.getHostname());

            UpdateItemRequest request = UpdateItemRequest.builder()
                    .tableName(tableName)
                    .key(itemKey)
                    .attributeUpdates(updatedValues)
                    .build();

            updateItemRetryDynamoDBCommand.run(() -> dynamoDB.updateItem(request));
            return true;

        } catch (Exception ex) {
            LOGGER.error("DynamoDB Workload update Error={}: {}/{}", workloadRecord, ex.getClass(), ex.getMessage());
            return false;
        }
    }

    @Override
    public boolean insertWorkloadRecord(WorkloadRecord workloadRecord) {

        final String primaryKey = getPrimaryKey(workloadRecord.getService(), workloadRecord.getInstanceId(),
                workloadRecord.getIp());

        try {
            HashMap<String, AttributeValue> itemValues = new HashMap<>();
            itemValues.put(KEY_PRIMARY, AttributeValue.fromS(primaryKey));
            itemValues.put(KEY_INSTANCE_ID, AttributeValue.fromS(workloadRecord.getInstanceId()));
            itemValues.put(KEY_PROVIDER, AttributeValue.fromS(workloadRecord.getProvider()));
            itemValues.put(KEY_SERVICE, AttributeValue.fromS(workloadRecord.getService()));
            itemValues.put(KEY_IP, AttributeValue.fromS(workloadRecord.getIp()));
            itemValues.put(KEY_HOSTNAME, AttributeValue.fromS(workloadRecord.getHostname()));
            itemValues.put(KEY_CREATION_TIME, AttributeValue.fromN(DynamoDBUtils.getNumberFromDate(workloadRecord.getCreationTime())));
            itemValues.put(KEY_UPDATE_TIME, AttributeValue.fromN(DynamoDBUtils.getNumberFromDate(workloadRecord.getUpdateTime())));
            itemValues.put(KEY_EXPIRY_TIME, AttributeValue.fromN(DynamoDBUtils.getNumberFromDate(workloadRecord.getCertExpiryTime())));
            itemValues.put(KEY_TTL, AttributeValue.fromN(Long.toString(workloadRecord.getUpdateTime().getTime() / 1000L + expiryTime)));

            PutItemRequest request = PutItemRequest.builder()
                    .tableName(tableName)
                    .item(itemValues)
                    .build();

            putItemRetryDynamoDBCommand.run(() -> dynamoDB.putItem(request));
            return true;

        } catch (Exception ex) {
            LOGGER.error("DynamoDB Workload Insert Error={}: {}/{}", workloadRecord, ex.getClass(), ex.getMessage());
            return false;
        }
    }
}
