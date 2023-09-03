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

import com.amazonaws.services.dynamodbv2.document.*;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.utils.DynamoDBUtils;
import com.yahoo.athenz.zts.utils.RetryDynamoDBCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class DynamoDBWorkloadRecordStoreConnection implements WorkloadRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBWorkloadRecordStoreConnection.class);
    private final RetryDynamoDBCommand<ItemCollection<QueryOutcome>> itemCollectionRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<UpdateItemOutcome> updateItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();
    private final RetryDynamoDBCommand<PutItemOutcome> putItemRetryDynamoDBCommand = new RetryDynamoDBCommand<>();

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

    // the configuration setting is in hours so we'll automatically
    // convert into seconds since that's what dynamoDB needs
    // we need to expire records in 30 days

    private static long expiryTime = 3660 * Long.parseLong(
            System.getProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_ITEM_TTL_HOURS, "720"));
    private final Table table;
    private final Index serviceIndex;
    private final Index ipIndex;

    public DynamoDBWorkloadRecordStoreConnection(DynamoDB dynamoDB, final String tableName, final String serviceIndex, final String ipIndex) {
        this.table = dynamoDB.getTable(tableName);
        this.serviceIndex = table.getIndex(serviceIndex);
        this.ipIndex = table.getIndex(ipIndex);
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
    public List<WorkloadRecord> getWorkloadRecordsByService(String domain, String service) {
        try {
            QuerySpec spec = new QuerySpec()
                    .withKeyConditionExpression("service = :v_service")
                    .withValueMap(new ValueMap()
                            .withString(":v_service", AthenzUtils.getPrincipalName(domain, service)));

            return getWorkloadRecords(spec, serviceIndex);
        } catch (Exception ex) {
            LOGGER.error("DynamoDB getWorkloadRecordsByService failed for service={}, error={}", AthenzUtils.getPrincipalName(domain, service), ex.getMessage());
        }

        return new ArrayList<>();
    }

    @Override
    public List<WorkloadRecord> getWorkloadRecordsByIp(String ip) {
        try {
            QuerySpec spec = new QuerySpec()
                    .withKeyConditionExpression("ip = :v_ip")
                    .withValueMap(new ValueMap()
                            .withString(":v_ip", ip));

            return getWorkloadRecords(spec, ipIndex);
        } catch (Exception ex) {
            LOGGER.error("DynamoDB getWorkloadRecordsByIp failed for ip={}, error={}", ip, ex.getMessage());
        }

        return new ArrayList<>();
    }

    private List<WorkloadRecord> getWorkloadRecords(QuerySpec spec, Index tableIndex) throws java.util.concurrent.TimeoutException, InterruptedException {
        ItemCollection<QueryOutcome> outcome = itemCollectionRetryDynamoDBCommand.run(() -> tableIndex.query(spec));
        List<WorkloadRecord> workloadRecords = new ArrayList<>();
        for (Item item : outcome) {
            workloadRecords.add(itemToWorkloadRecord(item));
        }
        return workloadRecords;
    }


    private WorkloadRecord itemToWorkloadRecord(Item item) {

        WorkloadRecord workloadRecord = new WorkloadRecord();
        workloadRecord.setInstanceId(item.getString(KEY_INSTANCE_ID));
        workloadRecord.setService(item.getString(KEY_SERVICE));
        workloadRecord.setIp(item.getString(KEY_IP));

        if (item.hasAttribute(KEY_HOSTNAME)) {
            workloadRecord.setHostname(item.getString(KEY_HOSTNAME));
        } else {
            workloadRecord.setHostname(DEFAULT_HOSTNAME_IF_NULL);
        }
        workloadRecord.setProvider(item.getString(KEY_PROVIDER));
        workloadRecord.setCreationTime(DynamoDBUtils.getDateFromItem(item, KEY_CREATION_TIME));
        workloadRecord.setUpdateTime(DynamoDBUtils.getDateFromItem(item, KEY_UPDATE_TIME));
        if (item.hasAttribute(KEY_EXPIRY_TIME)) {
            workloadRecord.setCertExpiryTime(DynamoDBUtils.getDateFromItem(item, KEY_EXPIRY_TIME));
        } else {
            workloadRecord.setCertExpiryTime(new Date(0)); //setting default date to 01/01/1970.
        }

        return workloadRecord;
    }


    @Override
    public boolean updateWorkloadRecord(WorkloadRecord workloadRecord) {
        //updateItem does not fail on absence of primaryKey, and behaves as insert. So we should set all attributes with update too.
        try {
            UpdateItemSpec updateItemSpec = new UpdateItemSpec()
                    .withPrimaryKey(KEY_PRIMARY, getPrimaryKey(workloadRecord.getService(), workloadRecord.getInstanceId(), workloadRecord.getIp()))
                    .withAttributeUpdate(
                            new AttributeUpdate(KEY_SERVICE).put(workloadRecord.getService()),
                            new AttributeUpdate(KEY_PROVIDER).put(workloadRecord.getProvider()),
                            new AttributeUpdate(KEY_IP).put(workloadRecord.getIp()),
                            new AttributeUpdate(KEY_INSTANCE_ID).put(workloadRecord.getInstanceId()),
                            new AttributeUpdate(KEY_CREATION_TIME).put(DynamoDBUtils.getLongFromDate(workloadRecord.getCreationTime())),
                            new AttributeUpdate(KEY_UPDATE_TIME).put(DynamoDBUtils.getLongFromDate(workloadRecord.getUpdateTime())),
                            new AttributeUpdate(KEY_EXPIRY_TIME).put(DynamoDBUtils.getLongFromDate(workloadRecord.getCertExpiryTime())),
                            new AttributeUpdate(KEY_HOSTNAME).put(workloadRecord.getHostname()),
                            new AttributeUpdate(KEY_TTL).put(workloadRecord.getUpdateTime().getTime() / 1000L + expiryTime)
                    );
            updateItemRetryDynamoDBCommand.run(() -> table.updateItem(updateItemSpec));
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Workload update Error={}: {}/{}", workloadRecord, ex.getClass(), ex.getMessage());
            return false;
        }
    }

    @Override
    public boolean insertWorkloadRecord(WorkloadRecord workloadRecord) {
        try {
            Item item = new Item()
                    .withPrimaryKey(KEY_PRIMARY, getPrimaryKey(workloadRecord.getService(), workloadRecord.getInstanceId(), workloadRecord.getIp()))
                    .withString(KEY_SERVICE, workloadRecord.getService())
                    .withString(KEY_PROVIDER, workloadRecord.getProvider())
                    .withString(KEY_IP, workloadRecord.getIp())
                    .withString(KEY_INSTANCE_ID, workloadRecord.getInstanceId())
                    .withString(KEY_HOSTNAME, workloadRecord.getHostname())
                    .with(KEY_CREATION_TIME, DynamoDBUtils.getLongFromDate(workloadRecord.getCreationTime()))
                    .with(KEY_UPDATE_TIME, DynamoDBUtils.getLongFromDate(workloadRecord.getUpdateTime()))
                    .with(KEY_EXPIRY_TIME, DynamoDBUtils.getLongFromDate(workloadRecord.getCertExpiryTime()))
                    .withLong(KEY_TTL, workloadRecord.getUpdateTime().getTime() / 1000L + expiryTime);
            putItemRetryDynamoDBCommand.run(() -> table.putItem(item));
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Workload Insert Error={}: {}/{}", workloadRecord, ex.getClass(), ex.getMessage());
            return false;
        }
    }
}
