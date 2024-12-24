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

import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import io.athenz.server.aws.common.utils.DynamoDBUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.util.HashMap;
import java.util.Map;

public class DynamoDBSSHRecordStoreConnection implements SSHRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBSSHRecordStoreConnection.class);

    public static final String ZTS_PROP_SSH_DYNAMODB_ITEM_TTL_HOURS = "athenz.zts.ssh_dynamodb_item_ttl_hours";

    private static final String KEY_PRIMARY = "primaryKey";
    private static final String KEY_INSTANCE_ID = "instanceId";
    private static final String KEY_SERVICE = "service";
    private static final String KEY_PRINCIPALS = "principals";
    private static final String KEY_CLIENT_IP = "clientIP";
    private static final String KEY_PRIVATE_IP = "privateIP";
    private static final String KEY_TTL = "ttl";

    // the configuration setting is in hours so we'll automatically
    // convert into seconds since that's what dynamoDB needs
    // we need to expire records in 30 days

    private static long expiryTime = 3660 * Long.parseLong(
            System.getProperty(ZTS_PROP_SSH_DYNAMODB_ITEM_TTL_HOURS, "720"));
    private final DynamoDbClient dynamoDB;
    private final String tableName;

    public DynamoDBSSHRecordStoreConnection(DynamoDbClient dynamoDB, final String tableName) {
        this.dynamoDB = dynamoDB;
        this.tableName = tableName;
    }

    @Override
    public void setOperationTimeout(int queryTimeout) {
    }
    
    @Override
    public void close() {
    }
    
    @Override
    public SSHCertRecord getSSHCertRecord(String instanceId, String service) {

        final String primaryKey = getPrimaryKey(instanceId, service);

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put(KEY_PRIMARY, AttributeValue.fromS(primaryKey));

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName(tableName)
                .build();

        try {
            GetItemResponse response = dynamoDB.getItem(request);
            Map<String, AttributeValue> item = response.item();
            if (item == null || item.isEmpty()) {
                LOGGER.error("DynamoDB Get Error for {}: item not found", primaryKey);
                return null;
            }

            SSHCertRecord certRecord = new SSHCertRecord();
            certRecord.setInstanceId(instanceId);
            certRecord.setService(service);
            certRecord.setPrincipals(DynamoDBUtils.getString(item, KEY_PRINCIPALS));
            certRecord.setClientIP(DynamoDBUtils.getString(item, KEY_CLIENT_IP));
            certRecord.setPrivateIP(DynamoDBUtils.getString(item, KEY_PRIVATE_IP));
            return certRecord;

        } catch (Exception ex) {
            LOGGER.error("DynamoDB Get Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return null;
        }
    }

    @Override
    public boolean updateSSHCertRecord(SSHCertRecord certRecord) {

        final String primaryKey = getPrimaryKey(certRecord.getInstanceId(), certRecord.getService());

        HashMap<String, AttributeValue> itemKey = new HashMap<>();
        itemKey.put(KEY_PRIMARY, AttributeValue.fromS(primaryKey));

        try {
            HashMap<String, AttributeValueUpdate> updatedValues = new HashMap<>();
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_INSTANCE_ID, certRecord.getInstanceId());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_SERVICE, certRecord.getService());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_CLIENT_IP, certRecord.getClientIP());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_PRINCIPALS, certRecord.getPrincipals());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_PRIVATE_IP, certRecord.getPrivateIP());
            DynamoDBUtils.updateItemStringValue(updatedValues, KEY_TTL, Long.toString(System.currentTimeMillis() / 1000L + expiryTime));

            UpdateItemRequest request = UpdateItemRequest.builder()
                    .tableName(tableName)
                    .key(itemKey)
                    .attributeUpdates(updatedValues)
                    .build();

            dynamoDB.updateItem(request);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Update Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public boolean insertSSHCertRecord(SSHCertRecord certRecord) {

        final String primaryKey = getPrimaryKey(certRecord.getInstanceId(), certRecord.getService());
        try {
            HashMap<String, AttributeValue> itemValues = new HashMap<>();
            itemValues.put(KEY_PRIMARY, AttributeValue.fromS(primaryKey));
            itemValues.put(KEY_INSTANCE_ID, AttributeValue.fromS(certRecord.getInstanceId()));
            itemValues.put(KEY_SERVICE, AttributeValue.fromS(certRecord.getService()));
            itemValues.put(KEY_CLIENT_IP, AttributeValue.fromS(certRecord.getClientIP()));
            itemValues.put(KEY_PRINCIPALS, AttributeValue.fromS(certRecord.getPrincipals()));
            itemValues.put(KEY_PRIVATE_IP, AttributeValue.fromS(certRecord.getPrivateIP()));
            itemValues.put(KEY_TTL, AttributeValue.fromN(Long.toString(System.currentTimeMillis() / 1000L + expiryTime)));

            PutItemRequest request = PutItemRequest.builder()
                    .tableName(tableName)
                    .item(itemValues)
                    .build();

            dynamoDB.putItem(request);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Insert Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public boolean deleteSSHCertRecord(String instanceId, String service) {

        final String primaryKey = getPrimaryKey(instanceId, service);

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put(KEY_PRIMARY, AttributeValue.fromS(primaryKey));

        DeleteItemRequest request = DeleteItemRequest.builder()
                .tableName(tableName)
                .key(keyToGet)
                .build();

        try {
            dynamoDB.deleteItem(request);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Delete Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public int deleteExpiredSSHCertRecords(int expiryTimeMins, int limit) {

        // with dynamo db there is no need to manually expunge expired
        // record since we have the TTL option enabled for our table,
        // and we just need to make sure the attribute is updated with
        // the epoch time + timeout seconds when it should retire

        return 0;
    }

    private String getPrimaryKey(final String instanceId, final String service) {
        return service + ":" + instanceId;
    }
}
