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

import com.amazonaws.services.dynamodbv2.document.AttributeUpdate;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import com.yahoo.athenz.zts.ZTSConsts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DynamoDBSSHRecordStoreConnection implements SSHRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBSSHRecordStoreConnection.class);

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
            System.getProperty(ZTSConsts.ZTS_PROP_SSH_DYNAMODB_ITEM_TTL_HOURS, "720"));
    private Table table;

    public DynamoDBSSHRecordStoreConnection(DynamoDB dynamoDB, final String tableName) {
        table = dynamoDB.getTable(tableName);
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
        try {
            Item item = table.getItem(KEY_PRIMARY, primaryKey);
            if (item == null) {
                LOGGER.error("DynamoDB Get Error for {}: item not found", primaryKey);
                return null;
            }
            SSHCertRecord certRecord = new SSHCertRecord();
            certRecord.setInstanceId(instanceId);
            certRecord.setService(service);
            certRecord.setPrincipals(item.getString(KEY_PRINCIPALS));
            certRecord.setClientIP(item.getString(KEY_CLIENT_IP));
            certRecord.setPrivateIP(item.getString(KEY_PRIVATE_IP));
            return certRecord;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Get Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return null;
        }
    }

    @Override
    public boolean updateSSHCertRecord(SSHCertRecord certRecord) {

        final String primaryKey = getPrimaryKey(certRecord.getInstanceId(), certRecord.getService());

        try {
            UpdateItemSpec updateItemSpec = new UpdateItemSpec()
                    .withPrimaryKey(KEY_PRIMARY, primaryKey)
                    .withAttributeUpdate(
                            new AttributeUpdate(KEY_INSTANCE_ID).put(certRecord.getInstanceId()),
                            new AttributeUpdate(KEY_SERVICE).put(certRecord.getService()),
                            new AttributeUpdate(KEY_CLIENT_IP).put(certRecord.getClientIP()),
                            new AttributeUpdate(KEY_PRINCIPALS).put(certRecord.getPrincipals()),
                            new AttributeUpdate(KEY_PRIVATE_IP).put(certRecord.getPrivateIP()),
                            new AttributeUpdate(KEY_TTL).put(System.currentTimeMillis() / 1000L + expiryTime)
                    );
            table.updateItem(updateItemSpec);
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
            Item item = new Item()
                    .withPrimaryKey(KEY_PRIMARY, primaryKey)
                    .withString(KEY_INSTANCE_ID, certRecord.getInstanceId())
                    .withString(KEY_SERVICE, certRecord.getService())
                    .withString(KEY_CLIENT_IP, certRecord.getClientIP())
                    .withString(KEY_PRINCIPALS, certRecord.getPrincipals())
                    .withString(KEY_PRIVATE_IP, certRecord.getPrivateIP())
                    .withLong(KEY_TTL, System.currentTimeMillis() / 1000L + expiryTime);
            table.putItem(item);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Insert Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public boolean deleteSSHCertRecord(String instanceId, String service) {

        final String primaryKey = getPrimaryKey(instanceId, service);
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
    public int deleteExpiredSSHCertRecords(int expiryTimeMins) {

        // with dynamo db there is no need to manually expunge expired
        // record since we have the TTL option enabled for our table
        // and we just need to make sure the attribute is updated with
        // the epoch time + timeout seconds when it should retire

        return 0;
    }

    private String getPrimaryKey(final String instanceId, final String service) {
        return service + ":" + instanceId;
    }
}
