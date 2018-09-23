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

import java.util.Date;

import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.CertRecordStoreConnection;
import com.yahoo.athenz.zts.cert.X509CertRecord;

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
    public X509CertRecord getX509CertRecord(String provider, String instanceId) {
        
        try {
            Item item = table.getItem(KEY_INSTANCE_ID, instanceId, KEY_PROVIDER, provider);
            if (item == null) {
                LOGGER.error("DynamoDB Get Error for {}/{}: item not found", provider, instanceId);
                return null;
            }
            X509CertRecord certRecord = new X509CertRecord();
            certRecord.setProvider(provider);
            certRecord.setInstanceId(instanceId);
            certRecord.setService(item.getString(KEY_SERVICE));
            certRecord.setCurrentSerial(item.getString(KEY_CURRENT_SERIAL));
            certRecord.setCurrentIP(item.getString(KEY_CURRENT_IP));
            certRecord.setCurrentTime(new Date(item.getLong(KEY_CURRENT_TIME)));
            certRecord.setPrevSerial(item.getString(KEY_PREV_SERIAL));
            certRecord.setPrevIP(item.getString(KEY_PREV_IP));
            certRecord.setPrevTime(new Date(item.getLong(KEY_PREV_TIME)));
            certRecord.setClientCert(item.getBoolean(KEY_CLIENT_CERT));
            return certRecord;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Get Error for {}/{}: {}/{}", provider, instanceId,
                    ex.getClass(), ex.getMessage());
            return null;
        }
    }
    
    @Override
    public boolean updateX509CertRecord(X509CertRecord certRecord) {

        try {
            UpdateItemSpec updateItemSpec = new UpdateItemSpec()
                    .withPrimaryKey(KEY_INSTANCE_ID, certRecord.getInstanceId(), KEY_PROVIDER, certRecord.getProvider())
                    .withAttributeUpdate(
                            new AttributeUpdate(KEY_SERVICE).put(certRecord.getService()),
                            new AttributeUpdate(KEY_CURRENT_SERIAL).put(certRecord.getCurrentSerial()),
                            new AttributeUpdate(KEY_CURRENT_IP).put(certRecord.getCurrentIP()),
                            new AttributeUpdate(KEY_CURRENT_TIME).put(certRecord.getCurrentTime().getTime()),
                            new AttributeUpdate(KEY_PREV_SERIAL).put(certRecord.getPrevSerial()),
                            new AttributeUpdate(KEY_PREV_IP).put(certRecord.getPrevIP()),
                            new AttributeUpdate(KEY_PREV_TIME).put(certRecord.getPrevTime().getTime()),
                            new AttributeUpdate(KEY_CLIENT_CERT).put(certRecord.getClientCert()),
                            new AttributeUpdate(KEY_TTL).put(certRecord.getCurrentTime().getTime() / 1000L + expiryTime)
                    );
            table.updateItem(updateItemSpec);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Update Error for {}/{}: {}/{}", certRecord.getProvider(),
                    certRecord.getInstanceId(), ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public boolean insertX509CertRecord(X509CertRecord certRecord) {

        try {
            Item item = new Item()
                    .withPrimaryKey(KEY_INSTANCE_ID, certRecord.getInstanceId(), KEY_PROVIDER, certRecord.getProvider())
                    .withString(KEY_SERVICE, certRecord.getService())
                    .withString(KEY_CURRENT_SERIAL, certRecord.getCurrentSerial())
                    .withString(KEY_CURRENT_IP, certRecord.getCurrentIP())
                    .withLong(KEY_CURRENT_TIME, certRecord.getCurrentTime().getTime())
                    .withString(KEY_PREV_SERIAL, certRecord.getPrevSerial())
                    .withString(KEY_PREV_IP, certRecord.getPrevIP())
                    .withLong(KEY_PREV_TIME, certRecord.getPrevTime().getTime())
                    .withBoolean(KEY_CLIENT_CERT, certRecord.getClientCert())
                    .withLong(KEY_TTL, certRecord.getCurrentTime().getTime() / 1000L + expiryTime);
            table.putItem(item);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Insert Error for {}/{}: {}/{}", certRecord.getProvider(),
                    certRecord.getInstanceId(), ex.getClass(), ex.getMessage());
            return false;
        }
    }
    
    @Override
    public boolean deleteX509CertRecord(String provider, String instanceId) {

        try {
            DeleteItemSpec deleteItemSpec = new DeleteItemSpec()
                    .withPrimaryKey(KEY_INSTANCE_ID, instanceId, KEY_PROVIDER, provider);
            table.deleteItem(deleteItemSpec);
            return true;
        } catch (Exception ex) {
            LOGGER.error("DynamoDB Delete Error for {}/{}: {}/{}", provider, instanceId,
                    ex.getClass(), ex.getMessage());
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
}
