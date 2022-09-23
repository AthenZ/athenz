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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.ssh.SSHRecordStore;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreFactory;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcher;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcherFactory;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.notification.ZTSClientNotificationSenderImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DynamoDBSSHRecordStoreFactory implements SSHRecordStoreFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBSSHRecordStoreFactory.class);

    @Override
    public SSHRecordStore create(PrivateKeyStore keyStore) {

        final String tableName = System.getProperty(ZTSConsts.ZTS_PROP_SSH_DYNAMODB_TABLE_NAME);
        if (tableName == null || tableName.isEmpty()) {
            LOGGER.error("SSH Store DynamoDB table name not specified");
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, "DynamoDB ssh table name not specified");
        }

        ZTSClientNotificationSenderImpl ztsClientNotificationSender = new ZTSClientNotificationSenderImpl();
        AmazonDynamoDB client = getDynamoDBClient(ztsClientNotificationSender, keyStore);
        return new DynamoDBSSHRecordStore(client, tableName, ztsClientNotificationSender);
    }

    AmazonDynamoDB getDynamoDBClient(ZTSClientNotificationSenderImpl ztsClientNotificationSender, PrivateKeyStore keyStore) {
        DynamoDBClientFetcher dynamoDBClientFetcher = DynamoDBClientFetcherFactory.getDynamoDBClientFetcher();
        ZTSDynamoDBClientSettingsFactory ztsDynamoDBClientSettingsFactory = new ZTSDynamoDBClientSettingsFactory(keyStore);
        return dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, ztsDynamoDBClientSettingsFactory.getDynamoDBClientSettings()).getAmazonDynamoDB();
    }
}
