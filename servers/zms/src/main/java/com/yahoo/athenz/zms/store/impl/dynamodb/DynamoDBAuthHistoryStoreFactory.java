/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms.store.impl.dynamodb;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.DynamoDBClientFetcher;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.AuthHistoryStore;
import com.yahoo.athenz.zms.store.AuthHistoryStoreFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;

public class DynamoDBAuthHistoryStoreFactory implements AuthHistoryStoreFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBAuthHistoryStoreFactory.class);

    @Override
    public AuthHistoryStore create(PrivateKeyStore pkeyStore) {
        final String tableName = System.getProperty(ZMSConsts.ZMS_PROP_AUTH_HISTORY_DYNAMODB_TABLE, ZMSConsts.ZMS_DEFAULT_AUTH_HISTORY_DYNAMODB_TABLE);
        if (tableName == null || tableName.isEmpty()) {
            LOGGER.error("Auth History DynamoDB table name not specified");
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, "DynamoDB table name not specified");
        }

        DynamoDBClientFetcher dynamoDBClientFetcher = ZmsDynamoDBClientFetcherFactory.getDynamoDBClientFetcher();
        DynamoDbEnhancedClient dynamoDbEnhancedClient = dynamoDBClientFetcher.getDynamoDBClient(null, pkeyStore).getDynamoDbEnhancedClient();
        DynamoDbTable<AuthHistoryDynamoDBRecord> table = dynamoDbEnhancedClient.table(tableName, TableSchema.fromBean(AuthHistoryDynamoDBRecord.class));
        return new DynamoDBAuthHistoryStore(table);
    }
}
