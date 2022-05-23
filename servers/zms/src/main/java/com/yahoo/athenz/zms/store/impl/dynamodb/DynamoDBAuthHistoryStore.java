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

import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.store.AuthHistoryStore;
import com.yahoo.athenz.zms.store.AuthHistoryStoreConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.enhanced.dynamodb.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

public class DynamoDBAuthHistoryStore implements AuthHistoryStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBAuthHistoryStore.class);
    private final DynamoDbEnhancedClient client;
    private final DynamoDbTable<AuthHistoryDynamoDBRecord> mappedTable;

    public DynamoDBAuthHistoryStore(String tableName, Region region) {
        DynamoDbClient dynamoDB = DynamoDbClient.builder()
                .region(region)
                .build();
        this.client = DynamoDbEnhancedClient.builder()
                .dynamoDbClient(dynamoDB)
                .build();

        this.mappedTable = client.table(tableName, TableSchema.fromBean(AuthHistoryDynamoDBRecord.class));
    }

    public DynamoDBAuthHistoryStore(String tableName, DynamoDbClient dynamoDB) {
        this.client = DynamoDbEnhancedClient.builder()
                .dynamoDbClient(dynamoDB)
                .build();

        this.mappedTable = client.table(tableName, TableSchema.fromBean(AuthHistoryDynamoDBRecord.class));
    }

    @Override
    public AuthHistoryStoreConnection getConnection() {
        try {
            return new DynamoDBAuthHistoryStoreConnection(mappedTable);
        } catch (Exception ex) {
            LOGGER.error("getConnection: {}", ex.getMessage());
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, ex.getMessage());
        }
    }

    @Override
    public void setOperationTimeout(int opTimeout) {
    }

    @Override
    public void clearConnections() {
    }
}
