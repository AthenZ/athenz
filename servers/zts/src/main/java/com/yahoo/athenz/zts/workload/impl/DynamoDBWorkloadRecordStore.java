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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import com.yahoo.athenz.zts.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DynamoDBWorkloadRecordStore implements WorkloadRecordStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBWorkloadRecordStore.class);

    private final String tableName;
    private final String serviceIndexName;
    private final String ipIndexName;
    private final DynamoDB dynamoDB;

    public DynamoDBWorkloadRecordStore(AmazonDynamoDB client, String tableName, String serviceIndexName, String ipIndexName) {
        this.dynamoDB = new DynamoDB(client);
        this.tableName = tableName;
        this.serviceIndexName = serviceIndexName;
        this.ipIndexName = ipIndexName;
    }

    @Override
    public WorkloadRecordStoreConnection getConnection() {
        try {
            return new DynamoDBWorkloadRecordStoreConnection(dynamoDB, tableName, serviceIndexName, ipIndexName);
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
