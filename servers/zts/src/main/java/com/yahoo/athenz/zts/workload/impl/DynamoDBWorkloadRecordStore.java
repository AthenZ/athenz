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

import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

public class DynamoDBWorkloadRecordStore implements WorkloadRecordStore {

    private final String tableName;
    private final String serviceIndexName;
    private final String ipIndexName;
    private final DynamoDbClient dynamoDB;

    public DynamoDBWorkloadRecordStore(DynamoDbClient client, final String tableName, final String serviceIndexName,
            final String ipIndexName) {
        this.dynamoDB = client;
        this.tableName = tableName;
        this.serviceIndexName = serviceIndexName;
        this.ipIndexName = ipIndexName;
    }

    @Override
    public WorkloadRecordStoreConnection getConnection() {
        return new DynamoDBWorkloadRecordStoreConnection(dynamoDB, tableName, serviceIndexName, ipIndexName);
    }

    @Override
    public void setOperationTimeout(int opTimeout) {
    }

    @Override
    public void clearConnections() {
    }
}
