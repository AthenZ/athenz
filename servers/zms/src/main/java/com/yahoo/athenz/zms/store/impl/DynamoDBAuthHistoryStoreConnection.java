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

package com.yahoo.athenz.zms.store.impl;

import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.store.AuthHistoryRecord;
import com.yahoo.athenz.zms.store.AuthHistoryStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;

import java.util.List;
import java.util.stream.Collectors;

public class DynamoDBAuthHistoryStoreConnection implements AuthHistoryStoreConnection {
    private final DynamoDbTable<AuthHistoryRecord> table;

    public DynamoDBAuthHistoryStoreConnection(final DynamoDbTable<AuthHistoryRecord> table) {
        this.table = table;
    }

    @Override
    public void close() {

    }

    @Override
    public void setOperationTimeout(int opTimeout) {

    }

    @Override
    public List<AuthHistoryRecord> getAuthHistory(String domain) {
        try {
            // Create a QueryConditional object that is used in the query operation.
            QueryConditional queryConditional = QueryConditional
                    .keyEqualTo(Key.builder().partitionValue(domain)
                            .build());
            return table.query(r -> r.queryConditional(queryConditional))
                    .items()
                    .stream()
                    .collect(Collectors.toList());
        } catch (ResourceNotFoundException resourceNotFoundException) {
            throw ZMSUtils.error(ResourceException.NOT_FOUND, resourceNotFoundException.getMessage(), "getAuthHistory");
        }
    }
}
