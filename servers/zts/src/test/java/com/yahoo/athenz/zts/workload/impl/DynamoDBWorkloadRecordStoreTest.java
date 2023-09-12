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
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;


public class DynamoDBWorkloadRecordStoreTest {

    @Mock
    private AmazonDynamoDB dbClient;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetConnection() {

        DynamoDBWorkloadRecordStore store = new DynamoDBWorkloadRecordStore(dbClient, "Workload-Table", "service-index", "ip-index");

        WorkloadRecordStoreConnection dbConn = store.getConnection();
        Assert.assertNotNull(dbConn);

        // empty methods
        store.setOperationTimeout(10);
        store.clearConnections();
    }

    @Test
    public void testGetConnectionException() {

        // passing null for table name to get exception
        DynamoDBWorkloadRecordStore store = new DynamoDBWorkloadRecordStore(dbClient, null, null, null);

        try {
            store.getConnection();
            Assert.fail();
        } catch (Exception ignored) {
        }
    }

}
