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

import com.yahoo.athenz.zms.store.AuthHistoryStoreConnection;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import static org.testng.AssertJUnit.assertNotNull;

public class DynamoDBAuthHistoryStoreTest {
    @Test
    public void testGetConnection() {
        DynamoDbClient dynamoDb = Mockito.mock(DynamoDbClient.class);
        DynamoDBAuthHistoryStore dynamoDBAuthHistoryStore = new DynamoDBAuthHistoryStore("TEST_TABLE", dynamoDb);
        AuthHistoryStoreConnection connection = dynamoDBAuthHistoryStore.getConnection();
        assertNotNull(connection);
        dynamoDBAuthHistoryStore.setOperationTimeout(0);
        dynamoDBAuthHistoryStore.clearConnections();
    }
}
