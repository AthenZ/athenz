/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.status.StatusCheckException;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientAndCredentials;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcher;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientSettings;
import com.yahoo.athenz.zts.AWSCredentialsProviderImplV2;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ListTablesRequest;
import software.amazon.awssdk.services.dynamodb.model.ListTablesResponse;

import java.io.IOException;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.AssertJUnit.*;

public class DynamoDBStatusCheckerTest {

    @Mock private DynamoDBClientFetcher dynamoDBClientFetcher;
    @Mock private DynamoDbClient amazonDynamoDB;
    @Mock private DynamoDbAsyncClient amazonDynamoAsyncDB;
    @Mock private AWSCredentialsProviderImplV2 awsCredentialsProvider;
    @Mock private PrivateKeyStore keyStore;

    public class DynamoDBStatusCheckerTestClass extends DynamoDBStatusChecker {

        public DynamoDBStatusCheckerTestClass(String tableName) {
            super(tableName, keyStore);
        }

        @Override
        DynamoDBClientFetcher getDynamoDBClientFetcher() {
            return dynamoDBClientFetcher;
        }
    }

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testCheck() throws StatusCheckException, IOException {
        // Mock getting client and credentials successfully and table exists
        String tableName = "testTable";

        ListTablesResponse response = Mockito.mock(ListTablesResponse.class);
        Mockito.when(amazonDynamoDB.listTables((ListTablesRequest) any())).thenReturn(response);
        when(response.tableNames()).thenReturn(Collections.singletonList(tableName));
        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(amazonDynamoDB,
                amazonDynamoAsyncDB, awsCredentialsProvider);
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class)))
                .thenReturn(dynamoDBClientAndCredentials);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(tableName);

        dynamoDBStatusChecker.check();
        Mockito.verify(amazonDynamoDB, times(1)).close();
        Mockito.verify(awsCredentialsProvider, times(1)).close();
    }

    @Test
    public void testCheckNoCredentialsProvider() throws StatusCheckException, IOException {
        // Mock getting client and credentials successfully and table exists
        String tableName = "testTable";

        ListTablesResponse response = Mockito.mock(ListTablesResponse.class);
        Mockito.when(amazonDynamoDB.listTables((ListTablesRequest) any())).thenReturn(response);
        when(response.tableNames()).thenReturn(Collections.singletonList(tableName));

        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(amazonDynamoDB,
                amazonDynamoAsyncDB, null);
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class)))
                .thenReturn(dynamoDBClientAndCredentials);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(tableName);

        dynamoDBStatusChecker.check();
        Mockito.verify(amazonDynamoDB, times(1)).close();
        Mockito.verify(awsCredentialsProvider, times(0)).close();
    }

    @Test
    public void testTableNotFound() throws IOException {
        String requestedTable = "requestedTable";
        String tableNameInAws = "someExistingTable";
        // Mock getting client and credentials successfully but table doesn't exist

        ListTablesResponse response = Mockito.mock(ListTablesResponse.class);
        Mockito.when(amazonDynamoDB.listTables((ListTablesRequest) any())).thenReturn(response);
        when(response.tableNames()).thenReturn(Collections.singletonList(tableNameInAws));

        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(amazonDynamoDB,
                amazonDynamoAsyncDB, awsCredentialsProvider);
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class)))
                .thenReturn(dynamoDBClientAndCredentials);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(requestedTable);

        try {
            dynamoDBStatusChecker.check();
            fail();
        } catch (StatusCheckException ex) {
            assertEquals("Table named " + requestedTable + " wasn't found in DynamoDB", ex.getMsg());
            assertEquals(200, ex.getCode());
        }
        Mockito.verify(amazonDynamoDB, times(1)).close();
        Mockito.verify(awsCredentialsProvider, times(1)).close();
    }

    @Test
    public void testClientNullTables() throws IOException {
        // Mock getting client and credentials successfully but client returns null instead of tables
        String tableName = "testTable";
        Mockito.when(amazonDynamoDB.listTables((ListTablesRequest) any())).thenReturn(null);

        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(amazonDynamoDB,
                amazonDynamoAsyncDB, awsCredentialsProvider);
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class)))
                .thenReturn(dynamoDBClientAndCredentials);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(tableName);

        try {
            dynamoDBStatusChecker.check();
            fail();
        } catch (StatusCheckException ex) {
            assertNull(ex.getMessage());
            assertEquals(500, ex.getCode());
        }

        Mockito.verify(amazonDynamoDB, times(1)).close();
        Mockito.verify(awsCredentialsProvider, times(1)).close();
    }

    @Test
    public void testGetDynamoDBClientFetcher() {
        DynamoDBStatusChecker dynamoDBStatusChecker = new DynamoDBStatusChecker("testTable", keyStore);
        DynamoDBClientFetcher dynamoDBClientFetcher = dynamoDBStatusChecker.getDynamoDBClientFetcher();
        assertNotNull(dynamoDBClientFetcher);
    }
}
