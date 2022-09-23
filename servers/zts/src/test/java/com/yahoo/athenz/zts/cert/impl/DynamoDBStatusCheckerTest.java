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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.ListTablesResult;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.status.StatusCheckException;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientAndCredentials;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcher;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientSettings;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.AssertJUnit.*;

public class DynamoDBStatusCheckerTest {

    @Mock private DynamoDBClientFetcher dynamoDBClientFetcher;
    @Mock private AmazonDynamoDB amazonDynamoDB;
    @Mock private AWSCredentialsProviderImpl awsCredentialsProvider;
    @Mock private ListTablesResult listTablesResult;
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
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testCheck() throws StatusCheckException, IOException {
        // Mock getting client and credentials successfully and table exists
        String tableName = "testTable";
        when(listTablesResult.getTableNames()).thenReturn(Collections.singletonList(tableName));
        when(amazonDynamoDB.listTables()).thenReturn(listTablesResult);
        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(amazonDynamoDB, null, awsCredentialsProvider);
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class))).thenReturn(dynamoDBClientAndCredentials);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(tableName);

        dynamoDBStatusChecker.check();
        Mockito.verify(amazonDynamoDB, times(1)).shutdown();
        Mockito.verify(awsCredentialsProvider, times(1)).close();
    }

    @Test
    public void testCheckNoCredentialsProvider() throws StatusCheckException, IOException {
        // Mock getting client and credentials successfully and table exists
        String tableName = "testTable";
        when(listTablesResult.getTableNames()).thenReturn(Collections.singletonList(tableName));
        when(amazonDynamoDB.listTables()).thenReturn(listTablesResult);
        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(amazonDynamoDB, null, null);
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class))).thenReturn(dynamoDBClientAndCredentials);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(tableName);

        dynamoDBStatusChecker.check();
        Mockito.verify(amazonDynamoDB, times(1)).shutdown();
        Mockito.verify(awsCredentialsProvider, times(0)).close();
    }

    @Test
    public void testCheckNoDynamoDBClient() throws StatusCheckException, IOException {
        // Mock getting client and credentials successfully and table exists
        String tableName = "testTable";
        when(listTablesResult.getTableNames()).thenReturn(Collections.singletonList(tableName));
        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(null, null, awsCredentialsProvider);
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class))).thenReturn(dynamoDBClientAndCredentials);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(tableName);

        try {
            dynamoDBStatusChecker.check();
            fail();
        } catch (StatusCheckException ex) {
            assertEquals(500, ex.getCode());
            Mockito.verify(amazonDynamoDB, times(0)).shutdown();
            Mockito.verify(awsCredentialsProvider, times(1)).close();
        }
    }

    @Test
    public void testTableNotFound() throws IOException {
        String requestedTable = "requestedTable";
        String tableNameInAws = "someExistingTable";
        // Mock getting client and credentials successfully but table doesn't exist
        when(listTablesResult.getTableNames()).thenReturn(Collections.singletonList(tableNameInAws));
        when(amazonDynamoDB.listTables()).thenReturn(listTablesResult);
        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(amazonDynamoDB, null, awsCredentialsProvider);
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class))).thenReturn(dynamoDBClientAndCredentials);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(requestedTable);

        try {
            dynamoDBStatusChecker.check();
            fail();
        } catch (StatusCheckException ex) {
            assertEquals("Table named " + requestedTable + " wasn't found in DynamoDB", ex.getMsg());
            assertEquals(200, ex.getCode());
        }
        Mockito.verify(amazonDynamoDB, times(1)).shutdown();
        Mockito.verify(awsCredentialsProvider, times(1)).close();
    }

    @Test
    public void testClientNullTables() throws IOException {
        // Mock getting client and credentials successfully but client returns null instead of tables
        String tableName = "testTable";
        when(amazonDynamoDB.listTables()).thenReturn(null);

        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(amazonDynamoDB, null, awsCredentialsProvider);
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class))).thenReturn(dynamoDBClientAndCredentials);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(tableName);

        try {
            dynamoDBStatusChecker.check();
            fail();
        } catch (StatusCheckException ex) {
            assertNull(ex.getMessage());
            assertEquals(500, ex.getCode());
        }

        Mockito.verify(amazonDynamoDB, times(1)).shutdown();
        Mockito.verify(awsCredentialsProvider, times(1)).close();
    }

    @Test
    public void testClientNull() throws IOException {
        String tableName = "testTable";
        // Mock getting client failed (returns null)
        when(dynamoDBClientFetcher.getDynamoDBClient(any(), any(DynamoDBClientSettings.class))).thenReturn(null);
        DynamoDBStatusCheckerTestClass dynamoDBStatusChecker = new DynamoDBStatusCheckerTestClass(tableName);

        try {
            dynamoDBStatusChecker.check();
            fail();
        } catch (StatusCheckException ex) {
            assertNull(ex.getMessage());
            assertEquals(500, ex.getCode());
        }

        Mockito.verify(amazonDynamoDB, times(0)).shutdown();
        Mockito.verify(awsCredentialsProvider, times(0)).close();
    }

    @Test
    public void testGetDynamoDBClientFetcher() {
        DynamoDBStatusChecker dynamoDBStatusChecker = new DynamoDBStatusChecker("testTable", keyStore);
        DynamoDBClientFetcher dynamoDBClientFetcher = dynamoDBStatusChecker.getDynamoDBClientFetcher();
        assertNotNull(dynamoDBClientFetcher);
    }
}
