/*
 * Copyright 2018 Oath Inc.
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

import com.yahoo.athenz.zts.cert.CertRecordStoreConnection;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class DynamoDBCertRecordStoreTest {

    @Mock private AmazonDynamoDB dbClient;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetConnection() {

        DynamoDBCertRecordStore store = new DynamoDBCertRecordStore(dbClient, "Athenz-ZTS-Table");

        CertRecordStoreConnection dbConn = store.getConnection();
        assertNotNull(dbConn);

        // empty methods
        store.setOperationTimeout(10);
        store.clearConnections();
    }

    @Test
    public void testGetConnectionException() {

        // passing null for table name to get exception
        DynamoDBCertRecordStore store = new DynamoDBCertRecordStore(dbClient, null);

        try {
            store.getConnection();
            fail();
        } catch (Exception ignored) {
        }
    }
}
