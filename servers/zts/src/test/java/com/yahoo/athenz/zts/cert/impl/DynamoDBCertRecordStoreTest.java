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

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.cert.CertRecordStoreConnection;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.X509Certificate;

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

    @Test
    public void testLog() {

        DynamoDBCertRecordStore store = new DynamoDBCertRecordStore(dbClient, "Athenz-ZTS-Table");

        File file = new File("src/test/resources/cert_log.pem");
        String pem = null;
        try {
            pem = new String(Files.readAllBytes(file.toPath()));
        } catch (IOException ex) {
            fail();
        }
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        Principal principal = SimplePrincipal.create("user", "joe", "creds");

        // make sure no exceptions are thrown when processing log request

        store.log(principal, "10.11.12.13", "athens.provider", "1234", cert);
    }
}
