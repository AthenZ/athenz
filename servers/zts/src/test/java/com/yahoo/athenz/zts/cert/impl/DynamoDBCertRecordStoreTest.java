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
package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.zts.notification.ZTSClientNotificationSenderImpl;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.X509Certificate;

import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

public class DynamoDBCertRecordStoreTest {

    @Mock private AmazonDynamoDB dbClient;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetConnection() {

        DynamoDBCertRecordStore store = new DynamoDBCertRecordStore(
                dbClient,
                "Athenz-ZTS-Table",
                "Athenz-ZTS-Current-Time-Index",
                "Athenz-ZTS-Host-Name-Index",
                null);

        CertRecordStoreConnection dbConn = store.getConnection();
        assertNotNull(dbConn);

        // empty methods
        store.setOperationTimeout(10);
        store.clearConnections();
    }

    @Test
    public void testGetConnectionException() {

        // passing null for table name to get exception
        DynamoDBCertRecordStore store = new DynamoDBCertRecordStore(
                dbClient,
                null,
                "Athenz-ZTS-Current-Time-Index",
                "Athenz-ZTS-Host-Name-Index",
                null);

        try {
            store.getConnection();
            fail();
        } catch (Exception ignored) {
        }

        // passing null for index name to get exception
        store = new DynamoDBCertRecordStore(dbClient, "Athenz-ZTS-Table", null, null, null);

        try {
            store.getConnection();
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testLog() {

        DynamoDBCertRecordStore store = new DynamoDBCertRecordStore(
                dbClient,
                "Athenz-ZTS-Table",
                "Athenz-ZTS-Current-Time-Index",
                "Athenz-ZTS-Host-Name-Index",
                null);

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

    @Test
    public void testEnableNotifications() {
        DynamoDBCertRecordStore store = new DynamoDBCertRecordStore(
                dbClient,
                "Athenz-ZTS-Table",
                "Athenz-ZTS-Current-Time-Index",
                "Athenz-ZTS-Host-Name-Index",
                null);
        boolean isEnabled = store.enableNotifications(null, null, null);
        assertFalse(isEnabled);

        ZTSClientNotificationSenderImpl ztsClientNotificationSender = new ZTSClientNotificationSenderImpl();
        store = new DynamoDBCertRecordStore(
                dbClient,
                "Athenz-ZTS-Table",
                "Athenz-ZTS-Current-Time-Index",
                "Athenz-ZTS-Host-Name-Index",
                ztsClientNotificationSender);
        isEnabled = store.enableNotifications(null, null, null);
        assertFalse(isEnabled);

        NotificationManager notificationManager = Mockito.mock(NotificationManager.class);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        String serverName = "testServer";
        isEnabled = store.enableNotifications(notificationManager, rolesProvider, serverName);
        assertTrue(isEnabled);
    }
}
