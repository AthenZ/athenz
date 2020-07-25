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

import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.notification.ZTSClientNotificationSenderImpl;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ZTSConsts;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;

import static com.yahoo.athenz.zts.ZTSConsts.*;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class DynamoDBCertRecordStoreFactoryTest {

    @Mock private AmazonDynamoDB dbClient;
    @Mock private Table table;
    @Mock private DynamoDB dynamoDB;

    class TestDynamoDBCertRecordStoreFactory extends DynamoDBCertRecordStoreFactory {

        @Override
        AmazonDynamoDB getDynamoDBClient(ZTSClientNotificationSenderImpl ztsClientNotificationSender, PrivateKeyStore keyStore) {
            return dbClient;
        }
    }

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        Mockito.doReturn(table).when(dynamoDB).getTable("Athenz-ZTS-Table");
    }

    @Test
    public void testCreate() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME, "Athenz-ZTS-Table");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_INDEX_CURRENT_TIME_NAME, "Athenz-ZTS-Current-Time-Index");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        TestDynamoDBCertRecordStoreFactory factory = new TestDynamoDBCertRecordStoreFactory();
        CertRecordStore store = factory.create(keyStore);
        assertNotNull(store);

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_INDEX_CURRENT_TIME_NAME);
    }

    @Test
    public void testCreateAmzClient() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME, "Athenz-ZTS-Table");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_INDEX_CURRENT_TIME_NAME, "Athenz-ZTS-Current-Time-Index");


        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        TestDynamoDBCertRecordStoreFactory factory = new TestDynamoDBCertRecordStoreFactory();
        try {
            factory.create(keyStore);
        } catch (Exception ignored) {
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_INDEX_CURRENT_TIME_NAME);
    }

    @Test
    public void testCreateMissingTableName() {

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME);
        TestDynamoDBCertRecordStoreFactory factory = new TestDynamoDBCertRecordStoreFactory();
        try {
            factory.create(keyStore);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
        }

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME, "");
        try {
            factory.create(keyStore);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME);
    }

    @Test
    public void testCreateMissingIndexName() {

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME, "Athenz-ZTS-Table");
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_INDEX_CURRENT_TIME_NAME);
        DynamoDBCertRecordStoreFactory factory = new DynamoDBCertRecordStoreFactory();
        try {
            factory.create(keyStore);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
        }

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_INDEX_CURRENT_TIME_NAME, "");
        try {
            factory.create(keyStore);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_INDEX_CURRENT_TIME_NAME);
    }

    @Test
    public void testGetDynamoDBClient() {
        System.setProperty(ZTS_PROP_DYNAMODB_KEY_PATH, "test.keypath");
        System.setProperty(ZTS_PROP_DYNAMODB_CERT_PATH, "test.certpath");
        System.setProperty(ZTS_PROP_DYNAMODB_DOMAIN, "test.domain");
        System.setProperty(ZTS_PROP_DYNAMODB_REGION, "test.region");
        System.setProperty(ZTS_PROP_DYNAMODB_ROLE, "test.role");
        System.setProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE, "test.truststore");
        System.setProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "test.truststore.password");
        System.setProperty(ZTS_PROP_DYNAMODB_ZTS_URL, "test.ztsurl");
        System.setProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_APPNAME, "test.appname");
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        when(keyStore.getApplicationSecret(Mockito.eq("test.appname"), Mockito.eq("test.truststore.password")))
                .thenReturn("decryptedPassword");

        DynamoDBCertRecordStoreFactory factory = new DynamoDBCertRecordStoreFactory();
        ZTSClientNotificationSenderImpl ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSenderImpl.class);
        PrivateKeyStore privateKeyStore = Mockito.mock(PrivateKeyStore.class);
        AmazonDynamoDB dynamoDBClient = factory.getDynamoDBClient(ztsClientNotificationSender, privateKeyStore);
        assertNotNull(dynamoDBClient);

        System.clearProperty(ZTS_PROP_DYNAMODB_KEY_PATH);
        System.clearProperty(ZTS_PROP_DYNAMODB_CERT_PATH);
        System.clearProperty(ZTS_PROP_DYNAMODB_DOMAIN);
        System.clearProperty(ZTS_PROP_DYNAMODB_REGION);
        System.clearProperty(ZTS_PROP_DYNAMODB_ROLE);
        System.clearProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE);
        System.clearProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD);
        System.clearProperty(ZTS_PROP_DYNAMODB_ZTS_URL);
        System.clearProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_APPNAME);
    }
}
