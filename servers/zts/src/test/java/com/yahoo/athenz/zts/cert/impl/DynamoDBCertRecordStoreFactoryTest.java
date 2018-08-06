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
import com.yahoo.athenz.zts.ResourceException;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.CertRecordStore;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class DynamoDBCertRecordStoreFactoryTest {

    @Mock private AmazonDynamoDB dbClient;
    @Mock private Table table;

    @Mock private DynamoDB dynamoDB;

    class TestDynamoDBCertRecordStoreFactory extends DynamoDBCertRecordStoreFactory {

        @Override
        AmazonDynamoDB getDynamoDBClient() {
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

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        TestDynamoDBCertRecordStoreFactory factory = new TestDynamoDBCertRecordStoreFactory();
        CertRecordStore store = factory.create(keyStore);
        assertNotNull(store);
    }

    @Test
    public void testCreateAmzClient() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME, "Athenz-ZTS-Table");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        DynamoDBCertRecordStoreFactory factory = new DynamoDBCertRecordStoreFactory();
        try {
            factory.create(keyStore);
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testCreateMissingTableName() {

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME);
        DynamoDBCertRecordStoreFactory factory = new DynamoDBCertRecordStoreFactory();
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
}
