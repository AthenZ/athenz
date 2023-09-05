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
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.notification.ZTSClientNotificationSenderImpl;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.yahoo.athenz.zts.ZTSConsts.*;
import static org.mockito.Mockito.when;

public class DynamoDBWorkloadRecordStoreFactoryTest {
    @Mock
    private AmazonDynamoDB dbClient;
    @Mock private Table table;
    @Mock private DynamoDB dynamoDB;

    class TestDynamoDBWorkloadRecordStoreFactory extends DynamoDBWorkloadRecordStoreFactory {

        @Override
        AmazonDynamoDB getDynamoDBClient(ZTSClientNotificationSenderImpl ztsClientNotificationSender, PrivateKeyStore keyStore) {
            return dbClient;
        }
    }

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        Mockito.doReturn(table).when(dynamoDB).getTable("Workloads-Table");
    }

    @Test
    public void testCreate() {

        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME, "Workload-Table");
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME, "Workload-Service-Index");
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME, "Workload-Ip-Index");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory();
        WorkloadRecordStore store = factory.create(keyStore);
        Assert.assertNotNull(store);

        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME);
    }

    @Test
    public void testCreateAmzClient() {

        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME, "Workload-Table");
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME, "Workload-Service-Index");
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME, "Workload-Ip-Index");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory();
        try {
            factory.create(keyStore);
        } catch (Exception ignored) {
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME);
    }

    @Test
    public void testCreateMissingTableName() {

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
        DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory();
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ResourceException ex) {
            Assert.assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
        }

        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME, "");
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ResourceException ex) {
            Assert.assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
    }

    @Test
    public void testCreateMissingIndexName() {
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME, "Workloads-Table");
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        // First, don't set any index - will fail on ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME index
        DynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactory();
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ResourceException ex) {
            Assert.assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
            Assert.assertEquals(ex.getMessage(), "ResourceException (503): DynamoDB index workload-service-index not specified");
        }

        // Set it to empty value, will still fail
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME, "");
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ResourceException ex) {
            Assert.assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
            Assert.assertEquals(ex.getMessage(), "ResourceException (503): DynamoDB index workload-service-index not specified");
        }

        // Set it to correct value, now will fail on host
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME, "Workload-Service-Index");
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ResourceException ex) {
            Assert.assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
            Assert.assertEquals(ex.getMessage(), "ResourceException (503): DynamoDB index workload-ip-index not specified");
        }

        // Set it to empty value, will still fail
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME, "");
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ResourceException ex) {
            Assert.assertEquals(ex.getCode(), ResourceException.SERVICE_UNAVAILABLE);
            Assert.assertEquals(ex.getMessage(), "ResourceException (503): DynamoDB index workload-ip-index not specified");
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME);
        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME);

        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
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
        when(keyStore.getSecret(Mockito.eq("test.appname"), Mockito.eq("test.truststore.password")))
                .thenReturn("decryptedPassword".toCharArray());

        DynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactory();
        ZTSClientNotificationSenderImpl ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSenderImpl.class);
        PrivateKeyStore privateKeyStore = Mockito.mock(PrivateKeyStore.class);
        AmazonDynamoDB dynamoDBClient = factory.getDynamoDBClient(ztsClientNotificationSender, privateKeyStore);
        Assert.assertNotNull(dynamoDBClient);

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