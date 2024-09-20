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
package io.athenz.server.aws.common.workload.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import io.athenz.server.aws.common.cert.impl.ZTSDynamoDBClientSettingsFactory;
import io.athenz.server.aws.common.notification.impl.ZTSClientNotificationSenderImpl;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import static org.mockito.Mockito.when;

public class DynamoDBWorkloadRecordStoreFactoryTest {

    @Mock private DynamoDbClient dbClient;

    class TestDynamoDBWorkloadRecordStoreFactory extends DynamoDBWorkloadRecordStoreFactory {

        @Override
        DynamoDbClient getDynamoDBClient(ZTSClientNotificationSenderImpl ztsClientNotificationSender, PrivateKeyStore keyStore) {
            return dbClient;
        }
    }

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testCreate() throws ServerResourceException {

        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME, "Workload-Table");
        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME, "Workload-Service-Index");
        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME, "Workload-Ip-Index");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory();
        WorkloadRecordStore store = factory.create(keyStore);
        Assert.assertNotNull(store);

        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME);
        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME);
    }

    @Test
    public void testCreateAmzClient() {

        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME, "Workload-Table");
        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME, "Workload-Service-Index");
        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME, "Workload-Ip-Index");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory();
        try {
            factory.create(keyStore);
        } catch (Exception ignored) {
        }

        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME);
        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME);
    }

    @Test
    public void testCreateMissingTableName() {

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
        DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactoryTest.TestDynamoDBWorkloadRecordStoreFactory();
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
        }

        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME, "");
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
        }

        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
    }

    @Test
    public void testCreateMissingIndexName() {
        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME, "Workloads-Table");
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        // First, don't set any index - will fail on DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME index
        DynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactory();
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
            Assert.assertEquals(ex.getMessage(), "DynamoDB index workload-service-index not specified");
        }

        // Set it to empty value, will still fail
        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME, "");
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
            Assert.assertEquals(ex.getMessage(), "DynamoDB index workload-service-index not specified");
        }

        // Set it to correct value, now will fail on host
        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME, "Workload-Service-Index");
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
            Assert.assertEquals(ex.getMessage(), "DynamoDB index workload-ip-index not specified");
        }

        // Set it to empty value, will still fail
        System.setProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME, "");
        try {
            factory.create(keyStore);
            Assert.fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
            Assert.assertEquals(ex.getMessage(), "DynamoDB index workload-ip-index not specified");
        }

        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME);
        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME);

        System.clearProperty(DynamoDBWorkloadRecordStoreFactory.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
    }

    @Test
    public void testGetDynamoDBClient() {
        System.setProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_KEY_PATH, "test.keypath");
        System.setProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_CERT_PATH, "test.certpath");
        System.setProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_DOMAIN, "test.domain");
        System.setProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_REGION, "test.region");
        System.setProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_ROLE, "test.role");
        System.setProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_TRUSTSTORE, "test.truststore");
        System.setProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "test.truststore.password");
        System.setProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_ZTS_URL, "test.ztsurl");
        System.setProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_TRUSTSTORE_APPNAME, "test.appname");
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        when(keyStore.getSecret(Mockito.eq("test.appname"), Mockito.eq(null), Mockito.eq("test.truststore.password")))
                .thenReturn("decryptedPassword".toCharArray());

        DynamoDBWorkloadRecordStoreFactory factory = new DynamoDBWorkloadRecordStoreFactory();
        ZTSClientNotificationSenderImpl ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSenderImpl.class);
        PrivateKeyStore privateKeyStore = Mockito.mock(PrivateKeyStore.class);
        DynamoDbClient dynamoDBClient = factory.getDynamoDBClient(ztsClientNotificationSender, privateKeyStore);
        Assert.assertNotNull(dynamoDBClient);

        System.clearProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_KEY_PATH);
        System.clearProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_CERT_PATH);
        System.clearProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_DOMAIN);
        System.clearProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_REGION);
        System.clearProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_ROLE);
        System.clearProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_TRUSTSTORE);
        System.clearProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD);
        System.clearProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_ZTS_URL);
        System.clearProperty(ZTSDynamoDBClientSettingsFactory.ZTS_PROP_DYNAMODB_TRUSTSTORE_APPNAME);
    }
}