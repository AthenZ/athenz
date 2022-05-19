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

package com.yahoo.athenz.common.server.db;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.google.common.io.Resources;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

public class DynamoDBClientFetcherImplTest {

    @Test
    public void testGetClientWitSpecifiedRegion() {
        MockDynamoDBClientSettings mockDynamoDBClientSettings = new MockDynamoDBClientSettings();
        mockDynamoDBClientSettings.setRegion("test.region");
        DynamoDBClientSettingsFactory dynamoDBClientSettingsFactory = keyStore -> mockDynamoDBClientSettings;
        DynamoDBClientFetcher dynamoDBClientFetcher = new DynamoDBClientFetcherImpl(dynamoDBClientSettingsFactory);
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        AmazonDynamoDB dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);
    }

    @Test
    public void testGetClientWithDefaultRegion() {
        MockDynamoDBClientSettings mockDynamoDBClientSettings = new MockDynamoDBClientSettings();
        DynamoDBClientSettingsFactory dynamoDBClientSettingsFactory = keyStore -> mockDynamoDBClientSettings;
        DynamoDBClientFetcher dynamoDBClientFetcher = new DynamoDBClientFetcherImpl("testRegion", dynamoDBClientSettingsFactory);
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        AmazonDynamoDB dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);
    }

    @Test
    public void testGetAuthenticatedClient() {
        String certPath = Resources.getResource("gdpr.aws.core.cert.pem").getPath();//public
        String keyPath = Resources.getResource("unit_test_gdpr.aws.core.key.pem").getPath();//private

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        when(keyStore.getSecret(Mockito.eq(""), Mockito.eq("test.truststore.password"))).thenReturn("mockPassword".toCharArray());
        MockDynamoDBClientSettings mockDynamoDBClientSettings = new MockDynamoDBClientSettings();
        mockDynamoDBClientSettings.setKeyPath(keyPath);
        mockDynamoDBClientSettings.setCertPath(certPath);
        mockDynamoDBClientSettings.setDomainName("test.domain");
        mockDynamoDBClientSettings.setRegion("test.region");
        mockDynamoDBClientSettings.setRoleName("test.role");
        mockDynamoDBClientSettings.setTrustStore("test.truststore");
        mockDynamoDBClientSettings.setTrustStorePassword("test.truststore.password");
        mockDynamoDBClientSettings.setZtsURL("https://dev.zts.athenzcompany.com:4443/zts/v1");
        mockDynamoDBClientSettings.setKeyStore(keyStore);

        DynamoDBClientSettingsFactory dynamoDBClientSettingsFactory = store -> mockDynamoDBClientSettings;
        DynamoDBClientFetcherImpl dynamoDBClientFetcher = new DynamoDBClientFetcherImpl(dynamoDBClientSettingsFactory);
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore);
        AmazonDynamoDB dynamoDBClient = dynamoDBClientAndCredentials.getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);
        DynamoDbEnhancedClient dynamoDbEnhancedClient = dynamoDBClientAndCredentials.getDynamoDbEnhancedClient();
        assertNotNull(dynamoDbEnhancedClient);

        // Also try with min, max expiry and externalId set
        mockDynamoDBClientSettings.setMinExpiryTimeStr("10");
        mockDynamoDBClientSettings.setMaxExpiryTimeStr("100");
        mockDynamoDBClientSettings.setExternalId("test");
        dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);
    }

    @Test
    public void testGetAWSRegion() {
        MockDynamoDBClientSettings mockDynamoDBClientSettings = new MockDynamoDBClientSettings();
        DynamoDBClientSettingsFactory dynamoDBClientSettingsFactory = keyStore -> mockDynamoDBClientSettings;
        DynamoDBClientFetcherImpl dynamoDBClientFetcher = new DynamoDBClientFetcherImpl(dynamoDBClientSettingsFactory);
        assertEquals(dynamoDBClientFetcher.getAWSRegion("us-west-2"), "us-west-2");

        dynamoDBClientFetcher = new DynamoDBClientFetcherImpl("us-east-1", dynamoDBClientSettingsFactory);
        assertEquals(dynamoDBClientFetcher.getAWSRegion("us-west-2"), "us-west-2");
        assertEquals(dynamoDBClientFetcher.getAWSRegion(""), "us-east-1");
        assertEquals(dynamoDBClientFetcher.getAWSRegion(null), "us-east-1");

        // if this test is running in aws, then we'll get a valid region
        // value. if running on-prem, then we'll get an exception when ec2 meta
        // api is called. so we'll get a null value back

        dynamoDBClientFetcher = new DynamoDBClientFetcherImpl(dynamoDBClientSettingsFactory);
        dynamoDBClientFetcher.getAWSRegion(null);
    }
}
