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

package com.yahoo.athenz.db.dynamodb;

import com.google.common.io.Resources;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

public class DynamoDBClientFetcherImplTest {

    @Test
    public void testDynamoDBClientFetcherFactory() {
        DynamoDBClientFetcherFactory dynamoDBClientFetcherFactory = new DynamoDBClientFetcherFactory();
        assertNotNull(dynamoDBClientFetcherFactory);
        assertNotNull(DynamoDBClientFetcherFactory.getDynamoDBClientFetcher());
    }

    @Test
    public void testGetClientWitSpecifiedRegion() {
        DynamoDBClientFetcher dynamoDBClientFetcher = DynamoDBClientFetcherFactory.getDynamoDBClientFetcher();
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(null, null, null, null, null,
                null, "test.region", null, null, keyStore, null, null, null, null);
        DynamoDbClient dynamoDbClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender,
                dynamoDBClientSettings).getDynamoDbClient();
        assertNotNull(dynamoDbClient);
        DynamoDbAsyncClient dynamoDbAsyncClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender,
                dynamoDBClientSettings).getDynamoDbAsyncClient();
        assertNotNull(dynamoDbAsyncClient);
    }

    @Test
    public void testGetClientWithDefaultRegion() {
        DynamoDBClientFetcher dynamoDBClientFetcher = new DynamoDBClientFetcherImpl("testRegion");
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(null, null, null, null, null,
                null, "testRegion", null, null, keyStore, null, null, null, null);
        DynamoDbClient dynamoDbClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender,
                dynamoDBClientSettings).getDynamoDbClient();
        assertNotNull(dynamoDbClient);
        DynamoDbAsyncClient dynamoDbAsyncClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender,
                dynamoDBClientSettings).getDynamoDbAsyncClient();
        assertNotNull(dynamoDbAsyncClient);
    }

    @Test
    public void testGetAuthenticatedClient() {
        String certPath = Resources.getResource("gdpr.aws.core.cert.pem").getPath();//public
        String keyPath = Resources.getResource("gdpr.aws.core.key.pem").getPath();//private

        DynamoDBClientFetcherImpl dynamoDBClientFetcher = new DynamoDBClientFetcherImpl();
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        when(keyStore.getSecret(Mockito.eq(""), Mockito.eq(null), Mockito.eq("test.truststore.password")))
                .thenReturn("mockPassword".toCharArray());
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);

        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(certPath, "test.domain",
                "test.role", "test.truststore", "test.truststore.password",
                "https://dev.zts.athenzcompany.com:4443/zts/v1", "test.region", keyPath, null,
                keyStore, null, null, null, null);
        DynamoDbClient dynamoDbClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender,
                dynamoDBClientSettings).getDynamoDbClient();
        assertNotNull(dynamoDbClient);
        DynamoDbAsyncClient dynamoDbAsyncClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender,
                dynamoDBClientSettings).getDynamoDbAsyncClient();
        assertNotNull(dynamoDbAsyncClient);
    }

    @Test
    public void testGetAWSRegion() {

        DynamoDBClientFetcherImpl dynamoDBClientFetcher = new DynamoDBClientFetcherImpl();
        assertEquals(dynamoDBClientFetcher.getAWSRegion("us-west-2"), Region.of("us-west-2"));

        dynamoDBClientFetcher = new DynamoDBClientFetcherImpl("us-east-1");
        assertEquals(dynamoDBClientFetcher.getAWSRegion("us-west-2"), Region.of("us-west-2"));
        assertEquals(dynamoDBClientFetcher.getAWSRegion(""), Region.of("us-east-1"));
        assertEquals(dynamoDBClientFetcher.getAWSRegion(null), Region.of("us-east-1"));

        // if this test is running in aws, then we'll get a valid region
        // value. if running on-prem, then we'll get an exception when ec2 meta
        // api is called. so we'll get a null value back

        dynamoDBClientFetcher = new DynamoDBClientFetcherImpl();
        try {
            dynamoDBClientFetcher.getAWSRegion(null);
        } catch (Exception ignored) {
        }
    }
}
