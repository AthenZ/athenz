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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.google.common.io.Resources;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

public class DynamoDBClientFetcherImplTest {

    private static final String ZTS_PROP_DYNAMODB_KEY_PATH            = "athenz.zts.dynamodb_key_path";
    private static final String ZTS_PROP_DYNAMODB_CERT_PATH           = "athenz.zts.dynamodb_cert_path";
    private static final String ZTS_PROP_DYNAMODB_DOMAIN              = "athenz.zts.dynamodb_aws_domain";
    private static final String ZTS_PROP_DYNAMODB_ROLE                = "athenz.zts.dynamodb_aws_role";
    private static final String ZTS_PROP_DYNAMODB_TRUSTSTORE          = "athenz.zts.dynamodb_trust_store_path";
    private static final String ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD = "athenz.zts.dynamodb_trust_store_password";
    private static final String ZTS_PROP_DYNAMODB_REGION              = "athenz.zts.dynamodb_region";
    private static final String ZTS_PROP_DYNAMODB_ZTS_URL             = "athenz.zts.dynamodb_zts_url";
    private static final String ZTS_PROP_DYNAMODB_MIN_EXPIRY_TIME     = "athenz.zts.dynamodb_min_expiry_time";
    private static final String ZTS_PROP_DYNAMODB_MAX_EXPIRY_TIME     = "athenz.zts.dynamodb_max_expiry_time";

    @Test
    public void testGetClientWitSpecifiedRegion() {
        System.setProperty(ZTS_PROP_DYNAMODB_REGION, "test.region");
        DynamoDBClientFetcher dynamoDBClientFetcher = DynamoDBClientFetcherFactory.getDynamoDBClientFetcher();
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        AmazonDynamoDB dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);
        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(null, null, null, null, null, null, "test.region", null, null, keyStore, null, null, null);
        dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, dynamoDBClientSettings).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);
        System.clearProperty(ZTS_PROP_DYNAMODB_REGION);
    }

    @Test
    public void testGetClientWithDefaultRegion() {
        DynamoDBClientFetcher dynamoDBClientFetcher = new DynamoDBClientFetcherImpl("testRegion");
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        AmazonDynamoDB dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);
        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(null, null, null, null, null, null, "testRegion", null, null, keyStore, null, null, null);
        dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, dynamoDBClientSettings).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);
    }

    @Test
    public void testGetAuthenticatedClient() {
        String certPath = Resources.getResource("gdpr.aws.core.cert.pem").getPath();//public
        String keyPath = Resources.getResource("gdpr.aws.core.key.pem").getPath();//private

        System.setProperty(ZTS_PROP_DYNAMODB_KEY_PATH, keyPath);
        System.setProperty(ZTS_PROP_DYNAMODB_CERT_PATH, certPath);
        System.setProperty(ZTS_PROP_DYNAMODB_DOMAIN, "test.domain");
        System.setProperty(ZTS_PROP_DYNAMODB_REGION, "test.region");
        System.setProperty(ZTS_PROP_DYNAMODB_ROLE, "test.role");
        System.setProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE, "test.truststore");
        System.setProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "test.truststore.password");
        System.setProperty(ZTS_PROP_DYNAMODB_ZTS_URL, "https://dev.zts.athenzcompany.com:4443/zts/v1");

        DynamoDBClientFetcherImpl dynamoDBClientFetcher = new DynamoDBClientFetcherImpl();
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        when(keyStore.getSecret(Mockito.eq(""), Mockito.eq("test.truststore.password"))).thenReturn("mockPassword".toCharArray());
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        AmazonDynamoDB dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);

        // Also try with min and max expiry set
        System.setProperty(ZTS_PROP_DYNAMODB_MIN_EXPIRY_TIME, "10");
        System.setProperty(ZTS_PROP_DYNAMODB_MAX_EXPIRY_TIME, "100");
        dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);

        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(certPath, "test.domain", "test.role", "test.truststore", "test.truststore.password", "https://dev.zts.athenzcompany.com:4443/zts/v1", "test.region", keyPath, null, keyStore, null, null, null);
        dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, dynamoDBClientSettings).getAmazonDynamoDB();
        assertNotNull(dynamoDBClient);

        System.clearProperty(ZTS_PROP_DYNAMODB_KEY_PATH);
        System.clearProperty(ZTS_PROP_DYNAMODB_CERT_PATH);
        System.clearProperty(ZTS_PROP_DYNAMODB_DOMAIN);
        System.clearProperty(ZTS_PROP_DYNAMODB_REGION);
        System.clearProperty(ZTS_PROP_DYNAMODB_ROLE);
        System.clearProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE);
        System.clearProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD);
        System.clearProperty(ZTS_PROP_DYNAMODB_ZTS_URL);
    }

    @Test
    public void testGetAWSRegion() {

        DynamoDBClientFetcherImpl dynamoDBClientFetcher = new DynamoDBClientFetcherImpl();
        assertEquals(dynamoDBClientFetcher.getAWSRegion("us-west-2"), "us-west-2");

        dynamoDBClientFetcher = new DynamoDBClientFetcherImpl("us-east-1");
        assertEquals(dynamoDBClientFetcher.getAWSRegion("us-west-2"), "us-west-2");
        assertEquals(dynamoDBClientFetcher.getAWSRegion(""), "us-east-1");
        assertEquals(dynamoDBClientFetcher.getAWSRegion(null), "us-east-1");

        // if this test is running in aws, then we'll get a valid region
        // value. if running on-prem, then we'll get an exception when ec2 meta
        // api is called. so we'll get a null value back

        dynamoDBClientFetcher = new DynamoDBClientFetcherImpl();
        dynamoDBClientFetcher.getAWSRegion(null);
    }
}
