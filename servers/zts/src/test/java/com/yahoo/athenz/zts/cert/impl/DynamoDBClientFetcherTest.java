/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static com.yahoo.athenz.zts.ZTSConsts.*;
import static com.yahoo.athenz.zts.ZTSConsts.ZTS_PROP_DYNAMODB_ZTS_URL;
import static org.testng.AssertJUnit.assertNotNull;

public class DynamoDBClientFetcherTest {

    @Test
    public void testGetClientWithRegion() {
        System.setProperty(ZTS_PROP_DYNAMODB_REGION, "test.region");
        DynamoDBClientFetcher dynamoDBClientFetcher = new DynamoDBClientFetcher();
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        AmazonDynamoDB dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore);
        assertNotNull(dynamoDBClient);
        System.clearProperty(ZTS_PROP_DYNAMODB_REGION);
    }

    @Test
    public void testGetAuthenticatedClient() {
        System.setProperty(ZTS_PROP_DYNAMODB_KEY_PATH, "test.keypath");
        System.setProperty(ZTS_PROP_DYNAMODB_CERT_PATH, "test.certpath");
        System.setProperty(ZTS_PROP_DYNAMODB_DOMAIN, "test.domain");
        System.setProperty(ZTS_PROP_DYNAMODB_REGION, "test.region");
        System.setProperty(ZTS_PROP_DYNAMODB_ROLE, "test.role");
        System.setProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE, "test.truststore");
        System.setProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "test.truststore.password");
        System.setProperty(ZTS_PROP_DYNAMODB_ZTS_URL, "test.ztsurl");

        DynamoDBClientFetcher dynamoDBClientFetcher = new DynamoDBClientFetcher();
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ZTSClientNotificationSender ztsClientNotificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        AmazonDynamoDB dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, keyStore);
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
}
