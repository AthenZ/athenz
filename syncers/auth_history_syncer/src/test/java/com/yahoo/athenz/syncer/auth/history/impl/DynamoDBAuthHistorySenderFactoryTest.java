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

package com.yahoo.athenz.syncer.auth.history.impl;

import com.amazonaws.SdkClientException;
import com.google.common.io.Resources;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.syncer.auth.history.AuthHistorySender;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static com.yahoo.athenz.syncer.auth.history.AuthHistorySyncerConsts.*;
import static org.testng.AssertJUnit.*;

public class DynamoDBAuthHistorySenderFactoryTest {

    @Test
    public void testCreate() {
        String certPath = Resources.getResource("impl/gdpr.aws.core.cert.pem").getPath();//public
        String keyPath = Resources.getResource("impl/gdpr.aws.core.key.pem").getPath();//private

        System.setProperty(PROP_DYNAMODB_KEY_PATH, keyPath);
        System.setProperty(PROP_DYNAMODB_CERT_PATH, certPath);
        System.setProperty(PROP_DYNAMODB_DOMAIN, "test.domain");
        System.setProperty(PROP_DYNAMODB_REGION, "test.region");
        System.setProperty(PROP_DYNAMODB_ROLE, "test.role");
        System.setProperty(PROP_DYNAMODB_TRUSTSTORE, "test.truststore");
        System.setProperty(PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "test.truststore.password");
        System.setProperty(PROP_DYNAMODB_ZTS_URL, "https://dev.zts.athenzcompany.com:4443/zts/v1");

        DynamoDBAuthHistorySenderFactory dynamoDBAuthHistorySenderFactory = new DynamoDBAuthHistorySenderFactory();
        PrivateKeyStore pkeyStore = Mockito.mock(PrivateKeyStore.class);
        AuthHistorySender authHistorySender = dynamoDBAuthHistorySenderFactory.create(pkeyStore, "us-west-2");
        assertNotNull(authHistorySender);

        System.clearProperty(PROP_DYNAMODB_KEY_PATH);
        System.clearProperty(PROP_DYNAMODB_CERT_PATH);
        System.clearProperty(PROP_DYNAMODB_DOMAIN);
        System.clearProperty(PROP_DYNAMODB_REGION);
        System.clearProperty(PROP_DYNAMODB_ROLE);
        System.clearProperty(PROP_DYNAMODB_TRUSTSTORE);
        System.clearProperty(PROP_DYNAMODB_TRUSTSTORE_PASSWORD);
        System.clearProperty(PROP_DYNAMODB_ZTS_URL);
    }

    @Test
    public void testCreateFailRegion() {
        try {
            DynamoDBAuthHistorySenderFactory dynamoDBAuthHistorySenderFactory = new DynamoDBAuthHistorySenderFactory();
            PrivateKeyStore pkeyStore = Mockito.mock(PrivateKeyStore.class);
            dynamoDBAuthHistorySenderFactory.create(pkeyStore, "us-west-2");
            fail();
        } catch (SdkClientException ex) {
            assertEquals("Could not find region information for 'null' in SDK metadata.", ex.getMessage());
        }
    }

    @Test
    public void testCreateSpecifiedRegion() {
        System.setProperty(PROP_DYNAMODB_REGION, "test.region");
        DynamoDBAuthHistorySenderFactory dynamoDBAuthHistorySenderFactory = new DynamoDBAuthHistorySenderFactory();
        PrivateKeyStore pkeyStore = Mockito.mock(PrivateKeyStore.class);
        AuthHistorySender authHistorySender = dynamoDBAuthHistorySenderFactory.create(pkeyStore, "us-west-2");
        assertNotNull(authHistorySender);
        System.clearProperty(PROP_DYNAMODB_REGION);
    }
}
