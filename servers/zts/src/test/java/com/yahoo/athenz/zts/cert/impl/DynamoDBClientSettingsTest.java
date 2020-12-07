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

import com.yahoo.athenz.auth.PrivateKeyStore;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static com.yahoo.athenz.zts.ZTSConsts.*;
import static org.mockito.Mockito.when;

import static org.testng.AssertJUnit.*;

public class DynamoDBClientSettingsTest {
    @Test
    public void credentialsNotProvided() {
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(keyStore);
        assertFalse(dynamoDBClientSettings.areCredentialsProvided());
    }

    @Test
    public void testCredentialsProvided() {
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

        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(keyStore);
        assertTrue(dynamoDBClientSettings.areCredentialsProvided());

        assertEquals("test.keypath", dynamoDBClientSettings.getKeyPath());
        assertEquals("test.certpath", dynamoDBClientSettings.getCertPath());
        assertEquals("test.domain", dynamoDBClientSettings.getDomainName());
        assertEquals("test.region", dynamoDBClientSettings.getRegion());
        assertEquals("test.role", dynamoDBClientSettings.getRoleName());
        assertEquals("test.truststore", dynamoDBClientSettings.getTrustStore());
        assertEquals("decryptedPassword", dynamoDBClientSettings.getTrustStorePassword());
        assertEquals("test.ztsurl", dynamoDBClientSettings.getZtsURL());

        // Now verify that when keyStore isn't provided, trustStorePassword will be null
        dynamoDBClientSettings = new DynamoDBClientSettings(null);
        assertNull(dynamoDBClientSettings.getTrustStorePassword());

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