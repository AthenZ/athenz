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

package com.yahoo.athenz.zms.store.impl.dynamodb;

import com.yahoo.athenz.auth.PrivateKeyStore;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static com.yahoo.athenz.zms.ZMSConsts.*;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.*;

public class DynamoDBClientSettingsZmsTest {
    @Test
    public void credentialsNotProvided() {
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        DynamoDBClientSettingsZms dynamoDBClientSettingsZts = new DynamoDBClientSettingsZms(keyStore);
        assertFalse(dynamoDBClientSettingsZts.areCredentialsProvided());
    }

    @Test
    public void testCredentialsProvided() {
        System.setProperty(ZMS_PROP_DYNAMODB_KEY_PATH, "test.keypath");
        System.setProperty(ZMS_PROP_DYNAMODB_CERT_PATH, "test.certpath");
        System.setProperty(ZMS_PROP_DYNAMODB_DOMAIN, "test.domain");
        System.setProperty(ZMS_PROP_DYNAMODB_REGION, "test.region");
        System.setProperty(ZMS_PROP_DYNAMODB_ROLE, "test.role");
        System.setProperty(ZMS_PROP_DYNAMODB_TRUSTSTORE, "test.truststore");
        System.setProperty(ZMS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "test.truststore.password");
        System.setProperty(ZMS_PROP_DYNAMODB_ZTS_URL, "test.ztsurl");
        System.setProperty(ZMS_PROP_DYNAMODB_TRUSTSTORE_APPNAME, "test.appname");
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        when(keyStore.getSecret(Mockito.eq("test.appname"), Mockito.eq("test.truststore.password")))
                .thenReturn("decryptedPassword".toCharArray());

        DynamoDBClientSettingsZms dynamoDBClientSettingsZms = new DynamoDBClientSettingsZms(keyStore);
        assertTrue(dynamoDBClientSettingsZms.areCredentialsProvided());

        assertEquals("test.keypath", dynamoDBClientSettingsZms.getKeyPath());
        assertEquals("test.certpath", dynamoDBClientSettingsZms.getCertPath());
        assertEquals("test.domain", dynamoDBClientSettingsZms.getDomainName());
        assertEquals("test.region", dynamoDBClientSettingsZms.getRegion());
        assertEquals("test.role", dynamoDBClientSettingsZms.getRoleName());
        assertEquals("test.truststore", dynamoDBClientSettingsZms.getTrustStore());
        assertEquals("decryptedPassword", String.valueOf(dynamoDBClientSettingsZms.getTrustStorePasswordChars()));
        assertEquals("test.ztsurl", dynamoDBClientSettingsZms.getZtsURL());

        // Now verify that when keyStore isn't provided, trustStorePassword will be null
        dynamoDBClientSettingsZms = new DynamoDBClientSettingsZms(null);
        assertNull(dynamoDBClientSettingsZms.getTrustStorePasswordChars());

        System.clearProperty(ZMS_PROP_DYNAMODB_KEY_PATH);
        System.clearProperty(ZMS_PROP_DYNAMODB_CERT_PATH);
        System.clearProperty(ZMS_PROP_DYNAMODB_DOMAIN);
        System.clearProperty(ZMS_PROP_DYNAMODB_REGION);
        System.clearProperty(ZMS_PROP_DYNAMODB_ROLE);
        System.clearProperty(ZMS_PROP_DYNAMODB_TRUSTSTORE);
        System.clearProperty(ZMS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD);
        System.clearProperty(ZMS_PROP_DYNAMODB_ZTS_URL);
        System.clearProperty(ZMS_PROP_DYNAMODB_TRUSTSTORE_APPNAME);
    }
}