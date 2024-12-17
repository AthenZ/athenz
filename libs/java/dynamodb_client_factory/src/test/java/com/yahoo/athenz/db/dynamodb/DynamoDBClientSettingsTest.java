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

import com.yahoo.athenz.auth.PrivateKeyStore;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.mockito.Mockito.when;

import static org.testng.Assert.*;

public class DynamoDBClientSettingsTest {
    @Test
    public void credentialsNotProvided() {
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(null, null, null, null,
                null, null, null, null, null, keyStore, null, null, null, null, false);
        assertFalse(dynamoDBClientSettings.areCredentialsProvided());
    }

    @Test
    public void testCredentialsProvided() {
        String keyPath = "test.keypath";
        String certPath = "test.certpath";
        String domain = "test.domain";
        String region = "test.region";
        String role = "test.role";
        String trustStore = "test.truststore";
        String trustStorePassword = "test.truststore.password";
        String ztsUrl = "test.ztsurl";
        String appName = "test.appname";

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        when(keyStore.getSecret(Mockito.eq("test.appname"), Mockito.eq(null), Mockito.eq("test.truststore.password")))
                .thenReturn("decryptedPassword".toCharArray());

        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(certPath, domain, role,
                trustStore, trustStorePassword, ztsUrl, region, keyPath, appName, keyStore, null, null,
                null, null, false);
        assertTrue(dynamoDBClientSettings.areCredentialsProvided());

        assertEquals(dynamoDBClientSettings.getKeyPath(), "test.keypath");
        assertEquals(dynamoDBClientSettings.getCertPath(), "test.certpath");
        assertEquals(dynamoDBClientSettings.getDomainName(), "test.domain");
        assertEquals(dynamoDBClientSettings.getRegion(), "test.region");
        assertEquals(dynamoDBClientSettings.getRoleName(), "test.role");
        assertEquals(dynamoDBClientSettings.getTrustStore(), "test.truststore");
        assertEquals(String.valueOf(dynamoDBClientSettings.getTrustStorePasswordChars()), "decryptedPassword");
        assertEquals(dynamoDBClientSettings.getZtsURL(), "test.ztsurl");

        // Now verify that when keyStore isn't provided, trustStorePassword will be null
        dynamoDBClientSettings = new DynamoDBClientSettings(certPath, domain, role, trustStore,
                trustStorePassword, ztsUrl, region, keyPath, appName, null, null, null, null, null, false);
        assertNull(dynamoDBClientSettings.getTrustStorePasswordChars());
    }
}