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

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientAndCredentials;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcher;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcherFactory;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientSettings;
import com.yahoo.athenz.syncer.auth.history.AuthHistorySender;
import com.yahoo.athenz.syncer.auth.history.AuthHistorySenderFactory;

import static com.yahoo.athenz.syncer.auth.history.AuthHistorySyncerConsts.*;

public class DynamoDBAuthHistorySenderFactory implements AuthHistorySenderFactory {
    @Override
    public AuthHistorySender create(PrivateKeyStore pkeyStore, String region) {
        try {
            DynamoDBClientFetcher dynamoDBClientFetcher = DynamoDBClientFetcherFactory.getDynamoDBClientFetcher();
            DynamoDBClientSettings clientSettings = getClientSettings(pkeyStore);
            DynamoDBClientAndCredentials dynamoDBClient = dynamoDBClientFetcher.getDynamoDBClient(null, clientSettings);
            return new DynamoDBAuthHistorySender(dynamoDBClient.getAmazonDynamoAsyncDB());
        } catch (InterruptedException e) {
            throw new RuntimeException("Failed to instantiate AuthHistorySender: ", e);
        }
    }

    private DynamoDBClientSettings getClientSettings(PrivateKeyStore pkeyStore) {
        String keyPath = System.getProperty(PROP_DYNAMODB_KEY_PATH, "");
        String certPath = System.getProperty(PROP_DYNAMODB_CERT_PATH, "");
        String domainName = System.getProperty(PROP_DYNAMODB_DOMAIN, "");
        String roleName = System.getProperty(PROP_DYNAMODB_ROLE, "");
        String trustStore = System.getProperty(PROP_DYNAMODB_TRUSTSTORE, "");
        String trustStorePassword = System.getProperty(PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "");
        String region = System.getProperty(PROP_DYNAMODB_REGION, "");
        String appName = System.getProperty(PROP_DYNAMODB_TRUSTSTORE_APPNAME, "");
        String ztsURL = System.getProperty(PROP_DYNAMODB_ZTS_URL, "");
        String externalId = System.getProperty(PROP_DYNAMODB_EXTERNAL_ID, null);
        String minExpiryTimeStr = System.getProperty(PROP_DYNAMODB_MIN_EXPIRY_TIME, "");
        String maxExpiryTimeStr = System.getProperty(PROP_DYNAMODB_MAX_EXPIRY_TIME, "");
        Integer minExpiryTime = minExpiryTimeStr.isEmpty() ? null : Integer.parseInt(minExpiryTimeStr);
        Integer maxExpiryTime = maxExpiryTimeStr.isEmpty() ? null : Integer.parseInt(maxExpiryTimeStr);

        return new DynamoDBClientSettings(certPath, domainName, roleName, trustStore, trustStorePassword, ztsURL, region, keyPath, appName, pkeyStore, externalId, minExpiryTime, maxExpiryTime);
    }
}
