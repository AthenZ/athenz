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

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;

import static com.yahoo.athenz.zts.ZTSConsts.*;

public class DynamoDBClientFetcher {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBClientFetcher.class);

    public AmazonDynamoDB getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender) {
        // if we're given key/cert path settings then
        // we'll deal with aws temporary credentials otherwise
        // we'll assume we're running in aws thus our ec2 already
        // has credentials to access dynamodb
        final String keyPath = System.getProperty(ZTS_PROP_DYNAMODB_KEY_PATH, "");
        final String certPath = System.getProperty(ZTS_PROP_DYNAMODB_CERT_PATH, "");
        final String dynamoDBDomain = System.getProperty(ZTS_PROP_DYNAMODB_DOMAIN, "");
        final String dynamoDBRole = System.getProperty(ZTS_PROP_DYNAMODB_ROLE, "");
        final String dynamoDBTrustStore = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE, "");
        final String dynamoDBRegion = System.getProperty(ZTS_PROP_DYNAMODB_REGION, "");
        final String dynamoDBTrustStorePassword = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "");
        final String ztsURL = System.getProperty(ZTS_PROP_DYNAMODB_ZTS_URL, "");

        if (!keyPath.isEmpty() &&
                !certPath.isEmpty() &&
                !dynamoDBDomain.isEmpty() &&
                !dynamoDBRole.isEmpty() &&
                !dynamoDBTrustStore.isEmpty() &&
                !dynamoDBTrustStorePassword.isEmpty() &&
                !ztsURL.isEmpty() &&
                !dynamoDBRegion.isEmpty()) {
            return getAuthenticatedDynamoDBClient(
                    keyPath,
                    certPath,
                    dynamoDBDomain,
                    dynamoDBRole,
                    dynamoDBTrustStore,
                    dynamoDBTrustStorePassword,
                    ztsURL,
                    dynamoDBRegion,
                    ztsClientNotificationSender);
        } else {
            if (dynamoDBRegion.isEmpty()) {
                return AmazonDynamoDBClientBuilder.standard().build();
            } else {
                return AmazonDynamoDBClientBuilder.standard().withRegion(dynamoDBRegion).build();
            }
        }
    }

    public static AmazonDynamoDB getAuthenticatedDynamoDBClient(String keyPath,
                                                                String certPath,
                                                                String domainName,
                                                                String role,
                                                                String dynamoDBTrustStore,
                                                                String dynamoDBTrustStorePassword,
                                                                String ztsURL,
                                                                String dynamoDBRegion,
                                                                ZTSClientNotificationSender ztsClientNotificationSender) {
        AWSCredentialsProvider credentialsProvider = getCredentials(
                keyPath,
                certPath,
                domainName,
                role,
                dynamoDBTrustStore,
                dynamoDBTrustStorePassword,
                ztsURL,
                ztsClientNotificationSender);
        return AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(dynamoDBRegion)
                .build();
    }

    private static AWSCredentialsProvider getCredentials(String keyPath,
                                                         String certPath,
                                                         String domainName,
                                                         String roleName,
                                                         String dynamoDBTrustStore,
                                                         String dynamoDBTrustStorePassword,
                                                         String ztsURL,
                                                         ZTSClientNotificationSender ztsClientNotificationSender) {
        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(dynamoDBTrustStore, dynamoDBTrustStorePassword, certPath, keyPath);
            keyRefresher.startup();

            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());

            return new AWSCredentialsProviderImpl(ztsURL,
                    sslContext, domainName, roleName, null, null, null, ztsClientNotificationSender);

        } catch (Exception ex) {
            LOGGER.error("Failed to get AWS Temporary credentials: {}", ex.getMessage());
        }
        return null;
    }
}
