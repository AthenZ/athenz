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
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;

import static com.yahoo.athenz.zts.ZTSConsts.*;

public class DynamoDBClientFetcher {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBClientFetcher.class);

    public AmazonDynamoDB getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender, PrivateKeyStore keyStore) {
        // if we're given key/cert path settings then
        // we'll deal with aws temporary credentials otherwise
        // we'll assume we're running in aws thus our ec2 already
        // has credentials to access dynamodb
        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(keyStore);

        if (dynamoDBClientSettings.areCredentialsProvided()) {
            LOGGER.info("DynamoDB Client will use temporary AWS credentials");
            return getAuthenticatedDynamoDBClient(dynamoDBClientSettings, ztsClientNotificationSender);
        } else {
            LOGGER.info("DynamoDB client will use existing AWS authentication");
            if (dynamoDBClientSettings.getRegion().isEmpty()) {
                // Use default region
                return AmazonDynamoDBClientBuilder.standard().build();
            } else {
                return AmazonDynamoDBClientBuilder
                        .standard()
                        .withRegion(dynamoDBClientSettings.getRegion())
                        .build();
            }
        }
    }

    private AmazonDynamoDB getAuthenticatedDynamoDBClient(DynamoDBClientSettings dynamoDBClientSettings,
                                                          ZTSClientNotificationSender ztsClientNotificationSender) {
        AWSCredentialsProvider credentialsProvider = getCredentials(dynamoDBClientSettings, ztsClientNotificationSender);
        return AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(dynamoDBClientSettings.getRegion())
                .build();
    }

    private AWSCredentialsProvider getCredentials(DynamoDBClientSettings dynamoDBClientSettings,
                                                  ZTSClientNotificationSender ztsClientNotificationSender) {
        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(
                    dynamoDBClientSettings.getTrustStore(),
                    dynamoDBClientSettings.getTrustStorePassword(),
                    dynamoDBClientSettings.getCertPath(),
                    dynamoDBClientSettings.getKeyPath());
            keyRefresher.startup();

            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());

            String externalId = System.getProperty(ZTS_PROP_DYNAMODB_EXTERNAL_ID, null);
            String minExpiryTimeStr = System.getProperty(ZTS_PROP_DYNAMODB_MIN_EXPIRY_TIME, "");
            String maxExpiryTimeStr = System.getProperty(ZTS_PROP_DYNAMODB_MAX_EXPIRY_TIME, "");
            Integer minExpiryTime = minExpiryTimeStr.isEmpty() ? null : Integer.parseInt(minExpiryTimeStr);
            Integer maxExpiryTime = maxExpiryTimeStr.isEmpty() ? null : Integer.parseInt(maxExpiryTimeStr);

            return new AWSCredentialsProviderImpl(
                    dynamoDBClientSettings.getZtsURL(),
                    sslContext,
                    dynamoDBClientSettings.getDomainName(),
                    dynamoDBClientSettings.getRoleName(),
                    externalId,
                    minExpiryTime,
                    maxExpiryTime,
                    ztsClientNotificationSender);

        } catch (Exception ex) {
            LOGGER.error("Failed to get AWS Temporary credentials: {}", ex.getMessage());
        }
        return null;
    }

    public static class DynamoDBClientSettings {
        private String certPath;
        private String domainName;
        private String roleName;
        private String trustStore;
        private String trustStorePassword;
        private String ztsURL;
        private String region;
        private String keyPath;
        private String appName;
        private PrivateKeyStore keyStore;

        public DynamoDBClientSettings(PrivateKeyStore keyStore) {
            keyPath = System.getProperty(ZTS_PROP_DYNAMODB_KEY_PATH, "");
            certPath = System.getProperty(ZTS_PROP_DYNAMODB_CERT_PATH, "");
            domainName = System.getProperty(ZTS_PROP_DYNAMODB_DOMAIN, "");
            roleName = System.getProperty(ZTS_PROP_DYNAMODB_ROLE, "");
            trustStore = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE, "");
            region = System.getProperty(ZTS_PROP_DYNAMODB_REGION, "");
            trustStorePassword = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD, "");
            appName = System.getProperty(ZTS_PROP_DYNAMODB_TRUSTSTORE_APPNAME, "");
            ztsURL = System.getProperty(ZTS_PROP_DYNAMODB_ZTS_URL, "");
            this.keyStore = keyStore;
        }

        public boolean areCredentialsProvided() {
            return (!keyPath.isEmpty() &&
                    !certPath.isEmpty() &&
                    !domainName.isEmpty() &&
                    !roleName.isEmpty() &&
                    !trustStore.isEmpty() &&
                    !trustStorePassword.isEmpty() &&
                    !ztsURL.isEmpty() &&
                    !region.isEmpty() &&
                    keyStore != null);
        }

        public String getKeyPath() {
            return keyPath;
        }

        public String getCertPath() {
            return certPath;
        }

        public String getDomainName() {
            return domainName;
        }

        public String getRoleName() {
            return roleName;
        }

        public String getTrustStore() {
            return trustStore;
        }

        public String getZtsURL() {
            return ztsURL;
        }

        public String getRegion() {
            return region;
        }

        public String getTrustStorePassword() {
            if (keyStore == null) {
                return null;
            }

            return keyStore.getApplicationSecret(appName, trustStorePassword);
        }

    }
}
