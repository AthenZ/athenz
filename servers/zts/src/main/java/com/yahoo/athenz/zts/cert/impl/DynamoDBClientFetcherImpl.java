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
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.util.EC2MetadataUtils;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;

import static com.yahoo.athenz.zts.ZTSConsts.*;

public class DynamoDBClientFetcherImpl implements DynamoDBClientFetcher {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBClientFetcherImpl.class);
    private String defaultAwsRegion;

    public DynamoDBClientFetcherImpl() {
    }

    public DynamoDBClientFetcherImpl(String defaultAwsRegion) {
        this.defaultAwsRegion = defaultAwsRegion;
    }

    @Override
    public DynamoDBClientAndCredentials getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender, PrivateKeyStore keyStore) {
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
            AmazonDynamoDB client = AmazonDynamoDBClientBuilder
                    .standard()
                    .withRegion(getAWSRegion(dynamoDBClientSettings.getRegion()))
                    .build();
            return new DynamoDBClientAndCredentials(client, null);
        }
    }

    String getAWSRegion(final String settingRegion) {
        if (StringUtil.isEmpty(settingRegion)) {
            if (defaultAwsRegion == null) {
                defaultAwsRegion = EC2MetadataUtils.getEC2InstanceRegion();
            }
            return defaultAwsRegion;
        } else {
            return settingRegion;
        }
    }

    private DynamoDBClientAndCredentials getAuthenticatedDynamoDBClient(DynamoDBClientSettings dynamoDBClientSettings,
                                                          ZTSClientNotificationSender ztsClientNotificationSender) {
        AWSCredentialsProviderImpl credentialsProvider = getCredentials(dynamoDBClientSettings, ztsClientNotificationSender);
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(dynamoDBClientSettings.getRegion())
                .build();
        return new DynamoDBClientAndCredentials(client, credentialsProvider);
    }

    private AWSCredentialsProviderImpl getCredentials(DynamoDBClientSettings dynamoDBClientSettings,
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
}
