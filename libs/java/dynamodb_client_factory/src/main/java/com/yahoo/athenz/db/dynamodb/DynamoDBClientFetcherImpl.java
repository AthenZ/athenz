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

import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.zts.AWSCredentialsProviderImplV2;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.utils.StringUtils;

import javax.net.ssl.SSLContext;

public class DynamoDBClientFetcherImpl implements DynamoDBClientFetcher {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBClientFetcherImpl.class);
    private String defaultAwsRegion;

    public DynamoDBClientFetcherImpl() {
    }

    public DynamoDBClientFetcherImpl(String defaultAwsRegion) {
        this.defaultAwsRegion = defaultAwsRegion;
    }

    @Override
    public DynamoDBClientAndCredentials getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender,
            DynamoDBClientSettings dynamoDBClientSettings) {

        // if we're given key/cert path settings then
        // we'll deal with aws temporary credentials otherwise
        // we'll assume we're running in aws thus our ec2 already
        // has credentials to access dynamodb
        if (dynamoDBClientSettings.areCredentialsProvided()) {
            LOGGER.info("DynamoDB Client will use temporary AWS credentials");
            return getAuthenticatedDynamoDBClient(dynamoDBClientSettings, ztsClientNotificationSender);
        } else {
            LOGGER.info("DynamoDB client will use existing AWS authentication");

            DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                    .region(getAWSRegion(dynamoDBClientSettings.getRegion()))
                    .build();

            DynamoDbAsyncClient dynamoDbAsyncClient = DynamoDbAsyncClient.builder()
                    .region(getAWSRegion(dynamoDBClientSettings.getRegion()))
                    .build();

            return new DynamoDBClientAndCredentials(dynamoDbClient, dynamoDbAsyncClient, null);
        }
    }

    Region getAWSRegion(final String settingRegion) {
        if (!StringUtils.isEmpty(settingRegion)) {
            return Region.of(settingRegion);
        } else if (!StringUtils.isEmpty(defaultAwsRegion)) {
            return Region.of(defaultAwsRegion);
        } else {
            DefaultAwsRegionProviderChain regionProvider = DefaultAwsRegionProviderChain.builder().build();
            return regionProvider.getRegion();
        }
    }

    private DynamoDBClientAndCredentials getAuthenticatedDynamoDBClient(DynamoDBClientSettings dynamoDBClientSettings,
            ZTSClientNotificationSender ztsClientNotificationSender) {

        SSLContext sslContext = null;
        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(
                    dynamoDBClientSettings.getTrustStore(),
                    dynamoDBClientSettings.getTrustStorePasswordChars(),
                    dynamoDBClientSettings.getCertPath(),
                    dynamoDBClientSettings.getKeyPath());
            keyRefresher.startup();

            sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());

        } catch (Exception ex) {
            LOGGER.error("Failed to get AWS Temporary credentials", ex);
        }

        AWSCredentialsProviderImplV2 credentialsProvider = null;
        String region = dynamoDBClientSettings.getRegion();

        try {
            credentialsProvider = new AWSCredentialsProviderImplV2(
                    dynamoDBClientSettings.getZtsURL(),
                    sslContext,
                    dynamoDBClientSettings.getDomainName(),
                    dynamoDBClientSettings.getRoleName(),
                    dynamoDBClientSettings.getExternalId(),
                    dynamoDBClientSettings.getMinExpiryTime(),
                    dynamoDBClientSettings.getMaxExpiryTime(),
                    ztsClientNotificationSender);
        } catch (Exception ex) {
            LOGGER.error("Failed to generate DynamoDbClient client", ex);
        }

        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.of(region))
                .build();

        DynamoDbAsyncClient dynamoDbAysncClient = DynamoDbAsyncClient.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.of(region))
                .build();

        return new DynamoDBClientAndCredentials(dynamoDbClient, dynamoDbAysncClient, credentialsProvider);
    }
}
