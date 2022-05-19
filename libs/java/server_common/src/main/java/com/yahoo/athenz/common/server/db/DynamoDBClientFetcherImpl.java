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

package com.yahoo.athenz.common.server.db;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.util.EC2MetadataUtils;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;
import com.yahoo.athenz.zts.AWSCredentialsProviderImplV2;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import javax.net.ssl.SSLContext;

public class DynamoDBClientFetcherImpl implements DynamoDBClientFetcher {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBClientFetcherImpl.class);
    private String defaultAwsRegion;
    private DynamoDBClientSettingsFactory dynamoDBClientSettingsFactory;

    public DynamoDBClientFetcherImpl(DynamoDBClientSettingsFactory dynamoDBClientSettingsFactory) {
        this.dynamoDBClientSettingsFactory = dynamoDBClientSettingsFactory;
    }

    public DynamoDBClientFetcherImpl(String defaultAwsRegion, DynamoDBClientSettingsFactory dynamoDBClientSettingsFactory) {
        this.defaultAwsRegion = defaultAwsRegion;
        this.dynamoDBClientSettingsFactory = dynamoDBClientSettingsFactory;
    }

    @Override
    public DynamoDBClientAndCredentials getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender, PrivateKeyStore keyStore) {
        // if we're given key/cert path settings then
        // we'll deal with aws temporary credentials otherwise
        // we'll assume we're running in aws thus our ec2 already
        // has credentials to access dynamodb
        DynamoDBClientSettings dynamoDBClientSettings = dynamoDBClientSettingsFactory.create(keyStore);

        if (dynamoDBClientSettings.areCredentialsProvided()) {
            LOGGER.info("DynamoDB Client will use temporary AWS credentials");
            return getAuthenticatedDynamoDBClient(dynamoDBClientSettings, ztsClientNotificationSender);
        } else {
            LOGGER.info("DynamoDB client will use existing AWS authentication");
            AmazonDynamoDB client = AmazonDynamoDBClientBuilder
                    .standard()
                    .withRegion(getAWSRegion(dynamoDBClientSettings.getRegion()))
                    .build();

            DynamoDbClient dynamoDB = DynamoDbClient.builder()
                    .region(Region.of(getAWSRegion(dynamoDBClientSettings.getRegion())))
                    .build();
            DynamoDbEnhancedClient dynamoDbEnhancedClient = DynamoDbEnhancedClient.builder()
                    .dynamoDbClient(dynamoDB)
                    .build();
            return new DynamoDBClientAndCredentials(client, null, dynamoDbEnhancedClient, null);
        }
    }

    public String getAWSRegion(final String settingRegion) {
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

        AWSCredentialsProviderImpl credentialsProvider = null;
        AWSCredentialsProviderImplV2 credentialsProviderImplV2 = null;
        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(
                    dynamoDBClientSettings.getTrustStore(),
                    dynamoDBClientSettings.getTrustStorePasswordChars(),
                    dynamoDBClientSettings.getCertPath(),
                    dynamoDBClientSettings.getKeyPath());
            keyRefresher.startup();

            final SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());

            final String externalId = dynamoDBClientSettings.getExternalId();
            final String minExpiryTimeStr = dynamoDBClientSettings.getMinExpiryTimeStr();
            final String maxExpiryTimeStr = dynamoDBClientSettings.getMaxExpiryTimeStr();
            final Integer minExpiryTime = minExpiryTimeStr.isEmpty() ? null : Integer.parseInt(minExpiryTimeStr);
            final Integer maxExpiryTime = maxExpiryTimeStr.isEmpty() ? null : Integer.parseInt(maxExpiryTimeStr);

            credentialsProvider = new AWSCredentialsProviderImpl(
                    dynamoDBClientSettings.getZtsURL(),
                    sslContext,
                    dynamoDBClientSettings.getDomainName(),
                    dynamoDBClientSettings.getRoleName(),
                    StringUtil.isEmpty(externalId) ? null : externalId,
                    minExpiryTime,
                    maxExpiryTime,
                    ztsClientNotificationSender);

            credentialsProviderImplV2 = new AWSCredentialsProviderImplV2(
                    dynamoDBClientSettings.getZtsURL(),
                    sslContext,
                    dynamoDBClientSettings.getDomainName(),
                    dynamoDBClientSettings.getRoleName(),
                    StringUtil.isEmpty(externalId) ? null : externalId,
                    minExpiryTime,
                    maxExpiryTime,
                    ztsClientNotificationSender);
        } catch (Exception ex) {
            LOGGER.error("Failed to get AWS Temporary credentials: {}", ex.getMessage());

        }

        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(dynamoDBClientSettings.getRegion())
                .build();

        DynamoDbClient dynamoDB = DynamoDbClient.builder()
                .credentialsProvider(credentialsProviderImplV2)
                .region(Region.of(getAWSRegion(dynamoDBClientSettings.getRegion())))
                .build();
        DynamoDbEnhancedClient dynamoDbEnhancedClient = DynamoDbEnhancedClient.builder()
                .dynamoDbClient(dynamoDB)
                .build();

        return new DynamoDBClientAndCredentials(client, credentialsProvider, dynamoDbEnhancedClient, credentialsProviderImplV2);
    }
}
