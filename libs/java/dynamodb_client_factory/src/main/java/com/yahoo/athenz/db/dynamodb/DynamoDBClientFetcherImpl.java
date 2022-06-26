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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.util.EC2MetadataUtils;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;
import com.yahoo.athenz.zts.AWSCredentialsProviderImplV2;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
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
    @Deprecated
    public DynamoDBClientAndCredentials getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender, PrivateKeyStore keyStore) {
        String keyPath = System.getProperty("athenz.zts.dynamodb_key_path", "");
        String certPath = System.getProperty("athenz.zts.dynamodb_cert_path", "");
        String domainName = System.getProperty("athenz.zts.dynamodb_aws_domain", "");
        String roleName = System.getProperty("athenz.zts.dynamodb_aws_role", "");
        String trustStore = System.getProperty("athenz.zts.dynamodb_trust_store_path", "");
        String region = System.getProperty("athenz.zts.dynamodb_region", "");
        String trustStorePassword = System.getProperty("athenz.zts.dynamodb_trust_store_password", "");
        String appName = System.getProperty("athenz.zts.dynamodb_trust_store_app_name", "");
        String ztsURL = System.getProperty("athenz.zts.dynamodb_zts_url", "");
        String externalId = System.getProperty("athenz.zts.dynamodb_external_id", null);
        String minExpiryTimeStr = System.getProperty("athenz.zts.dynamodb_min_expiry_time", "");
        String maxExpiryTimeStr = System.getProperty("athenz.zts.dynamodb_max_expiry_time", "");
        Integer minExpiryTime = minExpiryTimeStr.isEmpty() ? null : Integer.parseInt(minExpiryTimeStr);
        Integer maxExpiryTime = maxExpiryTimeStr.isEmpty() ? null : Integer.parseInt(maxExpiryTimeStr);

        DynamoDBClientSettings dynamoDBClientSettings = new DynamoDBClientSettings(certPath, domainName, roleName, trustStore, trustStorePassword, ztsURL, region, keyPath, appName, keyStore, externalId, minExpiryTime, maxExpiryTime);
        return getDynamoDBClient(ztsClientNotificationSender, dynamoDBClientSettings);
    }

    @Override
    public DynamoDBClientAndCredentials getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender, DynamoDBClientSettings dynamoDBClientSettings) {
        // if we're given key/cert path settings then
        // we'll deal with aws temporary credentials otherwise
        // we'll assume we're running in aws thus our ec2 already
        // has credentials to access dynamodb
        if (dynamoDBClientSettings.areCredentialsProvided()) {
            LOGGER.info("DynamoDB Client will use temporary AWS credentials");
            return getAuthenticatedDynamoDBClient(dynamoDBClientSettings, ztsClientNotificationSender);
        } else {
            LOGGER.info("DynamoDB client will use existing AWS authentication");
            String region = getAWSRegion(dynamoDBClientSettings.getRegion());
            AmazonDynamoDB client = AmazonDynamoDBClientBuilder
                    .standard()
                    .withRegion(region)
                    .build();

            DynamoDbAsyncClient asyncClient = DynamoDbAsyncClient.builder()
                    .region(Region.of(region))
                    .build();

            return new DynamoDBClientAndCredentials(client, asyncClient, null);
        }
    }

    String getAWSRegion(final String settingRegion) {
        if (StringUtils.isEmpty(settingRegion)) {
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

        AWSCredentialsProviderImpl credentialsProvider = null;
        String region = dynamoDBClientSettings.getRegion();
        try {
            credentialsProvider = new AWSCredentialsProviderImpl(
                    dynamoDBClientSettings.getZtsURL(),
                    sslContext,
                    dynamoDBClientSettings.getDomainName(),
                    dynamoDBClientSettings.getRoleName(),
                    dynamoDBClientSettings.getExternalId(),
                    dynamoDBClientSettings.getMinExpiryTime(),
                    dynamoDBClientSettings.getMaxExpiryTime(),
                    ztsClientNotificationSender);

        } catch (Exception ex) {
            LOGGER.error("Failed to generate AmazonDynamoDB client", ex);
        }
        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion(region)
                .build();


        AWSCredentialsProviderImplV2 credentialsProviderV2 = null;
        try {
            credentialsProviderV2 = new AWSCredentialsProviderImplV2(
                    dynamoDBClientSettings.getZtsURL(),
                    sslContext,
                    dynamoDBClientSettings.getDomainName(),
                    dynamoDBClientSettings.getRoleName(),
                    dynamoDBClientSettings.getExternalId(),
                    dynamoDBClientSettings.getMinExpiryTime(),
                    dynamoDBClientSettings.getMaxExpiryTime(),
                    ztsClientNotificationSender);
        } catch (Exception ex) {
            LOGGER.error("Failed to generate DynamoDbAsyncClient client", ex);
        }
        DynamoDbAsyncClient asyncClient = DynamoDbAsyncClient.builder()
                .credentialsProvider(credentialsProviderV2)
                .region(Region.of(region))
                .build();

        return new DynamoDBClientAndCredentials(client, asyncClient, credentialsProvider);
    }
}
