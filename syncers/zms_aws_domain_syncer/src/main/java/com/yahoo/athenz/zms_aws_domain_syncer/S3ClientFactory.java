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

package com.yahoo.athenz.zms_aws_domain_syncer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.time.Duration;

public class S3ClientFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3ClientFactory.class);

    private static final int DEFAULT_CONN_TIMEOUT = 10000;
    private static final int DEFAULT_REQ_TIMEOUT = 20000;

    public static S3Client getS3Client() throws Exception {
        // load up credentials
        // use the system props if set for aws key id and secret, else use zts client
        final String bucket = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET);
        if (Config.isEmpty(bucket)) {
            final String errMsg = "required bucket name not configured";
            LOGGER.error(errMsg);
            throw new Exception(errMsg);
        }
        long connectionTimeout = DEFAULT_CONN_TIMEOUT;
        long requestTimeout = DEFAULT_REQ_TIMEOUT;

        final String connTimeout = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT);
        if (!Config.isEmpty(connTimeout)) {
            try {
                connectionTimeout = Long.parseLong(connTimeout);
                LOGGER.debug("using connection timeout: {}", connectionTimeout);
            } catch (Exception exc) {
                LOGGER.error("ignore connection timeout parameter: {}, bad value: {}",
                        Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT, connTimeout);
            }
        }

        final String reqTimeout = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT);
        if (!Config.isEmpty(reqTimeout)) {
            try {
                requestTimeout = Long.parseLong(reqTimeout);
                LOGGER.debug("using request timeout: {}", requestTimeout);
            } catch (Exception exc) {
                LOGGER.error("ignore request timeout parameter: {}, bad value: {}",
                        Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT, reqTimeout);
            }
        }

        SdkHttpClient apacheHttpClient = ApacheHttpClient.builder()
                .connectionTimeout(Duration.ofMillis(connectionTimeout))
                .socketTimeout(Duration.ofMillis(requestTimeout))
                .build();

        S3Client s3client;
        final String awsKeyId = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_KEY_ID);
        final String awsAccKey = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        if (!Config.isEmpty(awsKeyId) && !Config.isEmpty(awsAccKey)) {
            AwsBasicCredentials awsCreds = AwsBasicCredentials.builder()
                    .accessKeyId(awsKeyId).secretAccessKey(awsAccKey).build();
            StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(awsCreds);

            s3client = S3Client.builder()
                    .credentialsProvider(credentialsProvider)
                    .httpClient(apacheHttpClient)
                    .region(getRegion())
                    .build();
        } else {
            s3client = S3Client.builder()
                    .httpClient(apacheHttpClient)
                    .region(getRegion())
                    .build();
        }

        verifyBucketExist(s3client, bucket);

        LOGGER.debug("success: using bucket: {}", bucket);
        return s3client;
    }

    public static Region getRegion() {

        final String awsRegion = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_S3_REGION);
        if (awsRegion != null && !awsRegion.isEmpty()) {
            return Region.of(awsRegion);
        }
        try {
            DefaultAwsRegionProviderChain regionProvider = DefaultAwsRegionProviderChain.builder().build();
            return regionProvider.getRegion();
        } catch (Exception ex) {
            LOGGER.error("Unable to determine AWS region", ex);
        }
        return Region.US_WEST_2;
    }

    public static void verifyBucketExist(S3Client s3Client, String bucketName) {
        try {
            HeadBucketRequest request = HeadBucketRequest.builder()
                    .bucket(bucketName)
                    .build();
            s3Client.headBucket(request);
        } catch (Exception ex) {
            String errMsg = "bucket: " + bucketName + " : does not exist in S3";
            LOGGER.error(errMsg, ex);
            throw ex;
        }
    }
}
