/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.athenz.syncer.aws.common.impl;

import com.yahoo.athenz.auth.util.Crypto;
import io.athenz.syncer.common.zms.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.checksums.ResponseChecksumValidation;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;

import javax.net.ssl.TrustManagerFactory;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
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

        ApacheHttpClient.Builder httpClientBuilder = ApacheHttpClient.builder()
                .connectionTimeout(Duration.ofMillis(connectionTimeout))
                .socketTimeout(Duration.ofMillis(requestTimeout));

        final String caCertPath = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_S3_CA_CERT);
        if (!Config.isEmpty(caCertPath)) {
            X509Certificate[] certs = Crypto.loadX509Certificates(caCertPath);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null); // Initialize empty keystore
            int i = 0;
            for (X509Certificate cert : certs) {
                keyStore.setCertificateEntry("custom-ca-" + i++, cert);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            httpClientBuilder.tlsTrustManagersProvider(tmf::getTrustManagers);
        }

        SdkHttpClient apacheHttpClient = httpClientBuilder.build();

        S3ClientBuilder s3ClientBuilder = S3Client.builder()
                .httpClient(apacheHttpClient)
                .region(getRegion());

        // Enable checksum calculation and validation if configured
        final String checksumValidation = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_S3_CHECKSUM_VALIDATION);
        if (!Config.isEmpty(checksumValidation) && Boolean.parseBoolean(checksumValidation)) {
            s3ClientBuilder
                    .requestChecksumCalculation(RequestChecksumCalculation.WHEN_REQUIRED)
                    .responseChecksumValidation(ResponseChecksumValidation.WHEN_REQUIRED);
            LOGGER.debug("S3 checksum calculation and validation enabled");
        }

        final String awsS3Endpoint = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_S3_ENDPOINT);
        if (!Config.isEmpty(awsS3Endpoint)) {
            s3ClientBuilder.endpointOverride(URI.create(awsS3Endpoint));
        }

        final String awsKeyId = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_KEY_ID);
        final String awsAccKey = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        if (!Config.isEmpty(awsKeyId) && !Config.isEmpty(awsAccKey)) {
            AwsBasicCredentials awsCreds = AwsBasicCredentials.builder()
                    .accessKeyId(awsKeyId).secretAccessKey(awsAccKey).build();
            StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(awsCreds);
            s3ClientBuilder.credentialsProvider(credentialsProvider);
        }

        S3Client s3client = s3ClientBuilder.build();

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
