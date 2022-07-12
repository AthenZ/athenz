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

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class S3ClientFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3ClientFactory.class);

    private static final int DEFAULT_CONN_TIMEOUT = 10000;
    private static final int DEFAULT_REQ_TIMEOUT = 20000;

    public static AmazonS3 getS3Client() throws Exception {
        // load up credentials
        // use the system props if set for aws key id and secret, else use zts client
        final String bucket = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET);
        if (Config.isEmpty(bucket)) {
            final String errMsg = "required bucket name not configured";
            LOGGER.error(errMsg);
            throw new Exception(errMsg);
        }
        ClientConfiguration cltConf = new ClientConfiguration();
        cltConf.setConnectionTimeout(DEFAULT_CONN_TIMEOUT);
        cltConf.setRequestTimeout(DEFAULT_REQ_TIMEOUT);

        final String connTimeout = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT);
        if (!Config.isEmpty(connTimeout)) {
            try {
                int connectionTimeout = Integer.parseInt(connTimeout);
                cltConf.setConnectionTimeout(connectionTimeout);
                LOGGER.debug("using connection timeout: {}", connectionTimeout);
            } catch (Exception exc) {
                LOGGER.error("ignore connection timeout parameter: {}, bad value: {}",
                        Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT, connTimeout);
            }
        }

        final String reqTimeout = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT);
        if (!Config.isEmpty(reqTimeout)) {
            try {
                int requestTimeout = Integer.parseInt(reqTimeout);
                cltConf.setRequestTimeout(requestTimeout);
                LOGGER.debug("using request timeout: {}", requestTimeout);
            } catch (Exception exc) {
                LOGGER.error("ignore request timeout parameter: {}, bad value: {}",
                        Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT, reqTimeout);
            }
        }

        AmazonS3 s3client;
        final String awsKeyId = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_KEY_ID);
        final String awsAccKey = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        if (!Config.isEmpty(awsKeyId) && !Config.isEmpty(awsAccKey)) {
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(awsKeyId, awsAccKey);
            s3client = AmazonS3ClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                    .withClientConfiguration(cltConf)
                    .withRegion(getRegion())
                    .build();
        } else {
            s3client = AmazonS3ClientBuilder.standard()
                    .withCredentials(new InstanceProfileCredentialsProvider(false))
                    .withClientConfiguration(cltConf)
                    .build();
        }

        if (!s3client.doesBucketExistV2(bucket)) {
            String errMsg = "bucket: " + bucket + " : does not exist in S3";
            LOGGER.error(errMsg);
            throw new Exception(errMsg);
        }

        LOGGER.debug("success: using bucket: {}", bucket);
        return s3client;
    }

    private static Regions getRegion() {

        final String awsRegion = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_S3_REGION);
        Regions region;
        if (Config.isEmpty(awsRegion)) {
            region = Regions.US_WEST_2;
            LOGGER.info("default to aws region: US_WEST_2");
        } else {
            region = Regions.fromName(awsRegion);
            LOGGER.info("using aws region: {}", awsRegion);
        }
        return region;
    }
}
