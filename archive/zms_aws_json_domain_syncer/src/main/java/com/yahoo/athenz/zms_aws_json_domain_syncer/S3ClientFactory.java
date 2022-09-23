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
package com.yahoo.athenz.zms_aws_json_domain_syncer;

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
    private static final int DEFAULT_CONN_TIMEOUT = 10000;
    private static final int DEFAULT_REQ_TIMEOUT = 20000;

    private static final Logger LOGGER = LoggerFactory.getLogger(S3ClientFactory.class);

    public static AmazonS3 getS3Client() throws Exception {
        // load up credentials
        // use the system props if set for aws keyid and secret, else use zts client
        final String bucket = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWSBUCK);
        if (bucket == null || bucket.isEmpty()) {
            String errMsg = "S3ClientFactory: error: bucket required";
            LOGGER.error(errMsg);
            throw new Exception(errMsg);
        }
        ClientConfiguration cltConf = new ClientConfiguration();
        cltConf.setConnectionTimeout(DEFAULT_CONN_TIMEOUT);
        cltConf.setRequestTimeout(DEFAULT_REQ_TIMEOUT);

        String connTimeout = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWSCONTO);
        if (connTimeout != null) {
            try {
                int connectionTimeout = Integer.parseInt(connTimeout);
                cltConf.setConnectionTimeout(connectionTimeout);
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("S3ClientFactory: using connection timeout: " + connectionTimeout);
                }
            } catch (Exception exc) {
                LOGGER.warn("S3ClientFactory: ignore connection timeout parameter: " +
                        Config.SYNC_CFG_PARAM_AWSCONTO + " : bad value: " + connTimeout);
            }
        }

        String reqTimeout = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWSREQTO);
        if (reqTimeout != null) {
            try {
                int requestTimeout = Integer.parseInt(reqTimeout);
                cltConf.setRequestTimeout(requestTimeout);
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("S3ClientFactory: using request timeout: " + requestTimeout);
                }
            } catch (Exception exc) {
                LOGGER.warn("S3ClientFactory: ignore request timeout parameter: " +
                        Config.SYNC_CFG_PARAM_AWSREQTO + " : bad value: " + reqTimeout);
            }
        }

        AmazonS3 s3client = null;
        final String awsKeyId = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWSKEYID);
        final String awsAccKey = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWSACCKEY);
        if (awsKeyId != null && !awsKeyId.isEmpty() && awsAccKey != null && !awsAccKey.isEmpty()) {
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

        if (!s3client.doesBucketExist(bucket)) {
            String errMsg = "S3ClientFactory: bucket: " + bucket + " : does NOT exist in S3";
            LOGGER.error(errMsg);
            throw new Exception(errMsg);
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("S3ClientFactory: success: using bucket: " + bucket);
        }

        return s3client;
    }

    private static Regions getRegion() {
        String awsRegion = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWSREGION);
        Regions region = Regions.fromName(awsRegion);
        if (awsRegion == null || !awsRegion.isEmpty()) {
            region = Regions.US_WEST_2;
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("S3ClientFactory: default to aws region: US_WEST_2");
            }
        } else {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("S3ClientFactory: using aws region: " + awsRegion);
            }
        }
        return region;
    }
}
