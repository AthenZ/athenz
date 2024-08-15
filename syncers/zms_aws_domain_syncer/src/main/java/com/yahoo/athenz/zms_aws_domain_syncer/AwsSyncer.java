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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;

public class AwsSyncer {

    private static final Logger LOGGER = LoggerFactory.getLogger(AwsSyncer.class);

    private static final int MAX_RETRY_COUNT = 3;

    private final S3Client s3Client;

    public AwsSyncer() throws Exception {
        this.s3Client = S3ClientFactory.getS3Client();
    }

    public AwsSyncer(S3Client s3Client) {
        this.s3Client = s3Client;
    }

    public void uploadDomain(final String domainName, final String domJson) {

        final String sseAlgorithm = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_SSE_ALGORITHM);
        final String bucketName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET);

        // now let's calculate our md5 digest

        byte[] payload = domJson.getBytes();
        byte[] md5Byte = DigestUtils.md5(payload);
        String md5Meta = new String(Base64.encodeBase64(md5Byte));

        // Upload object with MD5 hash

        PutObjectRequest.Builder putObjectRequestBuilder = PutObjectRequest.builder()
                .bucket(bucketName)
                .key(domainName)
                .contentMD5(md5Meta);

        if (!Config.isEmpty(sseAlgorithm)) {
            putObjectRequestBuilder.serverSideEncryption(ServerSideEncryption.fromValue(sseAlgorithm));
        }

        PutObjectRequest putObjectRequest = putObjectRequestBuilder.build();

        // in case we get a md5 mismatch exception from AWS, most likely
        // there were some network errors, so we're going to retry our
        // operations upto 3 times with some small delay between operations

        for (int count = 0; true; count++) {

            try {

                s3Client.putObject(putObjectRequest, RequestBody.fromBytes(payload));

            } catch (Exception ex) {

                LOGGER.error("unable to upload domain {}", domainName, ex);

                // if we haven't hit our limit, we're going to retry
                // this operation

                if (count < MAX_RETRY_COUNT - 1) {
                    continue;
                }

                throw ex;
            }

            // if we got here then no exception, and we successfully processed
            // our put object request

            LOGGER.info("upload completed for domain: {}, meta length sent: {}, md5 sent: {}",
                    domainName, payload.length, md5Meta);
            return;
        }
    }

    public void deleteDomain(final String domainName) {

        try {
            final String bucketName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET);
            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(bucketName)
                    .key(domainName)
                    .build();

            s3Client.deleteObject(deleteObjectRequest);
        } catch (Exception ex) {
            LOGGER.error("unable to delete domain: {}", domainName, ex);
            throw ex;
        }
    }
}
