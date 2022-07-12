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

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.ObjectMetadata;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

import static com.amazonaws.RequestClientOptions.DEFAULT_STREAM_BUFFER_SIZE;

public class AwsSyncer {

    private static final Logger LOGGER = LoggerFactory.getLogger(AwsSyncer.class);

    private static final int MAX_RETRY_COUNT = 3;
    private static final String OCTET_STREAM_CONTENT_TYPE = "application/octet-stream";

    private final AmazonS3 s3client;

    public AwsSyncer() throws Exception {
        this.s3client = S3ClientFactory.getS3Client();
    }

    public AwsSyncer(AmazonS3 s3client) {
        this.s3client = s3client;
    }

    public void uploadDomain(final String domainName, final String domJson) throws Exception {

        ObjectMetadata meta = new ObjectMetadata();
        meta.setContentDisposition(domainName);
        byte[] payload = domJson.getBytes();
        meta.setContentLength(payload.length);
        meta.setContentType(OCTET_STREAM_CONTENT_TYPE);
        final String sseAlgorithm = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_SSE_ALGORITHM);
        if (!Config.isEmpty(sseAlgorithm)) {
            meta.setSSEAlgorithm(sseAlgorithm);
        }

        // now let's calculate our md5 digest

        byte[] md5Byte = DigestUtils.md5(payload);
        String md5Meta = new String(Base64.encodeBase64(md5Byte));
        meta.setContentMD5(md5Meta);

        // in case we get a md5 mismatch exception from AWS, most likely
        // there were some network errors, so we're going to retry our
        // operations upto 3 times with some small delay between operations

        for (int count = 0; true; count++) {

            try (BufferedInputStream instr = new BufferedInputStream(
                    new ByteArrayInputStream(payload), DEFAULT_STREAM_BUFFER_SIZE)) {

                // Amazon S3 never stores partial objects; if during this
                // call an exception wasn't thrown, the entire object was stored.

                final String bucket = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET);
                s3client.putObject(bucket, domainName, instr, meta);

            } catch (Exception ex) {

                LOGGER.error("unable to upload domain {}", domainName, ex);

                // if we haven't hit our limit, we're going to retry
                // this operation

                if (count < MAX_RETRY_COUNT - 1) {
                    continue;
                }

                throw new Exception(ex);
            }

            // if we got here then no exception, and we successfully processed
            // our put object request

            LOGGER.info("upload completed for domain: {}, meta length sent: {}, md5 sent: {}",
                    domainName, payload.length, md5Meta);
            return;
        }
    }

    public void deleteDomain(final String domainName) throws Exception {

        try {
            final String bucket = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET);
            s3client.deleteObject(bucket, domainName);
        } catch (Exception ex) {
            LOGGER.error("unable to delete domain: {}", domainName, ex);
            throw new Exception(ex);
        }
    }
}
