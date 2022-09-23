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

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.s3.model.ObjectMetadata;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

import static com.amazonaws.RequestClientOptions.DEFAULT_STREAM_BUFFER_SIZE;

public class AwsSyncer implements CloudSyncer {

    private static final Logger LOGGER = LoggerFactory.getLogger(AwsSyncer.class);

    private static final int MAX_RETRY_COUNT = 3;

    private static final String OCTET_STREAM_CTYPE = "application/octet-stream";

    private final AmazonS3 s3client;

    public AwsSyncer() throws Exception {
        s3client = S3ClientFactory.getS3Client();
    }

    public void uploadDomain(String domainName, String domJson) throws Exception {

        ObjectMetadata meta = new ObjectMetadata();
        meta.setContentDisposition(domainName);
        byte[] payload = domJson.getBytes();
        meta.setContentLength(payload.length);
        meta.setContentType(OCTET_STREAM_CTYPE);
        final String sseAlgorithm = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWS_SSE_ALGORITHM);
        if (sseAlgorithm != null && !sseAlgorithm.isEmpty()) {
            meta.setSSEAlgorithm(sseAlgorithm);
        }

        // now let's calculate our md5 digest

        byte[] md5Byte = DigestUtils.md5(payload);
        String md5Meta = new String(Base64.encodeBase64(md5Byte));
        meta.setContentMD5(md5Meta);

        // in case we get an md5 mismatch exception from AWS, most likely
        // there were some network errors so we're going to retry our
        // operations upto 3 times with some small delay between operations

        for (int count = 0; true; count++) {

            try (BufferedInputStream instr = new BufferedInputStream(
                    new ByteArrayInputStream(payload), DEFAULT_STREAM_BUFFER_SIZE)) {

                // Amazon S3 never stores partial objects; if during this
                // call an exception wasn't thrown, the entire object was stored.

                final String bucket = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWSBUCK);
                s3client.putObject(bucket, domainName, instr, meta);

            } catch (Exception exc) {

                String errMsg = "AwsSyncer:uploadDomain: error: " + exc.getMessage();
                LOGGER.error(errMsg);

                // if we haven't hit our limit, we're going to retry
                // this operation

                if (count < MAX_RETRY_COUNT - 1) {
                    continue;
                }

                throw new Exception(errMsg, exc);
            }

            // if we got here then no exception and we successfully processed
            // our put object request

            LOGGER.info("AwsSyncer:uploadDomain: domain: " + domainName +
                    " : meta length sent: " + payload.length +
                    " : md5 sent: " + md5Meta);
            return;
        }
    }

    public void deleteDomain(String domainName) throws Exception {
        try {
            final String bucket = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_AWSBUCK);
            s3client.deleteObject(bucket, domainName);
        } catch (AmazonS3Exception exc) {
            String errMsg = "AwsSyncer:deleteDomain: error code: " + exc.getStatusCode() +
                    " : error message: " + exc.getErrorCode();
            LOGGER.error(errMsg);
            throw new Exception(errMsg, exc);
        }
    }
}
