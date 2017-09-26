/**
 * Copyright 2017 Yahoo Holdings Inc.
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

package com.yahoo.athenz.auth.impl.aws;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.yahoo.athenz.auth.PrivateKeyStore;

/**
 * Downloads encrypted secrete from private S3 bucket and returns decrypted secrete in plaintext
 * Assumes that S3 bucket contains data encrypted with KMS. 
 * Assumes that this runs on an instance with a policy set to allow kms decrypt and read access to private S3 bucket. But it can be a public S3 bucket.
 * AmazonS3 lib defaults to reading from S3 buckets created under us-east-1 unless its explicitly specified using system property or aws config
 * 
 * @author charlesk
 * See http://docs.aws.amazon.com/kms/latest/developerguide/programming-encryption.html
 * See http://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/examples-s3-objects.html
 */
public class AwsPrivateKeyStore implements PrivateKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(AwsPrivateKeyStore.class);
    private static final String ATHENZ_PROP_AWS_S3_REGION = "athenz.aws.s3.region";
    private final AmazonS3 s3;
    private final AWSKMS kms;


    public AwsPrivateKeyStore() {
       this(initAmazonS3(), AWSKMSClientBuilder.defaultClient());
    }
    
    private static AmazonS3 initAmazonS3() {
        String s3Region = System.getProperty(ATHENZ_PROP_AWS_S3_REGION);
        if (null != s3Region && !s3Region.isEmpty()) {
            return AmazonS3ClientBuilder.standard().withRegion(s3Region).build();
       }
        return AmazonS3ClientBuilder.defaultClient();
    }
    
    public AwsPrivateKeyStore(final AmazonS3 s3, final AWSKMS kms) {
        this.s3 = s3;
        this.kms = kms;
    }
    
    @Override
    public String getApplicationSecret(final String appName, final String keyName) {
        String keyValue = "";
        S3Object s3Object = s3.getObject(appName, keyName);
        if (LOG.isDebugEnabled()) {
            LOG.debug("retrieving appName {}, key {}", appName, keyName);
        }
        if (null == s3Object) {
            LOG.error("error retrieving key {}, from bucket {}", keyName, appName);
            return keyValue;
        }
        try (S3ObjectInputStream s3InputStream = s3Object.getObjectContent(); 
                ByteArrayOutputStream result = new ByteArrayOutputStream();) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = s3InputStream.read(buffer)) != -1) {
                result.write(buffer, 0, length);
            }
            //key should be encrypted. decrypt using aws KMS
            DecryptRequest req = new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(result.toByteArray()));
            ByteBuffer plainText = kms.decrypt(req).getPlaintext();
            keyValue = new String(plainText.array());
        } catch (IOException e) {
            LOG.error("error getting application secret.", e);
        }
        return keyValue.trim();
    }
}
