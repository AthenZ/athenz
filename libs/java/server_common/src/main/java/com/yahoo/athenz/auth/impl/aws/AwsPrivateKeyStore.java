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

package com.yahoo.athenz.auth.impl.aws;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.util.Crypto;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;

/**
 * Downloads encrypted secrets from private S3 bucket and returns decrypted data
 * in plaintext. The key store supports the following two use cases:
 *   a) Encrypted S3 bucket - all data already encrypted with keys from KMS
 *   b) Regular S3 bucket - data is manually encrypted with a key from KMS
 * Assumes that this runs on an instance with a policy set to allow kms decrypt and
 * read access to private S3 bucket. With use case (a) S3 api will automatically
 * decrypt the data and return plain text while in use case (b) the caller is
 * responsible for decrypting data.
 * AmazonS3 lib defaults to reading from S3 buckets created under us-east-1 unless
 * its explicitly specified using system property or aws config
 * 
 * @author charlesk
 * See http://docs.aws.amazon.com/kms/latest/developerguide/programming-encryption.html
 * See http://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/examples-s3-objects.html
 */
public class AwsPrivateKeyStore implements PrivateKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(AwsPrivateKeyStore.class);

    private static final String ATHENZ_PROP_AWS_S3_REGION   = "athenz.aws.s3.region";
    private static final String ATHENZ_PROP_AWS_KMS_DECRYPT = "athenz.aws.store_kms_decrypt";
    private static final String ATHENZ_PROP_AWS_KMS_REGION  = "athenz.aws.store_kms_region";
    private static final String ATHENZ_PROP_ZMS_BUCKET_NAME = "athenz.aws.zms.bucket_name";
    private static final String ATHENZ_PROP_ZMS_KEY_NAME    = "athenz.aws.zms.key_name";
    private static final String ATHENZ_PROP_ZMS_KEY_ID_NAME = "athenz.aws.zms.key_id_name";
    private static final String ATHENZ_PROP_ZTS_BUCKET_NAME = "athenz.aws.zts.bucket_name";
    private static final String ATHENZ_PROP_ZTS_KEY_NAME    = "athenz.aws.zts.key_name";
    private static final String ATHENZ_PROP_ZTS_KEY_ID_NAME = "athenz.aws.zts.key_id_name";

    private static final String ATHENZ_DEFAULT_KEY_NAME     = "service_private_key";
    private static final String ATHENZ_DEFAULT_KEY_ID_NAME  = "service_private_key_id";
     
    private static final String ZMS_SERVICE = "zms";
    private static final String ZTS_SERVICE = "zts";
    
    private final AmazonS3 s3;
    private final AWSKMS kms;
    private boolean kmsDecrypt;
    
    public AwsPrivateKeyStore() {
       this(initAmazonS3(), initAWSKMS());
       kmsDecrypt = Boolean.parseBoolean(System.getProperty(ATHENZ_PROP_AWS_KMS_DECRYPT, "false"));
    }

    private static AWSKMS initAWSKMS() {
        final String kmsRegion = System.getProperty(ATHENZ_PROP_AWS_KMS_REGION);
        return StringUtil.isEmpty(kmsRegion) ? AWSKMSClientBuilder.defaultClient() : AWSKMSClientBuilder.standard().withRegion(kmsRegion).build();
    }

    private static AmazonS3 initAmazonS3() {
        final String s3Region = System.getProperty(ATHENZ_PROP_AWS_S3_REGION);
        return StringUtil.isEmpty(s3Region) ? AmazonS3ClientBuilder.defaultClient() : AmazonS3ClientBuilder.standard().withRegion(s3Region).build();
    }
    
    public AwsPrivateKeyStore(final AmazonS3 s3, final AWSKMS kms) {
        this.s3 = s3;
        this.kms = kms;
    }

    @Override
    public ServerPrivateKey getPrivateKey(String service, String serverHostName, String serverRegion, String algorithm) {

        final String bucketName;
        String keyName;
        String keyIdName;

        final String objectSuffix = "." + algorithm.toLowerCase();
        if (ZMS_SERVICE.equals(service)) {
            bucketName = System.getProperty(ATHENZ_PROP_ZMS_BUCKET_NAME);
            keyName = System.getProperty(ATHENZ_PROP_ZMS_KEY_NAME, ATHENZ_DEFAULT_KEY_NAME) + objectSuffix;
            keyIdName = System.getProperty(ATHENZ_PROP_ZMS_KEY_ID_NAME, ATHENZ_DEFAULT_KEY_ID_NAME) + objectSuffix;
        } else if (ZTS_SERVICE.equals(service)) {
            bucketName = System.getProperty(ATHENZ_PROP_ZTS_BUCKET_NAME);
            keyName = System.getProperty(ATHENZ_PROP_ZTS_KEY_NAME, ATHENZ_DEFAULT_KEY_NAME) + objectSuffix;
            keyIdName = System.getProperty(ATHENZ_PROP_ZTS_KEY_ID_NAME, ATHENZ_DEFAULT_KEY_ID_NAME) + objectSuffix;
        } else {
            LOG.error("Unknown service specified: {}", service);
            return null;
        }

        if (bucketName == null) {
            LOG.error("No bucket name specified with system property");
            return null;
        }

        PrivateKey pkey = null;
        try {
            pkey = Crypto.loadPrivateKey(getDecryptedData(bucketName, keyName));
        } catch (Exception ex) {
            LOG.error("unable to load private key", ex);
        }
        return pkey == null ? null : new ServerPrivateKey(pkey, getDecryptedData(bucketName, keyIdName));
    }

    @Override
    public PrivateKey getPrivateKey(String service, String serverHostName, StringBuilder privateKeyId) {
        
        String bucketName;
        String keyName;
        String keyIdName;
        
        if (ZMS_SERVICE.equals(service)) {
            bucketName = System.getProperty(ATHENZ_PROP_ZMS_BUCKET_NAME);
            keyName = System.getProperty(ATHENZ_PROP_ZMS_KEY_NAME, ATHENZ_DEFAULT_KEY_NAME);
            keyIdName = System.getProperty(ATHENZ_PROP_ZMS_KEY_ID_NAME, ATHENZ_DEFAULT_KEY_ID_NAME);
        } else if (ZTS_SERVICE.equals(service)) {
            bucketName = System.getProperty(ATHENZ_PROP_ZTS_BUCKET_NAME);
            keyName = System.getProperty(ATHENZ_PROP_ZTS_KEY_NAME, ATHENZ_DEFAULT_KEY_NAME);
            keyIdName = System.getProperty(ATHENZ_PROP_ZTS_KEY_ID_NAME, ATHENZ_DEFAULT_KEY_ID_NAME);
        } else {
            LOG.error("Unknown service specified: {}", service);
            return null;
        }
        
        if (bucketName == null) {
            LOG.error("No bucket name specified with system property");
            return null;
        }
        
        PrivateKey pkey = Crypto.loadPrivateKey(getDecryptedData(bucketName, keyName));
        privateKeyId.append(getDecryptedData(bucketName, keyIdName));
        return pkey;
    }
    
    @Override
    public String getApplicationSecret(final String appName, final String keyName) {
        return getDecryptedData(appName, keyName);
    }
    
    private String getDecryptedData(final String bucketName, final String keyName) {
        
        String keyValue = "";
        S3Object s3Object = getS3().getObject(bucketName, keyName);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("retrieving appName {}, key {}", bucketName, keyName);
        }
        
        if (null == s3Object) {
            LOG.error("error retrieving key {}, from bucket {}", keyName, bucketName);
            return keyValue;
        }
        
        try (S3ObjectInputStream s3InputStream = s3Object.getObjectContent(); 
                ByteArrayOutputStream result = new ByteArrayOutputStream()) {
            
            byte[] buffer = new byte[1024];
            int length;
            while ((length = s3InputStream.read(buffer)) != -1) {
                result.write(buffer, 0, length);
            }
            // if key should be decrypted, do so with KMS

            if (kmsDecrypt) {
                DecryptRequest req = new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(result.toByteArray()));
                ByteBuffer plainText = getKMS().decrypt(req).getPlaintext();
                keyValue = new String(plainText.array());
            } else {
                keyValue = result.toString();
            }
            
        } catch (IOException e) {
            LOG.error("error getting application secret.", e);
        }

        return keyValue.trim();
    }

    AmazonS3 getS3() {
        return s3;
    }

    AWSKMS getKMS() {
        return kms;
    }
}
