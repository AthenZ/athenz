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

package io.athenz.server.aws.common.key.impl;

import com.yahoo.athenz.auth.util.StringUtils;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.util.Crypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
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
 */
public class S3PrivateKeyStore implements PrivateKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(S3PrivateKeyStore.class);

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
    
    private final S3Client s3;
    private final KmsClient kms;
    private boolean kmsDecrypt;
    
    public S3PrivateKeyStore() {
       this(initAmazonS3(), initAWSKMS());
       kmsDecrypt = Boolean.parseBoolean(System.getProperty(ATHENZ_PROP_AWS_KMS_DECRYPT, "false"));
    }

    public S3PrivateKeyStore(final S3Client s3, final KmsClient kms) {
        this.s3 = s3;
        this.kms = kms;
    }

    private static KmsClient initAWSKMS() {
        final String kmsRegion = System.getProperty(ATHENZ_PROP_AWS_KMS_REGION);
        return StringUtils.isEmpty(kmsRegion) ? KmsClient.create() :
                KmsClient.builder().region(Region.of(kmsRegion)).build();
    }

    private static S3Client initAmazonS3() {
        final String s3Region = System.getProperty(ATHENZ_PROP_AWS_S3_REGION);
        return StringUtils.isEmpty(s3Region) ? S3Client.create() :
                S3Client.builder().region(Region.of(s3Region)).build();
    }

    @Override
    public ServerPrivateKey getPrivateKey(String service, String serverHostName, String serverRegion, String algorithm) {

        final String bucketName;
        String keyName;
        String keyIdName;

        String objectSuffix = "";
        if (algorithm != null) {
            objectSuffix = "." + algorithm.toLowerCase();
        }
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
    public char[] getSecret(final String appName, final String keygroupName, final String keyName) {
        return getDecryptedData(appName, keyName).toCharArray();
    }
    
    private String getDecryptedData(final String bucketName, final String keyName) {
        
        String keyValue = "";

        if (LOG.isDebugEnabled()) {
            LOG.debug("retrieving appName {}, key {}", bucketName, keyName);
        }

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket(bucketName).key(keyName).build();

        try (ResponseInputStream<GetObjectResponse> responseInputStream = getS3().getObject(getObjectRequest)) {

            byte[] result = responseInputStream.readAllBytes();

            // if key should be decrypted, do so with KMS

            if (kmsDecrypt) {
                DecryptRequest decryptRequest = DecryptRequest.builder()
                        .ciphertextBlob(SdkBytes.fromByteArray(result)).build();
                DecryptResponse decryptResponse = getKMS().decrypt(decryptRequest);
                keyValue = decryptResponse.plaintext().asString(StandardCharsets.UTF_8);
            } else {
                keyValue = new String(result);
            }
            
        } catch (Exception ex) {
            LOG.error("error getting application secret.", ex);
        }

        return keyValue.trim();
    }

    S3Client getS3() {
        return s3;
    }

    KmsClient getKMS() {
        return kms;
    }
}
