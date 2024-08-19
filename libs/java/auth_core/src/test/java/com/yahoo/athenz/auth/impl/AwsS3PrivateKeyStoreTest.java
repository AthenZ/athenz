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
package com.yahoo.athenz.auth.impl;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import com.yahoo.athenz.auth.ServerPrivateKey;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.*;

public class AwsS3PrivateKeyStoreTest {

    private static final String ATHENZ_PROP_ZTS_BUCKET_NAME = "athenz.aws.zts.bucket_name";
    private static final String ATHENZ_AWS_KMS_REGION = "athenz.aws.store_kms_region";

    @Test
    public void testAwsS3PrivateKeyStore() {
        System.setProperty("athenz.aws.s3.region", "us-east-1");
        System.setProperty(ATHENZ_AWS_KMS_REGION, "us-east-1");
        String bucketName = "my_bucket";
        String keyName = "my_key";
        String expected = "my_value";

        System.setProperty(ATHENZ_PROP_ZTS_BUCKET_NAME, bucketName);
        System.setProperty("athenz.aws.zts.key_name", keyName);

        S3Client s3 = mock(S3Client.class);
        KmsClient kms = mock(KmsClient.class);
        InputStream is = new ByteArrayInputStream(expected.getBytes());
        GetObjectResponse response = GetObjectResponse.builder().build();
        ResponseInputStream<GetObjectResponse> s3ObjectInputStream = new ResponseInputStream<>(response, is);
        Mockito.when(s3.getObject(any(GetObjectRequest.class))).thenReturn(s3ObjectInputStream);

        DecryptResponse decryptResponse = mock(DecryptResponse.class);
        Mockito.when(kms.decrypt(any(DecryptRequest.class))).thenReturn(decryptResponse);
        SdkBytes buffer = SdkBytes.fromByteArray(expected.getBytes());
        Mockito.when(decryptResponse.plaintext()).thenReturn(buffer);

        AwsS3PrivateKeyStore awsPrivateKeyStore = new AwsS3PrivateKeyStore(s3, kms);
        char []actual = awsPrivateKeyStore.getSecret(bucketName, "", keyName);
        awsPrivateKeyStore.getPrivateKey("zts", "testServerHostName", "region", null);
        assertEquals(actual, expected.toCharArray());
        S3Exception s3Exception = mock(S3Exception.class);
        Mockito.when(s3.getObject(any(GetObjectRequest.class))).thenThrow(s3Exception);
        awsPrivateKeyStore.getPrivateKey("zts", "testServerHostName", "region", null);

        System.clearProperty("athenz.aws.s3.region");
        System.clearProperty(ATHENZ_AWS_KMS_REGION);
    }

    @Test
    public void testGetPrivateKey() {
        System.setProperty("athenz.aws.s3.region", "us-east-1");
        System.setProperty("athenz.aws.store_kms_region", "us-east-1");
        AwsS3PrivateKeyStoreFactory awsPrivateKeyStoreFactory = new AwsS3PrivateKeyStoreFactory();
        assertTrue(awsPrivateKeyStoreFactory.create() instanceof AwsS3PrivateKeyStore);

        AwsS3PrivateKeyStore awsPrivateKeyStore = new AwsS3PrivateKeyStore();
        awsPrivateKeyStore.getPrivateKey("zms", "testServerHostName", "region", null);
        awsPrivateKeyStore.getPrivateKey("testService", "testserverHostname", "region", null);
        System.clearProperty("athenz.aws.s3.region");
        System.clearProperty(ATHENZ_AWS_KMS_REGION);
    }

    @Test
    public void testGetApplicationSecret() {
        System.setProperty("athenz.aws.s3.region", "us-east-1");
        System.setProperty(ATHENZ_AWS_KMS_REGION, "us-east-1");
        String bucketName = "my_bucket";
        String keyName = "my_key";
        String expected = "my_value";

        S3Client s3 = mock(S3Client.class);
        KmsClient kms = mock(KmsClient.class);
        InputStream is = new ByteArrayInputStream(expected.getBytes());
        GetObjectResponse response = GetObjectResponse.builder().build();
        ResponseInputStream<GetObjectResponse> s3ObjectInputStream = new ResponseInputStream<>(response, is);
        Mockito.when(s3.getObject(any(GetObjectRequest.class))).thenReturn(s3ObjectInputStream);

        DecryptResponse decryptResponse = mock(DecryptResponse.class);
        Mockito.when(kms.decrypt(any(DecryptRequest.class))).thenReturn(decryptResponse);
        SdkBytes buffer = SdkBytes.fromByteArray(expected.getBytes());
        Mockito.when(decryptResponse.plaintext()).thenReturn(buffer);

        System.setProperty("athenz.aws.store_kms_decrypt", "true");
        AwsS3PrivateKeyStore awsPrivateKeyStore = new AwsS3PrivateKeyStore();
        AwsS3PrivateKeyStore spyAWS = Mockito.spy(awsPrivateKeyStore);
        doReturn(s3).when(spyAWS).getS3();
        doReturn(kms).when(spyAWS).getKMS();
        char[] actual = spyAWS.getSecret(bucketName, "", keyName);
        assertEquals(actual, expected.toCharArray());
        System.clearProperty("athenz.aws.s3.region");
        System.clearProperty(ATHENZ_AWS_KMS_REGION);
    }

    @Test
    public void testGetEncryptedDataException() {
        System.setProperty("athenz.aws.s3.region", "us-east-1");
        System.setProperty(ATHENZ_AWS_KMS_REGION, "us-east-1");
        String expected = "my_value";

        S3Client s3 = mock(S3Client.class);
        KmsClient kms = mock(KmsClient.class);
        S3Exception s3Exception = mock(S3Exception.class);
        Mockito.when(s3.getObject(any(GetObjectRequest.class))).thenThrow(s3Exception);

        DecryptResponse decryptResponse = mock(DecryptResponse.class);
        Mockito.when(kms.decrypt(any(DecryptRequest.class))).thenReturn(decryptResponse);
        SdkBytes buffer = SdkBytes.fromByteArray(expected.getBytes());
        Mockito.when(decryptResponse.plaintext()).thenReturn(buffer);

        System.setProperty("athenz.aws.store_kms_decrypt", "true");
        AwsS3PrivateKeyStore awsPrivateKeyStore = new AwsS3PrivateKeyStore();
        AwsS3PrivateKeyStore spyAWS = Mockito.spy(awsPrivateKeyStore);
        doReturn(s3).when(spyAWS).getS3();

        doReturn(kms).when(spyAWS).getKMS();
        assertEquals(spyAWS.getKMS(), kms);

        char[] secret = spyAWS.getSecret("app", "keygroup", "key");
        assertEquals(secret.length, 0);

        System.clearProperty("athenz.aws.s3.region");
        System.clearProperty(ATHENZ_AWS_KMS_REGION);
    }

    @Test
    public void testGetKMS() {
        S3Client s3 = mock(S3Client.class);
        KmsClient kms = mock(KmsClient.class);
        AwsS3PrivateKeyStore privateKeyStore = new AwsS3PrivateKeyStore(s3, kms);

        assertEquals(privateKeyStore.getKMS(), kms);
    }

    @Test
    public void testGetPrivateKeyAlgorithm() {

        // first valid zms/zts services

        try {
            testGetPrivateKeyAlgorithm("zms");
        } catch (IOException ex) {
            fail(ex.getMessage());
        }

        try {
            testGetPrivateKeyAlgorithm("zts");
        } catch (IOException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testGetPrivateKeyAlgorithmFailures() {

        // with unknown service we should get a null object

        S3Client s3 = mock(S3Client.class);
        KmsClient kms = mock(KmsClient.class);
        AwsS3PrivateKeyStore awsPrivateKeyStore = new AwsS3PrivateKeyStore(s3, kms);
        assertNull(awsPrivateKeyStore.getPrivateKey("msd", "testServerHostName", "us-east-1", "rsa"));

        // with no bucket with should get a null object

        System.clearProperty("athenz.aws.zts.bucket_name");
        System.setProperty("athenz.aws.zts.key_name", "key");
        System.setProperty("athenz.aws.zts.key_id_name", "keyid");
        assertNull(awsPrivateKeyStore.getPrivateKey("zts", "testServerHostName", "us-east-1", "rsa"));

        System.clearProperty("athenz.aws.zts.bucket_name");
        System.clearProperty("athenz.aws.zts.key_name");
        System.clearProperty("athenz.aws.zts.key_id_name");
    }

    private void testGetPrivateKeyAlgorithm(final String service) throws IOException {

        final String bucketName = "my_bucket";
        final String keyName = "my_key";
        final String algKeyName = "my_key.rsa";
        final String keyId = "my_key_id";
        final String algKeyId = "my_key_id.rsa";
        final String expectedKeyId = "1";

        System.setProperty("athenz.aws.s3.region", "us-east-1");

        System.setProperty("athenz.aws." + service + ".bucket_name", bucketName);
        System.setProperty("athenz.aws." + service + ".key_name", keyName);
        System.setProperty("athenz.aws." + service + ".key_id_name", keyId);

        S3Client s3 = mock(S3Client.class);
        KmsClient kms = mock(KmsClient.class);

        GetObjectRequest getObjectRequestKey = GetObjectRequest.builder().bucket(bucketName).key(algKeyName).build();
        File privKeyFile = new File("src/test/resources/unit_test_zts_private_k0.key");
        final String privKey = Files.readString(privKeyFile.toPath());
        InputStream isKey = new ByteArrayInputStream( privKey.getBytes() );
        GetObjectResponse response = GetObjectResponse.builder().build();
        ResponseInputStream<GetObjectResponse> s3ObjectInputStream = new ResponseInputStream<>(response, isKey);
        Mockito.when(s3.getObject(getObjectRequestKey)).thenReturn(s3ObjectInputStream);

        GetObjectRequest getObjectRequestId = GetObjectRequest.builder().bucket(bucketName).key(algKeyId).build();
        InputStream isKeyId = new ByteArrayInputStream( expectedKeyId.getBytes() );
        GetObjectResponse responseId = GetObjectResponse.builder().build();
        ResponseInputStream<GetObjectResponse> s3ObjectKeyIdInputStream = new ResponseInputStream<>(responseId, isKeyId);
        Mockito.when(s3.getObject(getObjectRequestId)).thenReturn(s3ObjectKeyIdInputStream);

        AwsS3PrivateKeyStore awsPrivateKeyStore = new AwsS3PrivateKeyStore(s3, kms);
        ServerPrivateKey serverPrivateKey = awsPrivateKeyStore.getPrivateKey(service, "testServerHostName", "us-east-1", "rsa");
        assertNotNull(serverPrivateKey);
        assertNotNull(serverPrivateKey.getKey());
        assertEquals(serverPrivateKey.getAlgorithm().toString(), "RS256");
        assertEquals(serverPrivateKey.getId(), "1");

        System.clearProperty("athenz.aws.s3.region");

        System.clearProperty("athenz.aws." + service + ".bucket_name");
        System.clearProperty("athenz.aws." + service + ".key_name");
        System.clearProperty("athenz.aws." + service + ".key_id_name");
    }

    @Test
    public void testGetPrivateKeyAlgorithmInvalidKey() {

        final String bucketName = "my_bucket";
        final String keyName = "my_key";
        final String algKeyName = "my_key.rsa";
        final String keyId = "my_key_id";
        final String algKeyId = "my_key_id.rsa";
        final String expectedKeyId = "1";
        final String privKey = "invalid-key";

        System.setProperty("athenz.aws.s3.region", "us-east-1");

        System.setProperty("athenz.aws.zts.bucket_name", bucketName);
        System.setProperty("athenz.aws.zts.key_name", keyName);
        System.setProperty("athenz.aws.zts.key_id_name", keyId);

        S3Client s3 = mock(S3Client.class);
        KmsClient kms = mock(KmsClient.class);

        GetObjectRequest getObjectRequestKey = GetObjectRequest.builder().bucket(bucketName).key(algKeyName).build();
        InputStream isKey = new ByteArrayInputStream( privKey.getBytes() );
        GetObjectResponse response = GetObjectResponse.builder().build();
        ResponseInputStream<GetObjectResponse> s3ObjectInputStream = new ResponseInputStream<>(response, isKey);
        Mockito.when(s3.getObject(getObjectRequestKey)).thenReturn(s3ObjectInputStream);

        GetObjectRequest getObjectRequestId = GetObjectRequest.builder().bucket(bucketName).key(algKeyId).build();
        InputStream isKeyId = new ByteArrayInputStream( expectedKeyId.getBytes() );
        GetObjectResponse responseId = GetObjectResponse.builder().build();
        ResponseInputStream<GetObjectResponse> s3ObjectKeyIdInputStream = new ResponseInputStream<>(responseId, isKeyId);
        Mockito.when(s3.getObject(getObjectRequestId)).thenReturn(s3ObjectKeyIdInputStream);

        AwsS3PrivateKeyStore awsPrivateKeyStore = new AwsS3PrivateKeyStore(s3, kms);
        assertNull(awsPrivateKeyStore.getPrivateKey("zts", "testServerHostName", "us-east-1", "rsa"));

        System.clearProperty("athenz.aws.s3.region");

        System.clearProperty("athenz.aws.zts.bucket_name");
        System.clearProperty("athenz.aws.zts.key_name");
        System.clearProperty("athenz.aws.zts.key_id_name");
    }

    @Test
    public void testGetPrivateKeyAlgorithmException() {

        final String bucketName = "my_bucket";
        final String keyName = "my_key";
        final String keyId = "my_key_id";

        System.setProperty("athenz.aws.s3.region", "us-east-1");

        System.setProperty("athenz.aws.zts.bucket_name", bucketName);
        System.setProperty("athenz.aws.zts.key_name", keyName);
        System.setProperty("athenz.aws.zts.key_id_name", keyId);

        S3Client s3 = mock(S3Client.class);
        KmsClient kms = mock(KmsClient.class);

        Mockito.when(s3.getObject(any(GetObjectRequest.class))).thenThrow(new IndexOutOfBoundsException());

        AwsS3PrivateKeyStore awsPrivateKeyStore = new AwsS3PrivateKeyStore(s3, kms);
        assertNull(awsPrivateKeyStore.getPrivateKey("zts", "testServerHostName", "us-east-1", "rsa"));

        System.clearProperty("athenz.aws.s3.region");

        System.clearProperty("athenz.aws.zts.bucket_name");
        System.clearProperty("athenz.aws.zts.key_name");
        System.clearProperty("athenz.aws.zts.key_id_name");
    }
}
