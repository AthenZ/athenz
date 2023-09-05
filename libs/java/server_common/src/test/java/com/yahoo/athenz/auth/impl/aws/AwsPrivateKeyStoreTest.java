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
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.yahoo.athenz.auth.ServerPrivateKey;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.*;

public class AwsPrivateKeyStoreTest {

    private static final String ATHENZ_PROP_ZTS_BUCKET_NAME = "athenz.aws.zts.bucket_name";
    private static final String ATHENZ_AWS_KMS_REGION = "athenz.aws.store_kms_region";

    @Test
    public void testAwsPrivateKeyStore() {
        System.setProperty("athenz.aws.s3.region", "us-east-1");
        System.setProperty(ATHENZ_AWS_KMS_REGION, "us-east-1");
        String bucketName = "my_bucket";
        String keyName = "my_key";
        String expected = "my_value";

        System.setProperty(ATHENZ_PROP_ZTS_BUCKET_NAME, bucketName);
        System.setProperty("athenz.aws.zts.key_name", keyName);

        AmazonS3 s3 = mock(AmazonS3.class);
        AWSKMS kms = mock(AWSKMS.class);
        S3Object s3Object = mock(S3Object.class);
        Mockito.when(s3.getObject(bucketName, keyName)).thenReturn(s3Object);
        InputStream is = new ByteArrayInputStream(expected.getBytes());
        S3ObjectInputStream s3ObjectInputStream = new S3ObjectInputStream(is, null);
        Mockito.when(s3Object.getObjectContent()).thenReturn(s3ObjectInputStream);

        ByteBuffer buffer = ByteBuffer.wrap(expected.getBytes());
        DecryptResult decryptResult = mock(DecryptResult.class);
        Mockito.when(kms.decrypt(Mockito.any(DecryptRequest.class))).thenReturn(decryptResult);
        Mockito.when(decryptResult.getPlaintext()).thenReturn(buffer);

        AwsPrivateKeyStore awsPrivateKeyStore = new AwsPrivateKeyStore(s3, kms);
        String actual = awsPrivateKeyStore.getApplicationSecret(bucketName, keyName);
        StringBuilder privateKeyId = new StringBuilder(keyName);
        awsPrivateKeyStore.getPrivateKey("zts", "testServerHostName", privateKeyId);
        assertEquals(actual, expected);
        Mockito.when(s3Object.getObjectContent()).thenAnswer(invocation -> { throw new IOException("test IOException"); });
        awsPrivateKeyStore.getPrivateKey("zts", "testServerHostName", privateKeyId);

        System.clearProperty("athenz.aws.s3.region");
        System.clearProperty(ATHENZ_AWS_KMS_REGION);
    }

    @Test
    public void testGetPrivateKey() {
        System.setProperty("athenz.aws.s3.region", "us-east-1");
        System.setProperty("athenz.aws.store_kms_region", "us-east-1");
        AwsPrivateKeyStoreFactory awsPrivateKeyStoreFactory = new AwsPrivateKeyStoreFactory();
        assertTrue(awsPrivateKeyStoreFactory.create() instanceof AwsPrivateKeyStore);

        AwsPrivateKeyStore awsPrivateKeyStore = new AwsPrivateKeyStore();
        StringBuilder privateKeyId = new StringBuilder("testPrivateKeyId");
        awsPrivateKeyStore.getPrivateKey("zms", "testServerHostName", privateKeyId);
        awsPrivateKeyStore.getPrivateKey("testService", "testserverHostname", privateKeyId);
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

        AmazonS3 s3 = mock(AmazonS3.class);
        AWSKMS kms = mock(AWSKMS.class);
        S3Object s3Object = mock(S3Object.class);
        Mockito.when(s3.getObject(bucketName, keyName)).thenReturn(s3Object);
        InputStream is = new ByteArrayInputStream(expected.getBytes());
        S3ObjectInputStream s3ObjectInputStream = new S3ObjectInputStream(is, null);
        Mockito.when(s3Object.getObjectContent()).thenReturn(s3ObjectInputStream);

        ByteBuffer buffer = ByteBuffer.wrap(expected.getBytes());
        DecryptResult decryptResult = mock(DecryptResult.class);
        Mockito.when(kms.decrypt(Mockito.any(DecryptRequest.class))).thenReturn(decryptResult);
        Mockito.when(decryptResult.getPlaintext()).thenReturn(buffer);

        System.setProperty("athenz.aws.store_kms_decrypt", "true");
        AwsPrivateKeyStore awsPrivateKeyStore = new AwsPrivateKeyStore();
        AwsPrivateKeyStore spyAWS = Mockito.spy(awsPrivateKeyStore);
        doReturn(s3).when(spyAWS).getS3();
        doReturn(kms).when(spyAWS).getKMS();
        String actual = spyAWS.getApplicationSecret(bucketName, keyName);
        assertEquals(actual, expected);
        System.clearProperty("athenz.aws.s3.region");
        System.clearProperty(ATHENZ_AWS_KMS_REGION);
    }

    @Test
    public void testGetEncryptedDataException() {
        System.setProperty("athenz.aws.s3.region", "us-east-1");
        System.setProperty(ATHENZ_AWS_KMS_REGION, "us-east-1");
        String bucketName = "my_bucket";
        String keyName = "my_key";
        String expected = "my_value";

        AmazonS3 s3 = mock(AmazonS3.class);
        AWSKMS kms = mock(AWSKMS.class);
        S3Object s3Object = mock(S3Object.class);
        Mockito.when(s3.getObject(bucketName, keyName)).thenReturn(s3Object);
        given(s3Object.getObjectContent()).willAnswer(invocation -> { throw new IOException();});

        ByteBuffer buffer = ByteBuffer.wrap(expected.getBytes());
        DecryptResult decryptResult = mock(DecryptResult.class);
        Mockito.when(kms.decrypt(Mockito.any(DecryptRequest.class))).thenReturn(decryptResult);
        Mockito.when(decryptResult.getPlaintext()).thenReturn(buffer);

        System.setProperty("athenz.aws.store_kms_decrypt", "true");
        AwsPrivateKeyStore awsPrivateKeyStore = new AwsPrivateKeyStore();
        AwsPrivateKeyStore spyAWS = Mockito.spy(awsPrivateKeyStore);
        doReturn(s3).when(spyAWS).getS3();

        doReturn(kms).when(spyAWS).getKMS();
        assertEquals(spyAWS.getKMS(), kms);

        System.clearProperty("athenz.aws.s3.region");
        System.clearProperty(ATHENZ_AWS_KMS_REGION);
    }

    @Test
    public void testGetKMS() {
        AWSKMS kms = mock(AWSKMS.class);
        AmazonS3 s3 = mock(AmazonS3.class);
        AwsPrivateKeyStore privateKeyStore = new AwsPrivateKeyStore(s3, kms);

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

        AmazonS3 s3 = mock(AmazonS3.class);
        AWSKMS kms = mock(AWSKMS.class);
        AwsPrivateKeyStore awsPrivateKeyStore = new AwsPrivateKeyStore(s3, kms);
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

        AmazonS3 s3 = mock(AmazonS3.class);
        AWSKMS kms = mock(AWSKMS.class);

        S3Object s3ObjectKey = mock(S3Object.class);
        Mockito.when(s3.getObject(bucketName, algKeyName)).thenReturn(s3ObjectKey);
        File privKeyFile = new File("src/test/resources/unit_test_zts_private.pem");
        final String privKey = Files.readString(privKeyFile.toPath());
        InputStream isKey = new ByteArrayInputStream( privKey.getBytes() );
        S3ObjectInputStream s3ObjectKeyInputStream = new S3ObjectInputStream(isKey, null);
        Mockito.when(s3ObjectKey.getObjectContent()).thenReturn(s3ObjectKeyInputStream);

        S3Object s3ObjectKeyId = mock(S3Object.class);
        Mockito.when(s3.getObject(bucketName, algKeyId)).thenReturn(s3ObjectKeyId);
        InputStream isKeyId = new ByteArrayInputStream( expectedKeyId.getBytes() );
        S3ObjectInputStream s3ObjectKeyIdInputStream = new S3ObjectInputStream(isKeyId, null);
        Mockito.when(s3ObjectKeyId.getObjectContent()).thenReturn(s3ObjectKeyIdInputStream);

        AwsPrivateKeyStore awsPrivateKeyStore = new AwsPrivateKeyStore(s3, kms);
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

        AmazonS3 s3 = mock(AmazonS3.class);
        AWSKMS kms = mock(AWSKMS.class);

        S3Object s3ObjectKey = mock(S3Object.class);
        Mockito.when(s3.getObject(bucketName, algKeyName)).thenReturn(s3ObjectKey);
        InputStream isKey = new ByteArrayInputStream( privKey.getBytes() );
        S3ObjectInputStream s3ObjectKeyInputStream = new S3ObjectInputStream(isKey, null);
        Mockito.when(s3ObjectKey.getObjectContent()).thenReturn(s3ObjectKeyInputStream);

        S3Object s3ObjectKeyId = mock(S3Object.class);
        Mockito.when(s3.getObject(bucketName, algKeyId)).thenReturn(s3ObjectKeyId);
        InputStream isKeyId = new ByteArrayInputStream( expectedKeyId.getBytes() );
        S3ObjectInputStream s3ObjectKeyIdInputStream = new S3ObjectInputStream(isKeyId, null);
        Mockito.when(s3ObjectKeyId.getObjectContent()).thenReturn(s3ObjectKeyIdInputStream);

        AwsPrivateKeyStore awsPrivateKeyStore = new AwsPrivateKeyStore(s3, kms);
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
        final String algKeyName = "my_key.rsa";
        final String keyId = "my_key_id";

        System.setProperty("athenz.aws.s3.region", "us-east-1");

        System.setProperty("athenz.aws.zts.bucket_name", bucketName);
        System.setProperty("athenz.aws.zts.key_name", keyName);
        System.setProperty("athenz.aws.zts.key_id_name", keyId);

        AmazonS3 s3 = mock(AmazonS3.class);
        AWSKMS kms = mock(AWSKMS.class);

        Mockito.when(s3.getObject(bucketName, algKeyName)).thenThrow(new IndexOutOfBoundsException());

        AwsPrivateKeyStore awsPrivateKeyStore = new AwsPrivateKeyStore(s3, kms);
        assertNull(awsPrivateKeyStore.getPrivateKey("zts", "testServerHostName", "us-east-1", "rsa"));

        System.clearProperty("athenz.aws.s3.region");

        System.clearProperty("athenz.aws.zts.bucket_name");
        System.clearProperty("athenz.aws.zts.key_name");
        System.clearProperty("athenz.aws.zts.key_id_name");
    }
}
