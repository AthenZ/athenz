/*
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

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class AwsPrivateKeyStoreTest {

    @Test
    public void testAwsPrivateKeyStore() {
        String bucketName = "my_bucket";
        String keyName = "my_key";
        String expected = "my_value";
        
        AmazonS3 s3 = Mockito.mock(AmazonS3.class);
        AWSKMS kms = Mockito.mock(AWSKMS.class);
        S3Object s3Object = Mockito.mock(S3Object.class);
        Mockito.when(s3.getObject(bucketName, keyName)).thenReturn(s3Object);
        InputStream is = new ByteArrayInputStream( expected.getBytes() );
        S3ObjectInputStream s3ObjectInputStream = new S3ObjectInputStream(is, null);
        Mockito.when(s3Object.getObjectContent()).thenReturn(s3ObjectInputStream);

        ByteBuffer buffer = ByteBuffer.wrap(expected.getBytes());
        DecryptResult decryptResult = Mockito.mock(DecryptResult.class); 
        Mockito.when(kms.decrypt(Mockito.any(DecryptRequest.class))).thenReturn(decryptResult);
        Mockito.when(decryptResult.getPlaintext()).thenReturn(buffer);

        AwsPrivateKeyStore awsPrivateKeyStore = new AwsPrivateKeyStore(s3, kms);
        String actual = awsPrivateKeyStore.getApplicationSecret(bucketName, keyName);
        Assert.assertEquals(actual, expected);
        
    }
}
