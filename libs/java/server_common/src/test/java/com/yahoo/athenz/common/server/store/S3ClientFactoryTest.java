/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.store;

import com.amazonaws.auth.BasicSessionCredentials;
import com.yahoo.athenz.zms.ResourceException;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_PUBLIC_CERT;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;
import static org.testng.Assert.assertNotNull;

public class S3ClientFactoryTest {
    @Test
    public void testGetS3ClientNullCreds() {
        AWSCredentialsRefresher awsCredentialsRefresher = Mockito.mock(AWSCredentialsRefresher.class);
        S3ClientFactory s3ClientFactory = new S3ClientFactory(awsCredentialsRefresher);
        try {
            s3ClientFactory.create();
            fail();
        } catch (ResourceException ex) {
            assertEquals(500, ex.getCode());
        }
    }

    @Test
    public void testGetS3Client() {

        System.setProperty(ZTS_PROP_AWS_PUBLIC_CERT, "src/test/resources/aws_public.crt");
        AWSCredentialsRefresher credentialsRefresher = Mockito.mock(AWSCredentialsRefresher.class);
        when(credentialsRefresher.getCredentials()).thenReturn(new BasicSessionCredentials("accessKey", "secretKey", "token"));
        when(credentialsRefresher.getAwsRegion()).thenReturn("us-west-2");

        S3ClientFactory s3ClientFactory = new S3ClientFactory(credentialsRefresher);

        assertNotNull(s3ClientFactory.create());
    }
}
