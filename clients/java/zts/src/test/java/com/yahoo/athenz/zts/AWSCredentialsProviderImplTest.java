/*
 * Copyright 2018 Yahoo Holdings, Inc.
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
package com.yahoo.athenz.zts;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class AWSCredentialsProviderImplTest {

    @BeforeClass
    public void init() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE, "false");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_X509CSR_DN, "ou=eng,o=athenz,c=us");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_X509CSR_DOMAIN, "athenz.cloud");
    }

    @Test
    public void testAWSCredentialsProviderImpl() {
        ZTSClient ztsClient = Mockito.mock(ZTSClient.class);
        AWSTemporaryCredentials awsTemporaryCredentials = new AWSTemporaryCredentials();
        awsTemporaryCredentials.setAccessKeyId("accessKey");

        AWSTemporaryCredentials awsTemporaryCredentialsTwo = new AWSTemporaryCredentials();
        awsTemporaryCredentialsTwo.setAccessKeyId("accessKeyTwo");


        //Check that get credentials calls refresh to get credentials from ZTS

        Mockito.when(ztsClient.getAWSTemporaryCredentials(Mockito.any(), Mockito.any())).thenReturn(awsTemporaryCredentials, awsTemporaryCredentialsTwo);
        AWSCredentialsProviderImpl original = new AWSCredentialsProviderImpl(ztsClient, null, null);

        AWSCredentialsProviderImpl awsCredentialsProviderImpl = Mockito.spy(original);

        Assert.assertEquals(awsTemporaryCredentials.getAccessKeyId(), awsCredentialsProviderImpl.getCredentials().getAWSAccessKeyId());
        Mockito.verify(awsCredentialsProviderImpl, Mockito.times(1)).refresh();

        Assert.assertEquals(awsTemporaryCredentialsTwo.getAccessKeyId(), awsCredentialsProviderImpl.getCredentials().getAWSAccessKeyId());
        Mockito.verify(awsCredentialsProviderImpl, Mockito.times(2)).refresh();

        //null credentials are returned in case of exception
        Mockito.when(ztsClient.getAWSTemporaryCredentials(Mockito.any(), Mockito.any())).thenThrow(new ResourceException(400));
        Assert.assertNull(awsCredentialsProviderImpl.getCredentials());
    }
}
