package com.yahoo.athenz.zts;


import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import static org.mockito.Matchers.any;


public class AWSCredentialsProviderImplTest {
    @Test
    public void testAWSCredentialsProviderImpl() throws Exception {
        ZTSClient ztsClient = Mockito.mock(ZTSClient.class);
        AWSTemporaryCredentials awsTemporaryCredentials = new AWSTemporaryCredentials();
        awsTemporaryCredentials.setAccessKeyId("accessKey");

        AWSTemporaryCredentials awsTemporaryCredentialsTwo = new AWSTemporaryCredentials();
        awsTemporaryCredentialsTwo.setAccessKeyId("accessKeyTwo");


        //Check that get credentials calls refresh to get credentials from ZTS

        Mockito.when(ztsClient.getAWSTemporaryCredentials(any(String.class), any(String.class))).thenReturn(awsTemporaryCredentials, awsTemporaryCredentialsTwo);
        AWSCredentialsProviderImpl original = new AWSCredentialsProviderImpl(ztsClient, null, null);

        AWSCredentialsProviderImpl awsCredentialsProviderImpl = Mockito.spy(original);

        Assert.assertEquals(awsTemporaryCredentials.getAccessKeyId(), awsCredentialsProviderImpl.getCredentials().getAWSAccessKeyId());
        Mockito.verify(awsCredentialsProviderImpl, Mockito.times(1)).refresh();

        Assert.assertEquals(awsTemporaryCredentialsTwo.getAccessKeyId(), awsCredentialsProviderImpl.getCredentials().getAWSAccessKeyId());
        Mockito.verify(awsCredentialsProviderImpl, Mockito.times(2)).refresh();

        //null credentials are returned in case of exception
        Mockito.when(ztsClient.getAWSTemporaryCredentials(any(String.class), any(String.class))).thenThrow(new ResourceException(400));
        Assert.assertNull(awsCredentialsProviderImpl.getCredentials());
    }
}