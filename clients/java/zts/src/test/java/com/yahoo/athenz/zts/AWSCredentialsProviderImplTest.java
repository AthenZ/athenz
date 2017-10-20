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
    public void testAWSCredentialsProviderImpl() throws Exception {
        ZTSClient ztsClient = Mockito.mock(ZTSClient.class);
        AWSTemporaryCredentials awsTemporaryCredentials = new AWSTemporaryCredentials();
        awsTemporaryCredentials.setAccessKeyId("accessKey");

        AWSTemporaryCredentials awsTemporaryCredentialsTwo = new AWSTemporaryCredentials();
        awsTemporaryCredentialsTwo.setAccessKeyId("accessKeyTwo");


        //Check that get credentials calls refresh to get credentials from ZTS

        Mockito.when(ztsClient.getAWSTemporaryCredentials(Mockito.<String>any(), Mockito.<String>any())).thenReturn(awsTemporaryCredentials, awsTemporaryCredentialsTwo);
        AWSCredentialsProviderImpl original = new AWSCredentialsProviderImpl(ztsClient, null, null);

        AWSCredentialsProviderImpl awsCredentialsProviderImpl = Mockito.spy(original);

        Assert.assertEquals(awsTemporaryCredentials.getAccessKeyId(), awsCredentialsProviderImpl.getCredentials().getAWSAccessKeyId());
        Mockito.verify(awsCredentialsProviderImpl, Mockito.times(1)).refresh();

        Assert.assertEquals(awsTemporaryCredentialsTwo.getAccessKeyId(), awsCredentialsProviderImpl.getCredentials().getAWSAccessKeyId());
        Mockito.verify(awsCredentialsProviderImpl, Mockito.times(2)).refresh();

        //null credentials are returned in case of exception
        Mockito.when(ztsClient.getAWSTemporaryCredentials(Mockito.<String>any(), Mockito.<String>any())).thenThrow(new ResourceException(400));
        Assert.assertNull(awsCredentialsProviderImpl.getCredentials());
    }
}