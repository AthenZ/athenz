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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URISyntaxException;

import static org.testng.Assert.*;

public class AWSCredentialsProviderImplTest {

    final private Authority PRINCIPAL_AUTHORITY = new PrincipalAuthority();

    @BeforeClass
    public void init() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE, "false");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_X509CSR_DN, "ou=eng,o=athenz,c=us");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_X509CSR_DOMAIN, "athenz.cloud");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
    }

    @Test
    public void testAWSCredentialsProviderImplRefreshDisabled() {
        ZTSClient ztsClient = Mockito.mock(ZTSClient.class);
        AWSCredentialsProviderImpl.setAwsAutoRefreshEnable(false);
        AWSTemporaryCredentials awsTemporaryCredentials = new AWSTemporaryCredentials();
        awsTemporaryCredentials.setAccessKeyId("accessKey");
        awsTemporaryCredentials.setExpiration(Timestamp.fromCurrentTime());

        AWSTemporaryCredentials awsTemporaryCredentialsTwo = new AWSTemporaryCredentials();
        awsTemporaryCredentialsTwo.setAccessKeyId("accessKeyTwo");
        awsTemporaryCredentialsTwo.setExpiration(Timestamp.fromCurrentTime());

        //Check that get credentials calls refresh to get credentials from ZTS

        Mockito.when(ztsClient.getAWSTemporaryCredentials(Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(awsTemporaryCredentials, awsTemporaryCredentialsTwo);
        AWSCredentialsProviderImpl original = new AWSCredentialsProviderImpl(ztsClient, null, null);

        AWSCredentialsProviderImpl awsCredentialsProviderImpl = Mockito.spy(original);

        assertEquals(awsTemporaryCredentials.getAccessKeyId(), awsCredentialsProviderImpl.getCredentials().getAWSAccessKeyId());
        Mockito.verify(awsCredentialsProviderImpl, Mockito.times(1)).refresh();

        assertEquals(awsTemporaryCredentialsTwo.getAccessKeyId(), awsCredentialsProviderImpl.getCredentials().getAWSAccessKeyId());
        Mockito.verify(awsCredentialsProviderImpl, Mockito.times(2)).refresh();

        //null credentials are returned in case of exception
        Mockito.when(ztsClient.getAWSTemporaryCredentials(Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any())).thenThrow(new ResourceException(400));

        try {
            awsCredentialsProviderImpl.getCredentials();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testAWSCredentialsProviderImplRefreshEnabled() throws URISyntaxException, IOException {

        ZTSClient.setPrefetchAutoEnable(true);
        ZTSClient.AWS_CREDS_CACHE.clear();

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);

        ZTSClient ztsClient = new ZTSClientMock("https://zts.athenz", principal);
        ztsClient.setEnablePrefetch(true);

        AWSCredentialsProviderImpl.setAwsAutoRefreshEnable(true);

        AWSTemporaryCredentials awsTemporaryCredentials = new AWSTemporaryCredentials();
        awsTemporaryCredentials.setAccessKeyId("accessKey");
        awsTemporaryCredentials.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600 * 1000));

        AWSTemporaryCredentials awsTemporaryCredentialsTwo = new AWSTemporaryCredentials();
        awsTemporaryCredentialsTwo.setAccessKeyId("accessKeyTwo");
        awsTemporaryCredentialsTwo.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600 * 1000));

        // we're going to return two different creds from consecutive calls
        // however, our test is that because we add the entry to the cache
        // the second call should not take place unless the token is
        // considered expired

        ZTSRDLGeneratedClientMock rdlClient = Mockito.mock(ZTSRDLGeneratedClientMock.class);
        Mockito.when(rdlClient.getAWSTemporaryCredentials(Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any()))
                .thenReturn(awsTemporaryCredentials, awsTemporaryCredentialsTwo);

        ztsClient.setZTSRDLGeneratedClient(rdlClient);

        AWSCredentialsProviderImpl firstImpl = new AWSCredentialsProviderImpl(ztsClient,
                "athenz.aws", "s3role");

        // because we're going to cache the result

        assertEquals(awsTemporaryCredentials.getAccessKeyId(),
                firstImpl.getCredentials().getAWSAccessKeyId());

        assertEquals(awsTemporaryCredentials.getAccessKeyId(),
                firstImpl.getCredentials().getAWSAccessKeyId());

        // we're going to create another impl object which will call
        // the second refresh operation

        AWSCredentialsProviderImpl secondImpl = new AWSCredentialsProviderImpl(ztsClient,
                "athenz.aws", "s3role2");

        assertEquals(awsTemporaryCredentialsTwo.getAccessKeyId(),
                secondImpl.getCredentials().getAWSAccessKeyId());

        // exception handling

        Mockito.when(rdlClient.getAWSTemporaryCredentials(Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any())).thenThrow(new ResourceException(400));

        try {
             new AWSCredentialsProviderImpl(ztsClient, "athenz.aws", "s3role3");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
}
