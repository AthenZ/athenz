/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class AWSCredentialsProviderImplV2Test {

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
    public void testAWSCredentialsProviderImplV2RefreshDisabled() {
        ZTSClient ztsClient = Mockito.mock(ZTSClient.class);
        AWSCredentialsProviderImplV2.setAwsAutoRefreshEnable(false);
        AWSTemporaryCredentials awsTemporaryCredentials = new AWSTemporaryCredentials();
        awsTemporaryCredentials.setAccessKeyId("accessKey");
        awsTemporaryCredentials.setExpiration(Timestamp.fromCurrentTime());

        AWSTemporaryCredentials awsTemporaryCredentialsTwo = new AWSTemporaryCredentials();
        awsTemporaryCredentialsTwo.setAccessKeyId("accessKeyTwo");
        awsTemporaryCredentialsTwo.setExpiration(Timestamp.fromCurrentTime());

        Mockito.when(ztsClient.getAWSTemporaryCredentials(Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(awsTemporaryCredentials, awsTemporaryCredentials, awsTemporaryCredentials, awsTemporaryCredentialsTwo);
        AWSCredentialsProviderImplV2 original = new AWSCredentialsProviderImplV2(ztsClient, null, null);

        AWSCredentialsProviderImplV2 awsCredentialsProviderImplV2 = Mockito.spy(original);

        // In AWS SDK2, secretKey must not be null
        try {
            awsCredentialsProviderImplV2.resolveCredentials();
            fail();
        } catch (NullPointerException ex) {
            assertEquals(ex.getMessage(), "secretKey must not be null.");
        }

        awsTemporaryCredentials.setSecretAccessKey("secretKey");
        awsTemporaryCredentialsTwo.setSecretAccessKey("secretKeyTwo");

        // In AWS SDK2, sessionToken must not be null
        try {
            awsCredentialsProviderImplV2.resolveCredentials();
            fail();
        } catch (NullPointerException ex) {
            assertEquals(ex.getMessage(), "sessionToken must not be null.");
        }

        awsTemporaryCredentials.setSessionToken("sessionToken");
        awsTemporaryCredentialsTwo.setSessionToken("sessionTokenTwo");

        //Check that get credentials calls refresh to get credentials from ZTS

        assertEquals(awsTemporaryCredentials.getAccessKeyId(), awsCredentialsProviderImplV2.resolveCredentials().accessKeyId());
        Mockito.verify(awsCredentialsProviderImplV2, Mockito.times(3)).refresh();

        assertEquals(awsTemporaryCredentialsTwo.getAccessKeyId(), awsCredentialsProviderImplV2.resolveCredentials().accessKeyId());
        Mockito.verify(awsCredentialsProviderImplV2, Mockito.times(4)).refresh();

        //null credentials are returned in case of exception
        Mockito.when(ztsClient.getAWSTemporaryCredentials(Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any())).thenThrow(new ResourceException(400));

        try {
            awsCredentialsProviderImplV2.resolveCredentials();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testAWSCredentialsProviderImplV2RefreshEnabled() throws URISyntaxException, IOException {

        ZTSClient.setPrefetchAutoEnable(true);
        ZTSClient.AWS_CREDS_CACHE.clear();

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);

        ZTSClient ztsClient = new ZTSClientMock("https://zts.athenz", principal);
        ztsClient.setEnablePrefetch(true);

        AWSCredentialsProviderImplV2.setAwsAutoRefreshEnable(true);

        AWSTemporaryCredentials awsTemporaryCredentials = new AWSTemporaryCredentials();
        awsTemporaryCredentials.setAccessKeyId("accessKey");
        awsTemporaryCredentials.setSecretAccessKey("secretKey");
        awsTemporaryCredentials.setSessionToken("sesstionToken");
        awsTemporaryCredentials.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600 * 1000));

        AWSTemporaryCredentials awsTemporaryCredentialsTwo = new AWSTemporaryCredentials();
        awsTemporaryCredentialsTwo.setAccessKeyId("accessKeyTwo");
        awsTemporaryCredentialsTwo.setSecretAccessKey("secretKeyTwo");
        awsTemporaryCredentialsTwo.setSessionToken("sesstionTokenTwo");
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

        AWSCredentialsProviderImplV2 firstImpl = new AWSCredentialsProviderImplV2(ztsClient,
                "athenz.aws", "s3role");

        // because we're going to cache the result

        assertEquals(awsTemporaryCredentials.getAccessKeyId(),
                firstImpl.resolveCredentials().accessKeyId());

        assertEquals(awsTemporaryCredentials.getAccessKeyId(),
                firstImpl.resolveCredentials().accessKeyId());

        // we're going to create another impl object which will call
        // the second refresh operation

        AWSCredentialsProviderImplV2 secondImpl = new AWSCredentialsProviderImplV2(ztsClient,
                "athenz.aws", "s3role2");

        assertEquals(awsTemporaryCredentialsTwo.getAccessKeyId(),
                secondImpl.resolveCredentials().accessKeyId());

        // exception handling

        Mockito.when(rdlClient.getAWSTemporaryCredentials(Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any())).thenThrow(new ResourceException(400));

        try {
             new AWSCredentialsProviderImplV2(ztsClient, "athenz.aws", "s3role3");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
}
