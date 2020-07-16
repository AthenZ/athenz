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

import com.amazonaws.auth.AWSCredentials;
import com.yahoo.athenz.zms.ResourceException;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import static com.yahoo.athenz.common.server.store.AWSInstanceMetadataFetcherTest.AWS_IAM_ROLE_INFO;
import static com.yahoo.athenz.common.server.store.AWSInstanceMetadataFetcherTest.AWS_INSTANCE_DOCUMENT;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class AWSCredentialsRefresherTest {
    @Test
    public void testAWSCredentialsUpdaterExceptions () {

        AWSCredentialsRefresher awsCredentialsRefresher = Mockito.mock(AWSCredentialsRefresher.class);

        // we're going to test exceptions from three components
        // and make sure our run does not throw any

        // first operation - all return true
        // second operation - fetchRoleCredentials throws exception
        // third operation - removeExpiredCredentials throws exception
        // forth opreation - removeExpiredInvalidCredentials throws exception

        AWSCredentials credentials = Mockito.mock(AWSCredentials.class);
        Mockito.when(awsCredentialsRefresher.getCredentials())
                .thenReturn(credentials)
                .thenThrow(new NullPointerException("invalid state"))
                .thenReturn(credentials)
                .thenReturn(credentials);

        AWSCredentialsRefresher.AWSCredentialsRefreshTask updater = awsCredentialsRefresher.new AWSCredentialsRefreshTask();
        updater.run();
        updater.run();
        updater.run();
        updater.run();
    }

    @Test
    public void testInitializeAwsSupportInvalidCreds()  throws InterruptedException, ExecutionException, TimeoutException {

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(200);
        Mockito.when(responseInfo.getContentAsString()).thenReturn(AWS_IAM_ROLE_INFO);

        ContentResponse responseCreds = Mockito.mock(ContentResponse.class);
        Mockito.when(responseCreds.getStatus()).thenReturn(200);
        Mockito.when(responseCreds.getContentAsString()).thenReturn("invalid-creds");

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(responseDoc);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")).thenReturn(responseSig);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/info")).thenReturn(responseInfo);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")).thenReturn(responseCreds);

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        awsInstanceMetadataFetcher.setHttpClient(httpClient);

        try {
            new AWSCredentialsRefresher(awsInstanceMetadataFetcher);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testInitializeAwsSupportInvalidDocument()  throws InterruptedException, ExecutionException, TimeoutException {

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn("invalid-document");
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(responseDoc);

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        awsInstanceMetadataFetcher.setHttpClient(httpClient);

        try {
            new AWSCredentialsRefresher(awsInstanceMetadataFetcher);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        awsInstanceMetadataFetcher.close();
    }
}
