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

import com.yahoo.athenz.zms.ResourceException;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import static org.testng.Assert.*;

public class AWSInstanceMetadataFetcherTest {
    public final static String AWS_INSTANCE_DOCUMENT = "{\n"
            + "  \"devpayProductCodes\" : null,\n"
            + "  \"availabilityZone\" : \"us-west-2a\",\n"
            + "  \"privateIp\" : \"10.10.10.10\",\n"
            + "  \"version\" : \"2010-08-31\",\n"
            + "  \"instanceId\" : \"i-056921225f1fbb47a\",\n"
            + "  \"billingProducts\" : null,\n"
            + "  \"instanceType\" : \"t2.micro\",\n"
            + "  \"accountId\" : \"111111111111\",\n"
            + "  \"pendingTime\" : \"2016-04-26T05:37:23Z\",\n"
            + "  \"imageId\" : \"ami-c229c0a2\",\n"
            + "  \"architecture\" : \"x86_64\",\n"
            + "  \"kernelId\" : null,\n"
            + "  \"ramdiskId\" : null,\n"
            + "  \"region\" : \"us-west-2\"\n"
            + "}";

    public final static String AWS_IAM_ROLE_INFO = "{\n"
            + "\"Code\" : \"Success\",\n"
            + "\"LastUpdated\" : \"2016-04-26T05:37:04Z\",\n"
            + "\"InstanceProfileArn\" : \"arn:aws:iam::111111111111:instance-profile/athenz.zts,athenz\",\n"
            + "\"InstanceProfileId\" : \"AIPAJAVNLUGEWFWTIDPRA\"\n"
            + "}";

    @Test
    public void testParseInstanceInfo() {
        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();

        assertTrue(awsInstanceMetadataFetcher.parseInstanceInfo(AWS_INSTANCE_DOCUMENT, true));
        assertEquals(awsInstanceMetadataFetcher.awsRegion, "us-west-2");
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseInstanceInfoInvalid() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        assertFalse(awsInstanceMetadataFetcher.parseInstanceInfo("some_invalid_doc", true));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseInstanceInfoRegion() {

        // first this should fail since we have no region
        // override and the document has no region

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        assertFalse(awsInstanceMetadataFetcher.parseInstanceInfo("{\"accountId\":\"012345678901\"}", true));

        // now we're going to use the same doc with override

        awsInstanceMetadataFetcher.close();

        awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        assertTrue(awsInstanceMetadataFetcher.parseInstanceInfo("{\"accountId\":\"012345678901\"}", false));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseIamRoleInfoInvalid() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        assertFalse(awsInstanceMetadataFetcher.parseIamRoleInfo("some_invalid_doc"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseIamRoleInfoMissingInstanceProfile() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        assertFalse(awsInstanceMetadataFetcher.parseIamRoleInfo("{\"accountId\":\"012345678901\"}"));
        assertFalse(awsInstanceMetadataFetcher.parseIamRoleInfo("{\"accountId\":\"012345678901\",\"InstanceProfileArn\":\"\"}"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseIamRoleInfoInvalidInstanceProfile() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        assertFalse(awsInstanceMetadataFetcher.parseIamRoleInfo("{\"accountId\":\"012345678901\"}"));
        assertFalse(awsInstanceMetadataFetcher.parseIamRoleInfo("{\"accountId\":\"012345678901\",\"InstanceProfileArn\":\"invalid\"}"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseIamRoleInfo() {
        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        assertTrue(awsInstanceMetadataFetcher.parseIamRoleInfo(AWS_IAM_ROLE_INFO));
        assertEquals(awsInstanceMetadataFetcher.awsRole, "athenz.zts");
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseInstanceProfileArn() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        assertTrue(awsInstanceMetadataFetcher.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/athenz.zts,athenz"));
        assertEquals(awsInstanceMetadataFetcher.awsRole, "athenz.zts");
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseInstanceProfileArnInvalidPrefix() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();

        // invalid starting prefix

        assertFalse(awsInstanceMetadataFetcher.parseInstanceProfileArn("arn:aws:iam:111111111111:instance-profile/athenz.zts,athenz"));
        assertFalse(awsInstanceMetadataFetcher.parseInstanceProfileArn("arn:aws:iam2:111111111111:instance-profile/athenz.zts,athenz"));
        assertFalse(awsInstanceMetadataFetcher.parseInstanceProfileArn("instance-profile/athenz.zts,athenz"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseInstanceProfileArnInvalidProfile() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();

        // missing instance-profile part

        assertFalse(awsInstanceMetadataFetcher.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile2/athenz.zts,athenz"));
        assertFalse(awsInstanceMetadataFetcher.parseInstanceProfileArn("arn:aws:iam::111111111111:instance/athenz.zts,athenz"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseInstanceProfileArnInvalidNoProfile() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();

        // no profile name

        assertFalse(awsInstanceMetadataFetcher.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testParseInstanceProfileArnCloud() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        // cloud name is optional for backwards compatibility
        assertTrue(awsInstanceMetadataFetcher.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/athenz.zts"));
        assertEquals(awsInstanceMetadataFetcher.awsRole, "athenz.zts");
        assertTrue(awsInstanceMetadataFetcher.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/athenz.proxy,athenz,test"));
        assertEquals(awsInstanceMetadataFetcher.awsRole, "athenz.proxy");
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testGetMetaDataExceptions() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/exc1")).thenThrow(InterruptedException.class);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/exc2")).thenThrow(ExecutionException.class);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/exc3")).thenThrow(TimeoutException.class);

        assertNull(awsInstanceMetadataFetcher.getMetaData("/exc1"));
        assertNull(awsInstanceMetadataFetcher.getMetaData("/exc2"));
        assertNull(awsInstanceMetadataFetcher.getMetaData("/exc3"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testGetMetaDataFailureStatus() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(404);
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/iam-info")).thenReturn(response);

        assertNull(awsInstanceMetadataFetcher.getMetaData("/iam-info"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testGetMetaDataNullResponse() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn(null);
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/iam-info")).thenReturn(response);

        assertNull(awsInstanceMetadataFetcher.getMetaData("/iam-info"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testGetMetaDataEmptyResponse() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("");
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/iam-info")).thenReturn(response);

        assertNull(awsInstanceMetadataFetcher.getMetaData("/iam-info"));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testGetMetaDataValidResponse() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("json-document");
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/iam-info")).thenReturn(response);

        assertEquals(awsInstanceMetadataFetcher.getMetaData("/iam-info"), "json-document");
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidDocumentGet() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(404);
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(response);

        assertFalse(awsInstanceMetadataFetcher.loadBootMetaData(true));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidDocumentParse() throws InterruptedException, ExecutionException, TimeoutException {

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("{\"accountId\":\"012345678901\"}");
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(response);

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        assertFalse(awsInstanceMetadataFetcher.loadBootMetaData(true));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidDocumentException() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("json-document");
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(response);

        assertFalse(awsInstanceMetadataFetcher.loadBootMetaData(true));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidSignature() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(404);

        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(responseDoc);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")).thenReturn(responseSig);

        assertFalse(awsInstanceMetadataFetcher.loadBootMetaData(true));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidIamInfoGet() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(404);

        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(responseDoc);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")).thenReturn(responseSig);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/info")).thenReturn(responseInfo);

        assertFalse(awsInstanceMetadataFetcher.loadBootMetaData(true));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidIamInfoException() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(200);
        Mockito.when(responseInfo.getContentAsString()).thenReturn("invalid-info");

        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(responseDoc);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")).thenReturn(responseSig);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/info")).thenReturn(responseInfo);

        assertFalse(awsInstanceMetadataFetcher.loadBootMetaData(true));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidIamInfoParse() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(200);
        Mockito.when(responseInfo.getContentAsString()).thenReturn("{\"accountId\":\"012345678901\",\"InstanceProfileArn\":\"invalid\"}");

        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(responseDoc);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")).thenReturn(responseSig);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/info")).thenReturn(responseInfo);

        assertFalse(awsInstanceMetadataFetcher.loadBootMetaData(true));
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testLoadBootMetaData() throws InterruptedException, ExecutionException, TimeoutException {

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(200);
        Mockito.when(responseInfo.getContentAsString()).thenReturn(AWS_IAM_ROLE_INFO);

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(responseDoc);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")).thenReturn(responseSig);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/info")).thenReturn(responseInfo);

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        awsInstanceMetadataFetcher.setHttpClient(httpClient);

        assertTrue(awsInstanceMetadataFetcher.loadBootMetaData(true));
        assertEquals(awsInstanceMetadataFetcher.awsRole, "athenz.zts");
        assertEquals(awsInstanceMetadataFetcher.awsRegion, "us-west-2");
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testFetchRoleCredentialsNoRole() {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();

        awsInstanceMetadataFetcher.awsRole = null;
        assertNull(awsInstanceMetadataFetcher.fetchRoleCredentials());

        awsInstanceMetadataFetcher.awsRole = "";
        assertNull(awsInstanceMetadataFetcher.fetchRoleCredentials());
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testFetchRoleCredentialsNoCreds() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        awsInstanceMetadataFetcher.awsRole = "athenz.zts";

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(404);
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")).thenReturn(response);

        assertNull(awsInstanceMetadataFetcher.fetchRoleCredentials());
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testFetchRoleCredentialInvalidCreds() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        awsInstanceMetadataFetcher.awsRole = "athenz.zts";

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("invalid-creds");

        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")).thenReturn(response);

        assertNull(awsInstanceMetadataFetcher.fetchRoleCredentials());
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testFetchRoleCredential() throws InterruptedException, ExecutionException, TimeoutException {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        awsInstanceMetadataFetcher.awsRole = "athenz.zts";

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("{\"AccessKeyId\":\"id\",\"SecretAccessKey\":\"key\",\"Token\":\"token\"}");

        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")).thenReturn(response);

        assertNotNull(awsInstanceMetadataFetcher.fetchRoleCredentials());
        awsInstanceMetadataFetcher.close();
    }

    @Test
    public void testSetupHttpClient() throws Exception {

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        HttpClient client = Mockito.mock(HttpClient.class);
        Mockito.doThrow(new Exception("Invalid client")).when(client).start();

        try {
            awsInstanceMetadataFetcher.setupHttpClient(client);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
    }

}
