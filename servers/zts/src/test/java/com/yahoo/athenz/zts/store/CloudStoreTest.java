/*
 *  Copyright The Athenz Authors
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

package com.yahoo.athenz.zts.store;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_PUBLIC_CERT;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_REGION_NAME;
import static org.testng.Assert.*;

import java.net.URI;
import java.util.Date;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.ContentResponse;
import org.eclipse.jetty.client.Request;
import org.eclipse.jetty.http.HttpMethod;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;

public class CloudStoreTest {

    private final static String AWS_INSTANCE_DOCUMENT = "{\n"
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

    private final static String AWS_IAM_ROLE_INFO = "{\n"
            + "\"Code\" : \"Success\",\n"
            + "\"LastUpdated\" : \"2016-04-26T05:37:04Z\",\n"
            + "\"InstanceProfileArn\" : \"arn:aws:iam::111111111111:instance-profile/athenz.zts,athenz\",\n"
            + "\"InstanceProfileId\" : \"AIPAJAVNLUGEWFWTIDPRA\"\n"
            + "}";

    @Test
    public void testGetS3ClientNullCreds() {
        CloudStore store = new CloudStore();
        store.awsEnabled = true;
        store.credentials = null;
        try {
            store.getS3Client();
            fail();
        } catch (ResourceException ex) {
            assertEquals(500, ex.getCode());
        }
        store.close();
    }

    @Test
    public void testGetS3ClientAWSNotEnabled() {
        CloudStore store = new CloudStore();
        store.credentials = null;
        try {
            store.getS3Client();
            fail();
        } catch (ResourceException ex) {
            assertEquals(500, ex.getCode());
        }
        store.close();
    }

    @Test
    public void testGetS3Client() {

        System.setProperty(ZTS_PROP_AWS_PUBLIC_CERT, "src/test/resources/aws_public.crt");
        CloudStore store = new CloudStore();
        store.credentials = new BasicSessionCredentials("accessKey", "secretKey", "token");
        store.awsEnabled = true;
        store.awsRegion = "us-west-2";
        assertNotNull(store.getS3Client());

        assertNotNull(store.getS3Client());
        store.close();
    }

    @Test
    public void testGetTokenServiceClient() {
        CloudStore store = new CloudStore();
        store.credentials = new BasicSessionCredentials("accessKey", "secretKey", "token");
        store.awsEnabled = true;
        store.awsRegion = "us-west-2";
        assertNotNull(store.getTokenServiceClient());
        store.close();
    }

    @Test
    public void testUpdateAccountUpdate() {

        CloudStore store = new CloudStore();
        assertNull(store.getAwsAccount("iaas"));

        // set the account to 1234

        store.updateAwsAccount("iaas", "1234");
        assertEquals("1234", store.getAwsAccount("iaas"));

        // update the account value

        store.updateAwsAccount("iaas", "1235");
        assertEquals("1235", store.getAwsAccount("iaas"));
        store.close();
    }

    @Test
    public void testUpdateAccountDelete() {

        CloudStore store = new CloudStore();

        // set the account to 1234

        store.updateAwsAccount("iaas", "1234");
        assertEquals("1234", store.getAwsAccount("iaas"));

        // delete the account with null

        store.updateAwsAccount("iaas", null);
        assertNull(store.getAwsAccount("iaas"));

        // update the account value

        store.updateAwsAccount("iaas", "1235");
        assertEquals("1235", store.getAwsAccount("iaas"));

        // delete the account with empty string

        store.updateAwsAccount("iaas", "");
        assertNull(store.getAwsAccount("iaas"));
        store.close();
    }

    @Test
    public void testGetAssumeRoleRequest() {

        CloudStore store = new CloudStore();
        AssumeRoleRequest req = store.getAssumeRoleRequest("1234", "admin", null, null, "athenz.api");
        assertEquals("arn:aws:iam::1234:role/admin", req.getRoleArn());
        assertEquals("athenz.api", req.getRoleSessionName());
        assertNull(req.getDurationSeconds());
        assertNull(req.getExternalId());

        req = store.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api");
        assertEquals("arn:aws:iam::12345:role/adminuser", req.getRoleArn());
        assertEquals("athenz.api", req.getRoleSessionName());
        assertEquals(Integer.valueOf(101), req.getDurationSeconds());
        assertEquals("external", req.getExternalId());

        req = store.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api-service");
        assertEquals("arn:aws:iam::12345:role/adminuser", req.getRoleArn());
        assertEquals("athenz.api-service", req.getRoleSessionName());
        assertEquals(Integer.valueOf(101), req.getDurationSeconds());
        assertEquals("external", req.getExternalId());

        req = store.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api_service-test");
        assertEquals("arn:aws:iam::12345:role/adminuser", req.getRoleArn());
        assertEquals("athenz.api_service-test", req.getRoleSessionName());
        assertEquals(Integer.valueOf(101), req.getDurationSeconds());
        assertEquals("external", req.getExternalId());

        final String principalLongerThan64Chars = "athenz.environment.production.regions.us-west-2.services.zts-service";
        req = store.getAssumeRoleRequest("12345", "adminuser", 101, "external", principalLongerThan64Chars);
        assertEquals("arn:aws:iam::12345:role/adminuser", req.getRoleArn());
        assertEquals("athenz.environment.production....us-west-2.services.zts-service", req.getRoleSessionName());
        assertEquals(Integer.valueOf(101), req.getDurationSeconds());
        assertEquals("external", req.getExternalId());
        store.close();

        System.setProperty(ZTSConsts.ZTS_PROP_AWS_ROLE_SESSION_NAME, "athenz-zts-service");
        store = new CloudStore();
        req = store.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api-service");
        assertEquals("arn:aws:iam::12345:role/adminuser", req.getRoleArn());
        assertEquals("athenz-zts-service", req.getRoleSessionName());
        assertEquals(Integer.valueOf(101), req.getDurationSeconds());
        assertEquals("external", req.getExternalId());
        store.close();
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_ROLE_SESSION_NAME);
    }

    @Test
    public void testParseInstanceInfo() {
        CloudStore store = new CloudStore();
        assertTrue(store.parseInstanceInfo(AWS_INSTANCE_DOCUMENT));
        assertEquals(store.awsRegion, "us-west-2");
        store.close();
    }

    @Test
    public void testParseInstanceInfoInvalid() {

        CloudStore store = new CloudStore();
        assertFalse(store.parseInstanceInfo("some_invalid_doc"));
        store.close();
    }

    @Test
    public void testParseInstanceInfoRegion() {

        // first this should fail since we have no region
        // override and the document has no region

        CloudStore store = new CloudStore();
        assertFalse(store.parseInstanceInfo("{\"accountId\":\"012345678901\"}"));

        // now we're going to use the same doc with override

        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "us-west-3");
        store.close();

        store = new CloudStore();
        assertTrue(store.parseInstanceInfo("{\"accountId\":\"012345678901\"}"));
        assertEquals(store.awsRegion, "us-west-3");
        System.clearProperty(ZTS_PROP_AWS_REGION_NAME);
        store.close();
    }

    @Test
    public void testParseIamRoleInfoInvalid() {

        CloudStore store = new CloudStore();
        assertFalse(store.parseIamRoleInfo("some_invalid_doc"));
        store.close();
    }

    @Test
    public void testParseIamRoleInfoMissingInstanceProfile() {

        CloudStore store = new CloudStore();
        assertFalse(store.parseIamRoleInfo("{\"accountId\":\"012345678901\"}"));
        assertFalse(store.parseIamRoleInfo("{\"accountId\":\"012345678901\",\"InstanceProfileArn\":\"\"}"));
        store.close();
    }

    @Test
    public void testParseIamRoleInfoInvalidInstanceProfile() {

        CloudStore store = new CloudStore();
        assertFalse(store.parseIamRoleInfo("{\"accountId\":\"012345678901\"}"));
        assertFalse(store.parseIamRoleInfo("{\"accountId\":\"012345678901\",\"InstanceProfileArn\":\"invalid\"}"));
        store.close();
    }

    @Test
    public void testParseIamRoleInfo() {
        CloudStore store = new CloudStore();
        assertTrue(store.parseIamRoleInfo(AWS_IAM_ROLE_INFO));
        assertEquals(store.awsRole, "athenz.zts");
        store.close();
    }

    @Test
    public void testParseInstanceProfileArn() {

        CloudStore store = new CloudStore();
        assertTrue(store.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/athenz.zts,athenz"));
        assertEquals(store.awsRole, "athenz.zts");
        store.close();
    }

    @Test
    public void testParseInstanceProfileArnInvalidPrefix() {

        CloudStore store = new CloudStore();

        // invalid starting prefix

        assertFalse(store.parseInstanceProfileArn("arn:aws:iam:111111111111:instance-profile/athenz.zts,athenz"));
        assertFalse(store.parseInstanceProfileArn("arn:aws:iam2:111111111111:instance-profile/athenz.zts,athenz"));
        assertFalse(store.parseInstanceProfileArn("instance-profile/athenz.zts,athenz"));
        store.close();
    }

    @Test
    public void testParseInstanceProfileArnInvalidProfile() {

        CloudStore store = new CloudStore();

        // missing instance-profile part

        assertFalse(store.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile2/athenz.zts,athenz"));
        assertFalse(store.parseInstanceProfileArn("arn:aws:iam::111111111111:instance/athenz.zts,athenz"));
        store.close();
    }

    @Test
    public void testParseInstanceProfileArnInvalidNoProfile() {

        CloudStore store = new CloudStore();

        // no profile name

        assertFalse(store.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/"));
        store.close();
    }

    @Test
    public void testParseInstanceProfileArnCloud() {

        CloudStore store = new CloudStore();
        // cloud name is optional for backwards compatibility
        assertTrue(store.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/athenz.zts"));
        assertEquals(store.awsRole, "athenz.zts");
        assertTrue(store.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/athenz.proxy,athenz,test"));
        assertEquals(store.awsRole, "athenz.proxy");
        store.close();
    }

    @Test
    public void testGetMetaDataExceptions() throws Exception {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        store.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/exc1")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenThrow(TimeoutException.class);
        Mockito.doThrow(new IndexOutOfBoundsException()).when(httpClient).stop();

        assertNull(store.getMetaData("/exc1"));
        store.close();
    }

    @Test
    public void testGetMetaDataFailureStatus() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(404);
        store.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/iam-info")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertNull(store.getMetaData("/iam-info"));
        store.close();
    }

    @Test
    public void testGetMetaDataNullResponse() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn(null);
        store.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/iam-info")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertNull(store.getMetaData("/iam-info"));
        store.close();
    }

    @Test
    public void testGetMetaDataEmptyResponse() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("");
        store.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/iam-info")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertNull(store.getMetaData("/iam-info"));
        store.close();
    }

    @Test
    public void testGetMetaDataValidResponse() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("json-document");
        store.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/iam-info")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertEquals(store.getMetaData("/iam-info"), "json-document");
        store.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidDocumentGet() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(404);
        store.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertFalse(store.loadBootMetaData());
        store.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidDocumentParse() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("{\"accountId\":\"012345678901\"}");
        store.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertFalse(store.loadBootMetaData());
        store.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidDocumentException() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("json-document");
        store.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertFalse(store.loadBootMetaData());
        store.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidSignature() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(404);

        store.setHttpClient(httpClient);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        Request sigRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")))
                .thenReturn(sigRequest);
        Mockito.when(sigRequest.method(HttpMethod.GET)).thenReturn(sigRequest);
        Mockito.when(sigRequest.send()).thenReturn(responseSig);

        assertFalse(store.loadBootMetaData());
        store.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidIamInfoGet() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(404);

        store.setHttpClient(httpClient);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        Request sigRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")))
                .thenReturn(sigRequest);
        Mockito.when(sigRequest.method(HttpMethod.GET)).thenReturn(sigRequest);
        Mockito.when(sigRequest.send()).thenReturn(responseSig);

        Request infoRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/info")))
                .thenReturn(infoRequest);
        Mockito.when(infoRequest.method(HttpMethod.GET)).thenReturn(infoRequest);
        Mockito.when(infoRequest.send()).thenReturn(responseInfo);

        assertFalse(store.loadBootMetaData());
        store.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidIamInfoException() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
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

        store.setHttpClient(httpClient);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        Request sigRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")))
                .thenReturn(sigRequest);
        Mockito.when(sigRequest.method(HttpMethod.GET)).thenReturn(sigRequest);
        Mockito.when(sigRequest.send()).thenReturn(responseSig);

        Request infoRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/info")))
                .thenReturn(infoRequest);
        Mockito.when(infoRequest.method(HttpMethod.GET)).thenReturn(infoRequest);
        Mockito.when(infoRequest.send()).thenReturn(responseInfo);

        assertFalse(store.loadBootMetaData());
        store.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidIamInfoParse() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
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

        store.setHttpClient(httpClient);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        Request sigRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")))
                .thenReturn(sigRequest);
        Mockito.when(sigRequest.method(HttpMethod.GET)).thenReturn(sigRequest);
        Mockito.when(sigRequest.send()).thenReturn(responseSig);

        Request infoRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/info")))
                .thenReturn(infoRequest);
        Mockito.when(infoRequest.method(HttpMethod.GET)).thenReturn(infoRequest);
        Mockito.when(infoRequest.send()).thenReturn(responseInfo);

        assertFalse(store.loadBootMetaData());
        store.close();
    }

    @Test
    public void testLoadBootMetaDataV1() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(200);
        Mockito.when(responseInfo.getContentAsString()).thenReturn(AWS_IAM_ROLE_INFO);

        store.setHttpClient(httpClient);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        Request sigRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")))
                .thenReturn(sigRequest);
        Mockito.when(sigRequest.method(HttpMethod.GET)).thenReturn(sigRequest);
        Mockito.when(sigRequest.send()).thenReturn(responseSig);

        Request infoRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/info")))
                .thenReturn(infoRequest);
        Mockito.when(infoRequest.method(HttpMethod.GET)).thenReturn(infoRequest);
        Mockito.when(infoRequest.send()).thenReturn(responseInfo);

        assertTrue(store.loadBootMetaData());
        assertEquals(store.awsRole, "athenz.zts");
        assertEquals(store.awsRegion, "us-west-2");
        store.close();
    }

    @Test
    public void testLoadBootMetaDataV2() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(200);
        Mockito.when(responseInfo.getContentAsString()).thenReturn(AWS_IAM_ROLE_INFO);

        ContentResponse responseToken = Mockito.mock(ContentResponse.class);
        Mockito.when(responseToken.getStatus()).thenReturn(200);
        Mockito.when(responseToken.getContentAsString()).thenReturn("aws-token-info");

        store.setHttpClient(httpClient);

        Request tokenRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/api/token")))
                .thenReturn(tokenRequest);
        Mockito.when(tokenRequest.method(HttpMethod.PUT)).thenReturn(tokenRequest);
        Mockito.when(tokenRequest.send()).thenReturn(responseToken);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        Request sigRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")))
                .thenReturn(sigRequest);
        Mockito.when(sigRequest.method(HttpMethod.GET)).thenReturn(sigRequest);
        Mockito.when(sigRequest.send()).thenReturn(responseSig);

        Request infoRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/info")))
                .thenReturn(infoRequest);
        Mockito.when(infoRequest.method(HttpMethod.GET)).thenReturn(infoRequest);
        Mockito.when(infoRequest.send()).thenReturn(responseInfo);

        assertTrue(store.loadBootMetaData());
        assertEquals(store.awsRole, "athenz.zts");
        assertEquals(store.awsRegion, "us-west-2");
        store.close();
    }

    @Test
    public void testFetchRoleCredentialsNoRole() {

        CloudStore store = new CloudStore();

        store.awsRole = null;
        assertFalse(store.fetchRoleCredentials());

        store.awsRole = "";
        assertFalse(store.fetchRoleCredentials());
        store.close();
    }

    @Test
    public void testFetchRoleCredentialsNoCreds() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        store.awsRole = "athenz.zts";

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(404);
        store.setHttpClient(httpClient);

        Request credsRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")))
                .thenReturn(credsRequest);
        Mockito.when(credsRequest.method(HttpMethod.GET)).thenReturn(credsRequest);
        Mockito.when(credsRequest.send()).thenReturn(response);

        assertFalse(store.fetchRoleCredentials());
        store.close();
    }

    @Test
    public void testFetchRoleCredentialInvalidCreds() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        store.awsRole = "athenz.zts";

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("invalid-creds");

        store.setHttpClient(httpClient);

        Request credsRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")))
                .thenReturn(credsRequest);
        Mockito.when(credsRequest.method(HttpMethod.GET)).thenReturn(credsRequest);
        Mockito.when(credsRequest.send()).thenReturn(response);

        assertFalse(store.fetchRoleCredentials());
        store.close();
    }

    @Test
    public void testFetchRoleCredential() throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        store.awsRole = "athenz.zts";

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("{\"AccessKeyId\":\"id\",\"SecretAccessKey\":\"key\",\"Token\":\"token\"}");

        store.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertTrue(store.fetchRoleCredentials());
        store.close();
    }

    @Test
    public void testInitializeAwsSupportInvalidDocument()  throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn("invalid-document");

        store.setHttpClient(httpClient);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        try {
            store.awsEnabled = true;
            store.initializeAwsSupport();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        store.close();
    }

    @Test
    public void testInitializeAwsSupportInvalidCreds()  throws InterruptedException, ExecutionException, TimeoutException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

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

        store.setHttpClient(httpClient);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        Request sigRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")))
                .thenReturn(sigRequest);
        Mockito.when(sigRequest.method(HttpMethod.GET)).thenReturn(sigRequest);
        Mockito.when(sigRequest.send()).thenReturn(responseSig);

        Request infoRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/info")))
                .thenReturn(infoRequest);
        Mockito.when(infoRequest.method(HttpMethod.GET)).thenReturn(infoRequest);
        Mockito.when(infoRequest.send()).thenReturn(responseInfo);

        Request credsRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")))
                .thenReturn(credsRequest);
        Mockito.when(credsRequest.method(HttpMethod.GET)).thenReturn(credsRequest);
        Mockito.when(credsRequest.send()).thenReturn(responseCreds);

        try {
            store.awsEnabled = true;
            store.initializeAwsSupport();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        store.close();
    }

    @Test
    public void testInitializeAwsSupport() throws ExecutionException, TimeoutException, InterruptedException {

        CloudStore store = new CloudStore();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

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
        Mockito.when(responseCreds.getContentAsString()).thenReturn("{\"AccessKeyId\":\"id\",\"SecretAccessKey\":\"key\",\"Token\":\"token\"}");

        store.setHttpClient(httpClient);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        Request sigRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")))
                .thenReturn(sigRequest);
        Mockito.when(sigRequest.method(HttpMethod.GET)).thenReturn(sigRequest);
        Mockito.when(sigRequest.send()).thenReturn(responseSig);

        Request infoRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/info")))
                .thenReturn(infoRequest);
        Mockito.when(infoRequest.method(HttpMethod.GET)).thenReturn(infoRequest);
        Mockito.when(infoRequest.send()).thenReturn(responseInfo);

        Request credsRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")))
                .thenReturn(credsRequest);
        Mockito.when(credsRequest.method(HttpMethod.GET)).thenReturn(credsRequest);
        Mockito.when(credsRequest.send()).thenReturn(responseCreds);

        // set creds update time every second

        System.setProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT, "1");

        store.awsEnabled = true;
        store.initializeAwsSupport();

        // sleep a couple of seconds for the background thread to run
        // before we try to shutting it down

        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }
        store.close();

        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT);
    }

    @Test
    public void testAssumeAWSRoleAWSNotEnabled() {
        CloudStore cloudStore = new CloudStore();
        try {
            StringBuilder errorMessage = new StringBuilder();
            cloudStore.assumeAWSRole("account", "sycner", "athenz.syncer", null, null, errorMessage);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        cloudStore.close();
    }

    @Test
    public void testAssumeAWSRole() {
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.awsEnabled = true;
        AssumeRoleResult mockResult = Mockito.mock(AssumeRoleResult.class);
        Credentials creds = Mockito.mock(Credentials.class);
        Mockito.when(creds.getAccessKeyId()).thenReturn("accesskeyid");
        Mockito.when(creds.getSecretAccessKey()).thenReturn("secretaccesskey");
        Mockito.when(creds.getSessionToken()).thenReturn("sessiontoken");
        Mockito.when(creds.getExpiration()).thenReturn(new Date());
        Mockito.when(mockResult.getCredentials()).thenReturn(creds);
        cloudStore.setAssumeRoleResult(mockResult);
        cloudStore.setReturnSuperAWSRole(true);

        StringBuilder errorMessage = new StringBuilder();
        AWSTemporaryCredentials awsCreds = cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage);
        assertNotNull(awsCreds);
        assertEquals(awsCreds.getAccessKeyId(), "accesskeyid");
        assertEquals(awsCreds.getSessionToken(), "sessiontoken");
        assertEquals(awsCreds.getSecretAccessKey(), "secretaccesskey");
        cloudStore.close();
    }

    @Test
    public void testAssumeAWSRoleFailedCreds() {
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.awsEnabled = true;
        AssumeRoleResult mockResult = Mockito.mock(AssumeRoleResult.class);
        Credentials creds = Mockito.mock(Credentials.class);
        Mockito.when(creds.getAccessKeyId()).thenReturn("accesskeyid");
        Mockito.when(creds.getSecretAccessKey()).thenReturn("secretaccesskey");
        Mockito.when(creds.getSessionToken()).thenReturn("sessiontoken");
        Mockito.when(creds.getExpiration()).thenReturn(new Date());
        Mockito.when(mockResult.getCredentials()).thenReturn(creds);
        cloudStore.setAssumeRoleResult(mockResult);
        cloudStore.setReturnSuperAWSRole(true);

        // add our key to the invalid cache

        cloudStore.putInvalidCacheCreds(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null));
        StringBuilder errorMessage = new StringBuilder();
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage));
        errorMessage.setLength(0);
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage));

        // now set the timeout to 1 second and sleep that long and after
        // that our test case should work as before

        cloudStore.invalidCacheTimeout = 1;
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ignored) {
        }
        errorMessage.setLength(0);
        assertNotNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage));
        cloudStore.close();
    }

    @Test
    public void testAssumeAWSRoleFailedCredsCache() {
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.awsEnabled = true;
        cloudStore.setReturnSuperAWSRole(true);
        cloudStore.invalidCacheTimeout = 120;

        // first we're going to return a regular exception
        // in which case we won't cache the failed creds

        cloudStore.setGetServiceException(403, false);
        StringBuilder errorMessage = new StringBuilder();
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage));
        assertNull(cloudStore.awsInvalidCredsCache.get(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null)));

        // now we're going to return aamazon service exception
        // but with 401 error code which means against no
        // caching of failed credentials

        cloudStore.setGetServiceException(401, true);
        errorMessage.setLength(0);
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage));
        assertNull(cloudStore.awsInvalidCredsCache.get(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null)));

        // finally we're going to return access denied - 403
        // amazon exception and we should cache the failed creds

        cloudStore.setGetServiceException(403, true);
        errorMessage.setLength(0);
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage));
        assertNotNull(cloudStore.awsInvalidCredsCache.get(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null)));

        cloudStore.close();
    }

    @Test
    public void testGetSshKeyReqType() {
        CloudStore cloudStore = new CloudStore();
        final String req = "{\"principals\":[\"localhost\"],\"pubkey\":\"ssh-rsa AAAs\"" +
                ",\"reqip\":\"10.10.10.10\",\"requser\":\"user\",\"certtype\":\"host\",\"transid\":\"0\"}";
        assertEquals(cloudStore.getSshKeyReqType(req), "host");

        final String req2 = "{\"principals\":[\"localhost\"],\"pubkey\":\"ssh-rsa AAAs\"" +
                ",\"reqip\":\"10.10.10.10\",\"requser\":\"user\",\"certtype2\":\"host\",\"transid\":\"0\"}";
        assertNull(cloudStore.getSshKeyReqType(req2));

        final String req3 = "{invalid-json";
        assertNull(cloudStore.getSshKeyReqType(req3));
        cloudStore.close();
    }

    @Test
    public void testGetCacheKey() {
        CloudStore cloudStore = new CloudStore();
        assertEquals(cloudStore.getCacheKey("account", "role", "user", null, null), "account:role:user::");
        assertEquals(cloudStore.getCacheKey("account", "role", "user", 100, null), "account:role:user:100:");
        assertEquals(cloudStore.getCacheKey("account", "role", "user", null, "ext"), "account:role:user::ext");
        assertEquals(cloudStore.getCacheKey("account", "role", "user", null, "100"), "account:role:user::100");
        assertEquals(cloudStore.getCacheKey("account", "role", "user", 100, "ext"), "account:role:user:100:ext");
        cloudStore.close();
    }

    @Test
    public void testGetCachedCreds() {
        CloudStore cloudStore = new CloudStore();
        AWSTemporaryCredentials creds = new AWSTemporaryCredentials();
        creds.setAccessKeyId("keyid");
        creds.setSecretAccessKey("accesskey");
        creds.setSessionToken("token");
        // set the expiration for 1 hour from now
        creds.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600*1000));
        cloudStore.putCacheCreds("account:role:user::", creds);

        // fetching with a different cache key should not match anything
        assertNull(cloudStore.getCachedCreds("account:role:user:100:", null));
        assertNull(cloudStore.getCachedCreds("account:role:user::ext", null));

        // fetching with null duration should match (default to 3600) and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", null));

        // fetching with 0 duration should match (default to 3600) and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", 0));

        // fetching with negative duration should match (default to 3600) and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", -1));

        // fetching with 1 hour duration should match and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", 3600));

        // fetching with 45 min duration should match duration
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", 2700));

        // fetching with 1 hour and 5 min duration should match and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", 3900));

        // fetching with 1 hour and 11 min duration should not match
        assertNull(cloudStore.getCachedCreds("account:role:user::", 4260));

        // fetching with 2 hour duration should not match
        assertNull(cloudStore.getCachedCreds("account:role:user::", 7200));
        cloudStore.close();
    }

    @Test
    public void testGetCachedCredsDisabled() {
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT, "0");
        CloudStore cloudStore = new CloudStore();

        assertNull(cloudStore.getCacheKey("account", "role", "user", null, null));
        assertNull(cloudStore.getCacheKey("account", "role", "user", 100, null));
        assertNull(cloudStore.getCacheKey("account", "role", "user", 100, "ext"));

        AWSTemporaryCredentials creds = new AWSTemporaryCredentials();
        creds.setAccessKeyId("keyid");
        creds.setSecretAccessKey("accesskey");
        creds.setSessionToken("token");
        // set the expiration for 1 hour from now
        creds.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600*1000));
        cloudStore.putCacheCreds("account:role:user::", creds);

        // with disabled cache there is nothing to match
        assertNull(cloudStore.getCachedCreds("account:role:user::", null));
        cloudStore.close();
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT);
    }

    @Test
    public void testRemoveExpiredCredentials() {
        CloudStore cloudStore = new CloudStore();

        AWSTemporaryCredentials creds = new AWSTemporaryCredentials();
        creds.setAccessKeyId("keyid");
        creds.setSecretAccessKey("accesskey");
        creds.setSessionToken("token");
        // set the expiration for 1 hour from now
        creds.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600*1000));
        cloudStore.putCacheCreds("account:role:user::", creds);

        assertFalse(cloudStore.removeExpiredCredentials());

        // now let's add an expired entry
        AWSTemporaryCredentials creds2 = new AWSTemporaryCredentials();
        creds2.setAccessKeyId("keyid");
        creds2.setSecretAccessKey("accesskey");
        creds2.setSessionToken("token");
        // expired credential
        creds2.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 1000));
        cloudStore.putCacheCreds("account:role:user2::", creds2);

        assertTrue(cloudStore.removeExpiredCredentials());
        cloudStore.close();
    }

    @Test
    public void testGetCachedAWSCredentials() {
        CloudStore cloudStore = new CloudStore();
        cloudStore.awsEnabled = true;

        AWSTemporaryCredentials creds = new AWSTemporaryCredentials();
        creds.setAccessKeyId("keyid");
        creds.setSecretAccessKey("accesskey");
        creds.setSessionToken("token");
        // set the expiration for 1 hour from now
        creds.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600 * 1000));
        cloudStore.putCacheCreds("account:role:user::ext", creds);

        StringBuilder errorMessage = new StringBuilder();
        AWSTemporaryCredentials testCreds = cloudStore.assumeAWSRole("account", "role", "user",
                null, "ext", errorMessage);
        assertNotNull(testCreds);
        assertEquals(testCreds.getAccessKeyId(), "keyid");
        assertEquals(testCreds.getSecretAccessKey(), "accesskey");
        assertEquals(testCreds.getSessionToken(), "token");
        cloudStore.close();
    }

    @Test
    public void testInvalidCacheCreds() {

        CloudStore cloudStore = new CloudStore();
        cloudStore.awsEnabled = true;

        // standard checks

        cloudStore.putInvalidCacheCreds("cacheKey");
        assertTrue(cloudStore.isFailedTempCredsRequest("cacheKey"));
        assertFalse(cloudStore.isFailedTempCredsRequest("unknown-key"));

        // now set the timeout to only 1 second
        // and sleep so our records are expired

        cloudStore.invalidCacheTimeout = 1;
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ignored) {
        }
        // this time our cache key is no longer considered failed

        assertFalse(cloudStore.isFailedTempCredsRequest("cacheKey"));

        // set the timeout to 0 value which should disable
        // cache functionality thus our put does nothing

        cloudStore.invalidCacheTimeout = 0;
        cloudStore.putInvalidCacheCreds("newKey");
        assertFalse(cloudStore.isFailedTempCredsRequest("newKey"));

        // set the timeout back to 2 mins and verify
        // expired check does not remove any entries

        cloudStore.invalidCacheTimeout = 120;
        assertEquals(cloudStore.awsInvalidCredsCache.size(), 1);

        cloudStore.removeExpiredInvalidCredentials();
        assertEquals(cloudStore.awsInvalidCredsCache.size(), 1);

        // now set it to 1 second and it should remove it

        cloudStore.invalidCacheTimeout = 1;
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ignored) {
        }
        cloudStore.removeExpiredInvalidCredentials();
        assertEquals(cloudStore.awsInvalidCredsCache.size(), 0);

        cloudStore.close();
    }

    @Test
    public void testSetupHttpClient() throws Exception {

        CloudStore cloudStore = new CloudStore();
        HttpClient client = Mockito.mock(HttpClient.class);
        Mockito.doThrow(new Exception("Invalid client")).when(client).start();

        try {
            cloudStore.setupHttpClient(client);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        cloudStore.close();
    }

    @Test
    public void testAWSCredentialsUpdaterExceptions () {

        CloudStore cloudStore = Mockito.mock(CloudStore.class);

        // we're going to test exceptions from three components
        // and make sure our run does not throw any

        // first operation - all return true
        // second operation - fetchRoleCredentials throws exception
        // third operation - removeExpiredCredentials throws exception
        // forth opreation - removeExpiredInvalidCredentials throws exception

        Mockito.when(cloudStore.fetchRoleCredentials())
                .thenReturn(true)
                .thenThrow(new NullPointerException("invalid state"))
                .thenReturn(true)
                .thenReturn(true);
        Mockito.when(cloudStore.removeExpiredCredentials())
                .thenReturn(true)
                .thenReturn(true)
                .thenThrow(new NullPointerException("invalid state"))
                .thenReturn(true);
        Mockito.when(cloudStore.removeExpiredInvalidCredentials())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenThrow(new NullPointerException("invalid state"));

        CloudStore.AWSCredentialsUpdater updater = cloudStore.new AWSCredentialsUpdater();
        updater.run();
        updater.run();
        updater.run();
        updater.run();
    }

    @Test
    public void testGetAzureSubscription() {
        CloudStore cloudStore = new CloudStore();
        assertNull(cloudStore.getAzureSubscription("athenz"));

        cloudStore.updateAzureSubscription("athenz", "12345", "321", "999");
        assertEquals("12345", cloudStore.getAzureSubscription("athenz"));
        assertEquals("321", cloudStore.getAzureTenant("athenz"));
        assertEquals("999", cloudStore.getAzureClient("athenz"));

        cloudStore.updateAzureSubscription("athenz", "", "", "");
        assertNull(cloudStore.getAzureSubscription("athenz"));
        assertNull(cloudStore.getAzureTenant("athenz"));
        assertNull(cloudStore.getAzureClient("athenz"));

        cloudStore.updateAzureSubscription("athenz", "12345", null, "888");
        assertEquals("12345", cloudStore.getAzureSubscription("athenz"));
        assertNull(cloudStore.getAzureTenant("athenz"));
        assertEquals("888", cloudStore.getAzureClient("athenz"));

        cloudStore.updateAzureSubscription("athenz", "12345", "777", null);
        assertEquals("12345", cloudStore.getAzureSubscription("athenz"));
        assertEquals("777", cloudStore.getAzureTenant("athenz"));
        assertEquals("888", cloudStore.getAzureClient("athenz"));

        cloudStore.close();
    }

    @Test
    public void testGetGcpProject() {
        CloudStore cloudStore = new CloudStore();
        assertNull(cloudStore.getGCPProjectId("athenz"));

        cloudStore.updateGCPProject("athenz", "athenz-gcp-xsdc", "1234");
        assertEquals(cloudStore.getGCPProjectId("athenz"), "athenz-gcp-xsdc");
        assertEquals(cloudStore.getGCPProjectNumber("athenz"), "1234");

        cloudStore.updateGCPProject("athenz", "", "");
        assertNull(cloudStore.getGCPProjectId("athenz"));
        assertNull(cloudStore.getGCPProjectNumber("athenz"));

        cloudStore.updateGCPProject("athenz", "athenz-gcp-xsdc", null);
        assertEquals(cloudStore.getGCPProjectId("athenz"), "athenz-gcp-xsdc");
        assertNull(cloudStore.getGCPProjectNumber("athenz"));

        cloudStore.close();
    }
}
