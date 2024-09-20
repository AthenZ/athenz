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

package io.athenz.server.aws.common.creds.impl;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import org.eclipse.jetty.client.ContentResponse;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.Request;
import org.eclipse.jetty.http.HttpMethod;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.net.URI;
import java.util.Date;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_REGION_NAME;
import static io.athenz.server.aws.common.creds.impl.TempCredsProvider.ZTS_PROP_AWS_ROLE_SESSION_NAME;
import static org.testng.Assert.*;

public class TempCredsProviderTest {

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
    public void testGetTokenServiceClient() throws ServerResourceException {
        TempCredsProvider credsProvider = new TempCredsProvider();
        credsProvider.credentials = AwsBasicCredentials.builder().accessKeyId("accessKey").secretAccessKey("secretKey").build();
        credsProvider.awsRegion = "us-west-2";
        assertNotNull(credsProvider.getTokenServiceClient());
        credsProvider.close();
    }

    @Test
    public void testGetAssumeRoleRequest() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();
        AssumeRoleRequest req = credsProvider.getAssumeRoleRequest("1234", "admin", null, null, "athenz.api");
        assertEquals("arn:aws:iam::1234:role/admin", req.roleArn());
        assertEquals("athenz.api", req.roleSessionName());
        assertNull(req.durationSeconds());
        assertNull(req.externalId());

        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api");
        assertEquals("arn:aws:iam::12345:role/adminuser", req.roleArn());
        assertEquals("athenz.api", req.roleSessionName());
        assertEquals(Integer.valueOf(101), req.durationSeconds());
        assertEquals("external", req.externalId());

        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api-service");
        assertEquals("arn:aws:iam::12345:role/adminuser", req.roleArn());
        assertEquals("athenz.api-service", req.roleSessionName());
        assertEquals(Integer.valueOf(101), req.durationSeconds());
        assertEquals("external", req.externalId());

        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api_service-test");
        assertEquals("arn:aws:iam::12345:role/adminuser", req.roleArn());
        assertEquals("athenz.api_service-test", req.roleSessionName());
        assertEquals(Integer.valueOf(101), req.durationSeconds());
        assertEquals("external", req.externalId());

        final String principalLongerThan64Chars = "athenz.environment.production.regions.us-west-2.services.zts-service";
        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", principalLongerThan64Chars);
        assertEquals("arn:aws:iam::12345:role/adminuser", req.roleArn());
        assertEquals("athenz.environment.production....us-west-2.services.zts-service", req.roleSessionName());
        assertEquals(Integer.valueOf(101), req.durationSeconds());
        assertEquals("external", req.externalId());
        credsProvider.close();

        System.setProperty(ZTS_PROP_AWS_ROLE_SESSION_NAME, "athenz-zts-service");
        credsProvider = new TempCredsProvider();
        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api-service");
        assertEquals("arn:aws:iam::12345:role/adminuser", req.roleArn());
        assertEquals("athenz-zts-service", req.roleSessionName());
        assertEquals(Integer.valueOf(101), req.durationSeconds());
        assertEquals("external", req.externalId());
        credsProvider.close();
        System.clearProperty(ZTS_PROP_AWS_ROLE_SESSION_NAME);
    }

    @Test
    public void testParseInstanceInfo() throws ServerResourceException {
        TempCredsProvider credsProvider = new TempCredsProvider();
        assertTrue(credsProvider.parseInstanceInfo(AWS_INSTANCE_DOCUMENT));
        assertEquals(credsProvider.awsRegion, "us-west-2");
        credsProvider.close();
    }

    @Test
    public void testParseInstanceInfoInvalid() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();
        assertFalse(credsProvider.parseInstanceInfo("some_invalid_doc"));
        credsProvider.close();
    }

    @Test
    public void testParseInstanceInfoRegion() throws ServerResourceException {

        // first this should fail since we have no region
        // override and the document has no region

        TempCredsProvider credsProvider = new TempCredsProvider();
        assertFalse(credsProvider.parseInstanceInfo("{\"accountId\":\"012345678901\"}"));

        // now we're going to use the same doc with override

        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "us-west-3");
        credsProvider.close();

        credsProvider = new TempCredsProvider();
        assertTrue(credsProvider.parseInstanceInfo("{\"accountId\":\"012345678901\"}"));
        assertEquals(credsProvider.awsRegion, "us-west-3");
        System.clearProperty(ZTS_PROP_AWS_REGION_NAME);
        credsProvider.close();
    }

    @Test
    public void testParseIamRoleInfoInvalid() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();
        assertFalse(credsProvider.parseIamRoleInfo("some_invalid_doc"));
        credsProvider.close();
    }

    @Test
    public void testParseIamRoleInfoMissingInstanceProfile() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();
        assertFalse(credsProvider.parseIamRoleInfo("{\"accountId\":\"012345678901\"}"));
        assertFalse(credsProvider.parseIamRoleInfo("{\"accountId\":\"012345678901\",\"InstanceProfileArn\":\"\"}"));
        credsProvider.close();
    }

    @Test
    public void testParseIamRoleInfoInvalidInstanceProfile() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();
        assertFalse(credsProvider.parseIamRoleInfo("{\"accountId\":\"012345678901\"}"));
        assertFalse(credsProvider.parseIamRoleInfo("{\"accountId\":\"012345678901\",\"InstanceProfileArn\":\"invalid\"}"));
        credsProvider.close();
    }

    @Test
    public void testParseIamRoleInfo() throws ServerResourceException {
        TempCredsProvider credsProvider = new TempCredsProvider();
        assertTrue(credsProvider.parseIamRoleInfo(AWS_IAM_ROLE_INFO));
        assertEquals(credsProvider.awsRole, "athenz.zts");
        credsProvider.close();
    }

    @Test
    public void testParseInstanceProfileArn() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();
        assertTrue(credsProvider.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/athenz.zts,athenz"));
        assertEquals(credsProvider.awsRole, "athenz.zts");
        credsProvider.close();
    }

    @Test
    public void testParseInstanceProfileArnInvalidPrefix() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();

        // invalid starting prefix

        assertFalse(credsProvider.parseInstanceProfileArn("arn:aws:iam:111111111111:instance-profile/athenz.zts,athenz"));
        assertFalse(credsProvider.parseInstanceProfileArn("arn:aws:iam2:111111111111:instance-profile/athenz.zts,athenz"));
        assertFalse(credsProvider.parseInstanceProfileArn("instance-profile/athenz.zts,athenz"));
        credsProvider.close();
    }

    @Test
    public void testParseInstanceProfileArnInvalidProfile()throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();

        // missing instance-profile part

        assertFalse(credsProvider.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile2/athenz.zts,athenz"));
        assertFalse(credsProvider.parseInstanceProfileArn("arn:aws:iam::111111111111:instance/athenz.zts,athenz"));
        credsProvider.close();
    }

    @Test
    public void testParseInstanceProfileArnInvalidNoProfile() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();

        // no profile name

        assertFalse(credsProvider.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/"));
        credsProvider.close();
    }

    @Test
    public void testParseInstanceProfileArnCloud() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();
        // cloud name is optional for backwards compatibility
        assertTrue(credsProvider.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/athenz.zts"));
        assertEquals(credsProvider.awsRole, "athenz.zts");
        assertTrue(credsProvider.parseInstanceProfileArn("arn:aws:iam::111111111111:instance-profile/athenz.proxy,athenz,test"));
        assertEquals(credsProvider.awsRole, "athenz.proxy");
        credsProvider.close();
    }

    @Test
    public void testGetMetaDataExceptions() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        credsProvider.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/exc1")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenThrow(TimeoutException.class);
        Mockito.doThrow(new IndexOutOfBoundsException()).when(httpClient).stop();

        assertNull(credsProvider.getMetaData("/exc1"));
        credsProvider.close();
    }

    @Test
    public void testGetMetaDataFailureStatus() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(404);
        credsProvider.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/iam-info")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertNull(credsProvider.getMetaData("/iam-info"));
        credsProvider.close();
    }

    @Test
    public void testGetMetaDataNullResponse() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn(null);
        credsProvider.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/iam-info")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertNull(credsProvider.getMetaData("/iam-info"));
        credsProvider.close();
    }

    @Test
    public void testGetMetaDataEmptyResponse() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("");
        credsProvider.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/iam-info")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertNull(credsProvider.getMetaData("/iam-info"));
        credsProvider.close();
    }

    @Test
    public void testGetMetaDataValidResponse() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("json-document");
        credsProvider.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/iam-info")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertEquals(credsProvider.getMetaData("/iam-info"), "json-document");
        credsProvider.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidDocumentGet() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(404);
        credsProvider.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertFalse(credsProvider.loadBootMetaData());
        credsProvider.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidDocumentParse() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("{\"accountId\":\"012345678901\"}");
        credsProvider.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertFalse(credsProvider.loadBootMetaData());
        credsProvider.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidDocumentException() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("json-document");
        credsProvider.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertFalse(credsProvider.loadBootMetaData());
        credsProvider.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidSignature() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(404);

        credsProvider.setHttpClient(httpClient);

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

        assertFalse(credsProvider.loadBootMetaData());
        credsProvider.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidIamInfoGet() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(404);

        credsProvider.setHttpClient(httpClient);

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

        assertFalse(credsProvider.loadBootMetaData());
        credsProvider.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidIamInfoException() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
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

        credsProvider.setHttpClient(httpClient);

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

        assertFalse(credsProvider.loadBootMetaData());
        credsProvider.close();
    }

    @Test
    public void testLoadBootMetaDataInvalidIamInfoParse() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
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

        credsProvider.setHttpClient(httpClient);

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

        assertFalse(credsProvider.loadBootMetaData());
        credsProvider.close();
    }

    @Test
    public void testLoadBootMetaDataV1() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
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

        credsProvider.setHttpClient(httpClient);

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

        assertTrue(credsProvider.loadBootMetaData());
        assertEquals(credsProvider.awsRole, "athenz.zts");
        assertEquals(credsProvider.awsRegion, "us-west-2");
        credsProvider.close();
    }

    @Test
    public void testLoadBootMetaDataV2() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
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

        credsProvider.setHttpClient(httpClient);

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

        assertTrue(credsProvider.loadBootMetaData());
        assertEquals(credsProvider.awsRole, "athenz.zts");
        assertEquals(credsProvider.awsRegion, "us-west-2");
        credsProvider.close();
    }

    @Test
    public void testFetchRoleCredentialsNoRole() throws ServerResourceException{

        TempCredsProvider credsProvider = new TempCredsProvider();

        credsProvider.awsRole = null;
        assertFalse(credsProvider.fetchRoleCredentials());

        credsProvider.awsRole = "";
        assertFalse(credsProvider.fetchRoleCredentials());
        credsProvider.close();
    }

    @Test
    public void testFetchRoleCredentialsNoCreds() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        credsProvider.awsRole = "athenz.zts";

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(404);
        credsProvider.setHttpClient(httpClient);

        Request credsRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")))
                .thenReturn(credsRequest);
        Mockito.when(credsRequest.method(HttpMethod.GET)).thenReturn(credsRequest);
        Mockito.when(credsRequest.send()).thenReturn(response);

        assertFalse(credsProvider.fetchRoleCredentials());
        credsProvider.close();
    }

    @Test
    public void testFetchRoleCredentialInvalidCreds() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        credsProvider.awsRole = "athenz.zts";

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("invalid-creds");

        credsProvider.setHttpClient(httpClient);

        Request credsRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")))
                .thenReturn(credsRequest);
        Mockito.when(credsRequest.method(HttpMethod.GET)).thenReturn(credsRequest);
        Mockito.when(credsRequest.send()).thenReturn(response);

        assertFalse(credsProvider.fetchRoleCredentials());
        credsProvider.close();
    }

    @Test
    public void testFetchRoleCredential() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        credsProvider.awsRole = "athenz.zts";

        HttpClient httpClient = Mockito.mock(HttpClient.class);
        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("{\"AccessKeyId\":\"id\",\"SecretAccessKey\":\"key\",\"Token\":\"token\"}");

        credsProvider.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")))
                .thenReturn(request);
        Mockito.when(request.method(HttpMethod.GET)).thenReturn(request);
        Mockito.when(request.send()).thenReturn(response);

        assertTrue(credsProvider.fetchRoleCredentials());
        credsProvider.close();
    }

    @Test
    public void testInitializeAwsSupportInvalidDocument()  throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn("invalid-document");

        credsProvider.setHttpClient(httpClient);

        Request docRequest = Mockito.mock(Request.class);
        Mockito.when(httpClient.newRequest(URI.create("http://169.254.169.254/latest/dynamic/instance-identity/document")))
                .thenReturn(docRequest);
        Mockito.when(docRequest.method(HttpMethod.GET)).thenReturn(docRequest);
        Mockito.when(docRequest.send()).thenReturn(responseDoc);

        try {
            credsProvider.initialize();
        } catch (ServerResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        credsProvider.close();
    }

    @Test
    public void testInitializeAwsSupportInvalidCreds()  throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
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

        credsProvider.setHttpClient(httpClient);

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
            credsProvider.initialize();
            fail();
        } catch (ServerResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        credsProvider.close();
    }

    @Test
    public void testInitializeAwsSupport() throws TimeoutException, InterruptedException, ServerResourceException, ExecutionException {

        TempCredsProvider credsProvider = new TempCredsProvider();
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

        credsProvider.setHttpClient(httpClient);

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

        credsProvider.initialize();

        // sleep a couple of seconds for the background thread to run
        // before we try to shut it down

        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }
        credsProvider.close();
    }

    @Test
    public void testAssumeAWSRole() throws ServerResourceException {

        MockTempCredsProvider credsProvider = new MockTempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        credsProvider.setHttpClient(httpClient);

        AssumeRoleResponse mockResult = Mockito.mock(AssumeRoleResponse.class);
        Credentials creds = Mockito.mock(Credentials.class);
        Mockito.when(creds.accessKeyId()).thenReturn("accesskeyid");
        Mockito.when(creds.secretAccessKey()).thenReturn("secretaccesskey");
        Mockito.when(creds.sessionToken()).thenReturn("sessiontoken");
        Mockito.when(creds.expiration()).thenReturn(new Date().toInstant());
        Mockito.when(mockResult.credentials()).thenReturn(creds);
        credsProvider.setAssumeRoleResult(mockResult);

        StringBuilder errorMessage = new StringBuilder();
        AWSTemporaryCredentials awsCreds = credsProvider.getTemporaryCredentials("account", "syncer",
                "athenz.syncer", null, null, errorMessage);
        assertNotNull(awsCreds);
        assertEquals(awsCreds.getAccessKeyId(), "accesskeyid");
        assertEquals(awsCreds.getSessionToken(), "sessiontoken");
        assertEquals(awsCreds.getSecretAccessKey(), "secretaccesskey");
        credsProvider.close();
    }

    @Test
    public void testAssumeAWSRoleFailedCreds() throws ServerResourceException {

        MockTempCredsProvider credsProvider = new MockTempCredsProvider();
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        credsProvider.setHttpClient(httpClient);

        AwsServiceException exception = AwsServiceException.builder()
            .awsErrorDetails(AwsErrorDetails.builder()
                    .sdkHttpResponse(SdkHttpResponse.builder().statusCode(503).build())
                    .build())
            .build();
        credsProvider.setAssumeRoleResponseException(exception);

        StringBuilder errorMessage = new StringBuilder();
        try {
            credsProvider.getTemporaryCredentials("account", "syncer",
                    "athenz.syncer", null, null, errorMessage);
            fail();
        } catch (ServerResourceException ex) {
            assertEquals(ex.getCode(), 503);
        }

        exception = AwsServiceException.builder().message("invalid").build();
        credsProvider.setAssumeRoleResponseException(exception);
        try {
            credsProvider.getTemporaryCredentials("account", "syncer",
                    "athenz.syncer", null, null, errorMessage);
            fail();
        } catch (ServerResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        credsProvider.setAssumeRoleResponseException(new IllegalArgumentException("invalid"));
        try {
            credsProvider.getTemporaryCredentials("account", "syncer",
                    "athenz.syncer", null, null, errorMessage);
            fail();
        } catch (ServerResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        credsProvider.close();
    }

    @Test
    public void testSetupHttpClient() throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();
        HttpClient client = Mockito.mock(HttpClient.class);
        Mockito.doThrow(new Exception("Invalid client")).when(client).start();

        try {
            credsProvider.setupHttpClient(client);
            fail();
        } catch (ServerResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        credsProvider.close();
    }

    static class MockTempCredsProvider extends TempCredsProvider {

        AssumeRoleResponse assumeRoleResponse;
        Exception assumeRoleResponseException;

        public MockTempCredsProvider() throws ServerResourceException {
            super();
        }

        @Override
        public StsClient getTokenServiceClient() {
            StsClient client = Mockito.mock(StsClient.class);
            if (assumeRoleResponseException != null) {
                Mockito.when(client.assumeRole(Mockito.any(AssumeRoleRequest.class)))
                        .thenThrow(assumeRoleResponseException);
            } else {
                Mockito.when(client.assumeRole(Mockito.any(AssumeRoleRequest.class)))
                        .thenReturn(assumeRoleResponse);
            }
            return client;
        }

        public void setAssumeRoleResult(AssumeRoleResponse assumeRoleResponse) {
            this.assumeRoleResponse = assumeRoleResponse;
        }

        public void setAssumeRoleResponseException(Exception assumeRoleResponseException) {
            this.assumeRoleResponseException = assumeRoleResponseException;
        }
    }
}
