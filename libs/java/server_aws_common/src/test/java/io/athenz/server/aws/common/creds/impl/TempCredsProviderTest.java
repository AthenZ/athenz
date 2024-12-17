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
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;
import java.util.Date;

import static io.athenz.server.aws.common.creds.impl.TempCredsProvider.ZTS_PROP_AWS_ROLE_SESSION_NAME;
import static org.testng.Assert.*;

public class TempCredsProviderTest {

    @Test
    public void testGetTokenServiceClient() throws ServerResourceException {
        TempCredsProvider credsProvider = new TempCredsProvider();
        credsProvider.credentialsProvider = Mockito.mock(InstanceProfileCredentialsProvider.class);
        credsProvider.awsRegion = "us-west-2";
        assertNotNull(credsProvider.getTokenServiceClient());
        credsProvider.close();
    }

    @Test
    public void testGetAssumeRoleRequest() throws ServerResourceException {

        TempCredsProvider credsProvider = new TempCredsProvider();
        AssumeRoleRequest req = credsProvider.getAssumeRoleRequest("1234", "admin", null, null, "athenz.api");
        assertEquals(req.roleArn(), "arn:aws:iam::1234:role/admin");
        assertEquals(req.roleSessionName(), "athenz.api");
        assertNull(req.durationSeconds());
        assertNull(req.externalId());

        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api");
        assertEquals(req.roleArn(), "arn:aws:iam::12345:role/adminuser");
        assertEquals(req.roleSessionName(), "athenz.api");
        assertEquals(req.durationSeconds(), Integer.valueOf(101));
        assertEquals(req.externalId(), "external");

        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api-service");
        assertEquals(req.roleArn(), "arn:aws:iam::12345:role/adminuser");
        assertEquals(req.roleSessionName(), "athenz.api-service");
        assertEquals(req.durationSeconds(), Integer.valueOf(101));
        assertEquals(req.externalId(), "external");

        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api_service-test");
        assertEquals(req.roleArn(), "arn:aws:iam::12345:role/adminuser");
        assertEquals(req.roleSessionName(), "athenz.api_service-test");
        assertEquals(req.durationSeconds(), Integer.valueOf(101));
        assertEquals(req.externalId(), "external");

        final String principalLongerThan64Chars = "athenz.environment.production.regions.us-west-2.services.zts-service";
        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", principalLongerThan64Chars);
        assertEquals(req.roleArn(), "arn:aws:iam::12345:role/adminuser");
        assertEquals(req.roleSessionName(), "athenz.environment.production....us-west-2.services.zts-service");
        assertEquals(req.durationSeconds(), Integer.valueOf(101));
        assertEquals(req.externalId(), "external");
        credsProvider.close();

        System.setProperty(ZTS_PROP_AWS_ROLE_SESSION_NAME, "athenz-zts-service");
        credsProvider = new TempCredsProvider();
        req = credsProvider.getAssumeRoleRequest("12345", "adminuser", 101, "external", "athenz.api-service");
        assertEquals(req.roleArn(), "arn:aws:iam::12345:role/adminuser");
        assertEquals(req.roleSessionName(), "athenz-zts-service");
        assertEquals(req.durationSeconds(), Integer.valueOf(101));
        assertEquals(req.externalId(), "external");
        credsProvider.close();
        System.clearProperty(ZTS_PROP_AWS_ROLE_SESSION_NAME);
    }


    @Test
    public void testInitializeAwsSupportInvalidDocument()  throws Exception {

        TempCredsProvider credsProvider = new TempCredsProvider();

        try {
            credsProvider.initialize();
        } catch (ServerResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        credsProvider.close();
    }

    @Test
    public void testAssumeAWSRole() throws ServerResourceException {

        MockTempCredsProvider credsProvider = new MockTempCredsProvider();

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
