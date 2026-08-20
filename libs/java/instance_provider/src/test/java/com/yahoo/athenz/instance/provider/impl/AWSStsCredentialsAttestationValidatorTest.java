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
package com.yahoo.athenz.instance.provider.impl;

import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class AWSStsCredentialsAttestationValidatorTest {

    @BeforeMethod
    public void setup() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_REGION_NAME, "us-west-2");
    }

    @AfterMethod
    public void shutdown() {
        System.clearProperty(InstanceAWSProvider.AWS_PROP_REGION_NAME);
    }

    @Test
    public void testInitialize() {
        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator();
        validator.initialize(null, null);
        assertNotNull(validator.awsRegion);
    }

    @Test
    public void testGetInstanceClient() {

        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator();
        validator.awsRegion = "us-west-2";

        AWSAttestationData data = new AWSAttestationData();

        // first with null and empty access point

        data.setAccess(null);
        assertNull(validator.getInstanceClient(data));

        data.setAccess("");
        assertNull(validator.getInstanceClient(data));

        // null and empty secret

        data.setAccess("access");

        data.setSecret(null);
        assertNull(validator.getInstanceClient(data));

        data.setSecret("");
        assertNull(validator.getInstanceClient(data));

        // null and empty token

        data.setSecret("secret");

        data.setToken(null);
        assertNull(validator.getInstanceClient(data));

        data.setToken("");
        assertNull(validator.getInstanceClient(data));

        data.setToken("valid");
        assertNotNull(validator.getInstanceClient(data));
    }

    @Test
    public void testValidateIdentityNoRegion() {
        // awsRegion is not configured - the request must be rejected before
        // attempting to build the STS client
        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator();
        AWSAttestationData info = new AWSAttestationData();
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(null, info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("aws region is not configured"));
    }

    @Test
    public void testValidateIdentityNullClient() {
        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator();
        validator.awsRegion = "us-west-2";
        AWSAttestationData info = new AWSAttestationData();
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(null, info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("unable to get AWS STS client object"));
    }

    @Test
    public void testValidateIdentityNullIdentity() {
        StsClient mockClient = Mockito.mock(StsClient.class);
        Mockito.when(mockClient.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(null);
        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator() {
            @Override
            StsClient getInstanceClient(AWSAttestationData info) {
                return mockClient;
            }
        };
        validator.awsRegion = "us-west-2";
        AWSAttestationData info = new AWSAttestationData();
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(null, info, "1234", errMsg));
    }

    @Test
    public void testValidateIdentityException() {
        StsClient mockClient = Mockito.mock(StsClient.class);
        Mockito.when(mockClient.getCallerIdentity(any(GetCallerIdentityRequest.class)))
                .thenThrow(new IllegalArgumentException("invalid request"));
        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator() {
            @Override
            StsClient getInstanceClient(AWSAttestationData info) {
                return mockClient;
            }
        };
        validator.awsRegion = "us-west-2";
        AWSAttestationData info = new AWSAttestationData();
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(null, info, "1234", errMsg));
    }

    @Test
    public void testValidateIdentityARNMismatch() {
        StsClient mockClient = Mockito.mock(StsClient.class);
        GetCallerIdentityResponse result = Mockito.mock(GetCallerIdentityResponse.class);
        Mockito.when(result.arn()).thenReturn("arn:aws:sts::1235:assumed-role/athenz.service/athenz.service");
        Mockito.when(mockClient.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(result);
        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator() {
            @Override
            StsClient getInstanceClient(AWSAttestationData info) {
                return mockClient;
            }
        };
        validator.awsRegion = "us-west-2";
        AWSAttestationData info = new AWSAttestationData();
        info.setRole("athenz.service");
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(null, info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("ARN mismatch"));
    }

    @Test
    public void testValidateIdentity() {
        StsClient mockClient = Mockito.mock(StsClient.class);
        GetCallerIdentityResponse result = Mockito.mock(GetCallerIdentityResponse.class);
        Mockito.when(result.arn()).thenReturn("arn:aws:sts::1234:assumed-role/athenz.service/athenz.service");
        Mockito.when(mockClient.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(result);
        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator() {
            @Override
            StsClient getInstanceClient(AWSAttestationData info) {
                return mockClient;
            }
        };
        validator.awsRegion = "us-west-2";
        AWSAttestationData info = new AWSAttestationData();
        info.setRole("athenz.service");
        StringBuilder errMsg = new StringBuilder(256);
        assertTrue(validator.validateIdentity(null, info, "1234", errMsg));
    }

    @Test
    public void testValidateIdentityMultipleAccountsMatch() {
        StsClient mockClient = Mockito.mock(StsClient.class);
        GetCallerIdentityResponse result = Mockito.mock(GetCallerIdentityResponse.class);
        Mockito.when(result.arn()).thenReturn("arn:aws:sts::5678:assumed-role/athenz.service/athenz.service");
        Mockito.when(mockClient.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(result);
        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator() {
            @Override
            StsClient getInstanceClient(AWSAttestationData info) {
                return mockClient;
            }
        };
        validator.awsRegion = "us-west-2";
        AWSAttestationData info = new AWSAttestationData();
        info.setRole("athenz.service");
        StringBuilder errMsg = new StringBuilder(256);
        assertTrue(validator.validateIdentity(null, info, "1234,5678", errMsg));
    }

    @Test
    public void testValidateIdentityMultipleAccountsNoMatch() {
        StsClient mockClient = Mockito.mock(StsClient.class);
        GetCallerIdentityResponse result = Mockito.mock(GetCallerIdentityResponse.class);
        Mockito.when(result.arn()).thenReturn("arn:aws:sts::9999:assumed-role/athenz.service/athenz.service");
        Mockito.when(mockClient.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(result);
        AWSStsCredentialsAttestationValidator validator = new AWSStsCredentialsAttestationValidator() {
            @Override
            StsClient getInstanceClient(AWSAttestationData info) {
                return mockClient;
            }
        };
        validator.awsRegion = "us-west-2";
        AWSAttestationData info = new AWSAttestationData();
        info.setRole("athenz.service");
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(null, info, "1234,5678", errMsg));
        assertTrue(errMsg.toString().contains("ARN mismatch"));
    }
}
