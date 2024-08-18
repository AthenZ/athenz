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

import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import org.mockito.Mockito;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;
import software.amazon.awssdk.awscore.exception.AwsServiceException;

public class MockCloudStore extends CloudStore {
    private String account = null;
    private String roleName = null;
    private String principal = null;
    private boolean returnSuperAWSRole = false;
    private AssumeRoleResponse assumeRoleResult = null;
    private GetCallerIdentityResponse callerIdentityResult = null;
    private int exceptionStatusCode = 0;
    private boolean amazonException = true;

    public MockCloudStore() {
        super();
    }

    @Override
    public boolean isAwsEnabled() {
        return true;
    }

    public void setMockFields(String account, String roleName, String principal) {
        this.account = account;
        this.roleName = roleName;
        this.principal = principal;
    }

    void setAssumeRoleResult(AssumeRoleResponse assumeRoleResult) {
        this.assumeRoleResult = assumeRoleResult;
    }

    void setGetCallerIdentityResult(GetCallerIdentityResponse callerIdentityResult) {
        this.callerIdentityResult = callerIdentityResult;
    }

    @Override
    public StsClient getTokenServiceClient() {
        if (exceptionStatusCode != 0) {
            if (amazonException) {
                throw AwsServiceException.builder().awsErrorDetails(
                        AwsErrorDetails.builder().sdkHttpResponse(
                                SdkHttpResponse.builder().statusCode(exceptionStatusCode).build()
                        ).build()
                ).build();
            } else {
                throw new IllegalArgumentException("Error");
            }
        } else {
            StsClient client = Mockito.mock(StsClient.class);
            Mockito.when(client.assumeRole(Mockito.any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);
            Mockito.when(client.getCallerIdentity(Mockito.any(GetCallerIdentityRequest.class)))
                    .thenReturn(callerIdentityResult);
            return client;
        }
    }

    void setReturnSuperAWSRole(boolean returnSuperAWSRole) {
        this.returnSuperAWSRole = returnSuperAWSRole;
    }

    @Override
    public AWSTemporaryCredentials assumeAWSRole(String account, String roleName, String principal,
            Integer durationSeconds, String externalId, StringBuilder errorMessage) {

        if (!returnSuperAWSRole) {
            AWSTemporaryCredentials tempCreds = null;
            if (this.account.equals(account) && this.roleName.equals(roleName)
                    && this.principal.equals(principal)) {
                tempCreds = new AWSTemporaryCredentials();
            }

            return tempCreds;
        } else {
            return super.assumeAWSRole(account, roleName, principal, durationSeconds, externalId, errorMessage);
        }
    }

    public void setGetServiceException(int statusCode, boolean amazonException) {
        this.exceptionStatusCode = statusCode;
        this.amazonException = amazonException;
    }
}
