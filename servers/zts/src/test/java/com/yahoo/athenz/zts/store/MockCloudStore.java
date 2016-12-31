/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts.store;

import org.mockito.Mockito;

import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.yahoo.athenz.zts.AWSInstanceInformation;
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.athenz.zts.cert.CertSigner;
import com.yahoo.athenz.zts.store.CloudStore;

public class MockCloudStore extends CloudStore {

    String account = null;
    String roleName = null;
    String principal = null;
    boolean skipSigCheck = false;
    boolean returnNullClient = false;
    boolean returnSuperAWSRole = false;
    int identityCheck = 0; // 0 call super, 1 - true, -1 false
    private AssumeRoleResult assumeRoleResult = null;
    private GetCallerIdentityResult callerIdentityResult = null;
    
    public MockCloudStore() {
        super(null);
    }
    
    public MockCloudStore(CertSigner certSigner) {
        super(certSigner);
    }

    @Override
    public
    boolean isAwsEnabled() {
        return true;
    }
    
    public void setMockFields(String account, String roleName, String principal) {
        this.account = account;
        this.roleName = roleName;
        this.principal = principal;
    }
    
    public void skipDocumentSignatureCheck(boolean skipCheck) {
        skipSigCheck = skipCheck;
    }
    
    public void setIdentityCheckResult(int idCheck) {
        identityCheck = idCheck;
    }
    
    @Override
    public
    boolean verifyInstanceIdentity(AWSInstanceInformation info) {
        boolean result = false;
        switch (identityCheck) {
            case 0:
                result = super.verifyInstanceIdentity(info);
                break;
            case 1:
                result = true;
                break;
            case -1:
                result = false;
                break;
        }
        return result;
    }
    
    @Override
    public
    boolean validateInstanceDocument(String document, String signature) {
        if (skipSigCheck) {
            return true;
        }
        return super.validateInstanceDocument(document, signature);
    }
    
    void setAssumeRoleResult(AssumeRoleResult assumeRoleResult) {
        this.assumeRoleResult = assumeRoleResult;
    }
    
    void setGetCallerIdentityResult(GetCallerIdentityResult callerIdentityResult) {
        this.callerIdentityResult = callerIdentityResult;
    }
    
    void setReturnNullClient(boolean returnNullClient) {
        this.returnNullClient = returnNullClient;
    }
    
    @Override
    AWSSecurityTokenServiceClient getTokenServiceClient() {
        AWSSecurityTokenServiceClient client = Mockito.mock(AWSSecurityTokenServiceClient.class);
        Mockito.when(client.assumeRole(Mockito.any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);
        Mockito.when(client.getCallerIdentity(Mockito.any(GetCallerIdentityRequest.class))).thenReturn(callerIdentityResult);
        return client;
    }

    @Override
    AWSSecurityTokenServiceClient getInstanceClient(AWSInstanceInformation info) {
        if (returnNullClient) {
            return null;
        } else {
            AWSSecurityTokenServiceClient client = Mockito.mock(AWSSecurityTokenServiceClient.class);
            Mockito.when(client.assumeRole(Mockito.any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);
            Mockito.when(client.getCallerIdentity(Mockito.any(GetCallerIdentityRequest.class))).thenReturn(callerIdentityResult);
            return client;
        }
    }

    void setAssumeAWSRole(boolean returnSuperAWSRole) {
        this.returnSuperAWSRole = returnSuperAWSRole;
    }
    
    @Override
    public AWSTemporaryCredentials assumeAWSRole(String account, String roleName, String principal) {

        if (!returnSuperAWSRole) {
            AWSTemporaryCredentials tempCreds = null;
            if (this.account.equals(account) && this.roleName.equals(roleName)
                    && this.principal.equals(principal)) {
                tempCreds = new AWSTemporaryCredentials();
            }
            
            return tempCreds;
        } else {
            return super.assumeAWSRole(account, roleName, principal);
        }
    }
}
