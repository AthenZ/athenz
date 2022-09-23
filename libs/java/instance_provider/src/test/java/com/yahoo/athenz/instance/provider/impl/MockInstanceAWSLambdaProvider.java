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

import com.amazonaws.services.securitytoken.AWSSecurityTokenService;

@SuppressWarnings("unused")
public class MockInstanceAWSLambdaProvider extends InstanceAWSLambdaProvider {

    boolean identityResult = true;
    boolean identitySuper = false;
    AWSSecurityTokenService stsClient;
    
    void setIdentityResult(boolean value) {
        identityResult = value;
    }
    
    void setIdentitySuper(boolean value) {
        identitySuper = value;
    }
    
    void setStsClient(AWSSecurityTokenService client) {
        stsClient = client;
    }
    
    @Override
    public boolean verifyInstanceIdentity(AWSAttestationData info, final String awsAccount) {
        return identitySuper ? super.verifyInstanceIdentity(info, awsAccount) : identityResult;
    }
    
    @Override
    public AWSSecurityTokenService getInstanceClient(AWSAttestationData info) {
        return stsClient != null ? stsClient : super.getInstanceClient(info);
    }
}
