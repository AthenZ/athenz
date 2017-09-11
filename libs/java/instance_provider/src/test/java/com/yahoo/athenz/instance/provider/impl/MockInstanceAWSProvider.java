/**
 * Copyright 2017 Yahoo Holdings, Inc.
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

import com.yahoo.athenz.instance.provider.impl.AWSAttestationData;
import com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider;

public class MockInstanceAWSProvider extends InstanceAWSProvider {

    boolean signatureResult = true;
    boolean identityResult = true;
    
    void setSignatureResult(boolean value) {
        signatureResult = value;
    }
    
    void setIdentityResult(boolean value) {
        identityResult = value;
    }
    
    @Override
    public boolean validateAWSSignature(final String document, final String signature) {
        return signatureResult;
    }
    
    @Override
    public boolean verifyInstanceIdentity(AWSAttestationData info) {
        return identityResult;
    }
}
