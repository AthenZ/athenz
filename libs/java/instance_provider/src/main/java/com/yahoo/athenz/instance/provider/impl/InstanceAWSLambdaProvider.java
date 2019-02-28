/*
 * Copyright 2018 Yahoo Holdings, Inc.
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

import java.util.HashMap;
import java.util.Map;

import com.yahoo.athenz.instance.provider.InstanceConfirmation;

public class InstanceAWSLambdaProvider extends InstanceAWSProvider {

    @Override
    boolean validateAWSDocument(final String provider, AWSAttestationData info,
            final String awsAccount, final String instanceId, boolean checkTime,
            StringBuilder errMsg) {
        
        // for lambda we don't have an instance document so we
        // are going to trust based on temporary credentials only
        
        return true;
    }
    
    @Override
    void setConfirmationAttributes(InstanceConfirmation confirmation, boolean sshCert) {
        
        // for lambda we can only issue client certificates
        // and we always do not allow ssh certs
        
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceUtils.ZTS_CERT_SSH, "false");
        confirmation.setAttributes(attributes);
    }
}
