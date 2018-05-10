/*
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

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.rdl.Struct;

import javax.net.ssl.*;

public class InstanceAWSECSProvider extends InstanceAWSProvider {

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslcontext,
            KeyStore keyStore) {
        
        super.initialize(provider, providerEndpoint, sslcontext, keyStore);
        
        // for ECS support, we're not going to enforce the
        // boot time since we don't know when the container
        // was started and temporary aws iam assume role
        // validation is sufficient
        
        bootTimeOffset = 0;
        
        // our ECS provider must validate refresh requests
        
        supportRefresh = true;
    }
    
    @Override
    String getInstanceId(AWSAttestationData info, Struct instanceDocument) {
        
        // we're going to look for container task id first
        // only if that's not present (as backup), we'll
        // return the instance document id
        
        String instanceId = info.getTaskid();
        if (instanceId == null || instanceId.isEmpty()) {
            instanceId = instanceDocument.getString(ATTR_INSTANCE_ID);
        }
        return instanceId;
    }
}
