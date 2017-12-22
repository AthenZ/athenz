package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.rdl.Struct;

public class InstanceAWSECSProvider extends InstanceAWSProvider {

    @Override
    public void initialize(String provider, String providerEndpoint) {
        super.initialize(provider, providerEndpoint);
        
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
