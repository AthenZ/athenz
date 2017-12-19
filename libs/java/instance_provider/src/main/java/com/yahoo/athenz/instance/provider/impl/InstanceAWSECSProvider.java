package com.yahoo.athenz.instance.provider.impl;

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
}
