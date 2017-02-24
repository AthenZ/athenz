package com.yahoo.athenz.zms;

import org.glassfish.jersey.server.ResourceConfig;

public class ZMS extends ResourceConfig {
    public ZMS() {
        registerClasses(ZMSResources.class);
        register(new ZMSBinder());
    }
}
