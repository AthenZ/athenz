package com.yahoo.athenz.zms;

import org.glassfish.hk2.utilities.binding.AbstractBinder;

public class ZMSBinder extends AbstractBinder {

    @Override
    protected void configure() {
        bind(new ZMSImpl()).to(ZMSHandler.class);
    }
}
