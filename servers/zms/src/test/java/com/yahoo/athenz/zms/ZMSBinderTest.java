package com.yahoo.athenz.zms;

import org.testng.annotations.Test;

public class ZMSBinderTest {

    @Test
    public void testZMSBinder() {

        System.setProperty(ZMSConsts.ZMS_PROP_FILE_NAME, "src/test/resources/zms.properties");
        System.setProperty(ZMSConsts.ZMS_PROP_FILE_STORE_PATH, "/tmp/zms_core_unit_tests/");
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN, "user.testadminuser");

        ZMSBinder binder = new ZMSBinder();
        binder.configure();
    }
}
