package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import org.testng.annotations.Test;

public class ZMSBinderTest {

    @Test
    public void testZMSBinder() {

        System.setProperty(ZMSConsts.ZMS_PROP_FILE_NAME, "src/test/resources/zms.properties");
        System.setProperty(ZMSConsts.ZMS_PROP_FILE_STORE_PATH, "/tmp/zms_core_unit_tests/");
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN, "user.testadminuser");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/zms_private.pem");

        ZMSBinder binder = new ZMSBinder();
        binder.configure();
    }
}
