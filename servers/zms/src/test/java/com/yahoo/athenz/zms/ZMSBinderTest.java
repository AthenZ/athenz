package com.yahoo.athenz.zms;

import com.wix.mysql.EmbeddedMysql;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class ZMSBinderTest {

    private static final String DB_USER = "admin";
    private static final String DB_PASS = "unit-test";

    private EmbeddedMysql mysqld;

    @BeforeClass
    public void setUp() {
        mysqld = ZMSTestUtils.startMemoryMySQL(DB_USER, DB_PASS);

        System.setProperty(ZMSConsts.ZMS_PROP_OBJECT_STORE_FACTORY_CLASS, "com.yahoo.athenz.zms.store.impl.JDBCObjectStoreFactory");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE, "jdbc:mysql://localhost:3310/zms_server");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_USER, DB_USER);
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_PASSWORD, DB_PASS);
    }

    @AfterClass
    public void shutdown() {
        ZMSTestUtils.stopMemoryMySQL(mysqld);
    }

    @Test
    public void testZMSBinder() {

        System.setProperty(ZMSConsts.ZMS_PROP_FILE_NAME, "src/test/resources/zms.properties");
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN, "user.testadminuser");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zms_private.pem");

        ZMSBinder binder = new ZMSBinder();
        binder.configure();
    }
}
