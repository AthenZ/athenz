/*
 * Copyright 2017 Yahoo Holdings Inc.
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
package com.yahoo.athenz.zts;

import static org.testng.Assert.assertNotNull;

import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import org.testng.annotations.Test;

import java.io.File;

public class ZTSTest {

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";

    @Test
    public void testZTS() {
        ZTS zts = new ZTS();
        assertNotNull(zts);
    }

    @Test
    public void testZTSBinder() {
        System.setProperty(ZTSConsts.ZTS_PROP_CHANGE_LOG_STORE_DIR, ZTS_DATA_STORE_PATH);
        System.setProperty(ZTSConsts.ZTS_PROP_CHANGE_LOG_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.zts.store.impl.MockZMSFileChangeLogStoreFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
        System.setProperty(ZTSConsts.ZTS_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTSConsts.ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/zts_private.pem");

        ZTSBinder binder = new ZTSBinder();
        binder.configure();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_CHANGE_LOG_STORE_DIR);
        System.clearProperty(ZTSConsts.ZTS_PROP_CHANGE_LOG_STORE_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH);
    }
}
