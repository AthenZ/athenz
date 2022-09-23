/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.yahoo.athenz.common.server.store.impl;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.PROP_DATA_STORE_SUBDIR;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Objects;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.store.ChangeLogStoreFactory;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.util.Crypto;

public class ZMSFileChangeLogStoreFactoryTest {

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    
    @Test
    public void testCreateStore() {
        
        File privKeyFile = new File("src/test/resources/unit_test_zts_private.pem");
        String privKey = Crypto.encodedFile(privKeyFile);
        PrivateKey pkey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        ZMSFileChangeLogStoreFactory factory = new ZMSFileChangeLogStoreFactory();
        ChangeLogStore store = factory.create(ZTS_DATA_STORE_PATH, pkey, "0");
        assertNotNull(store);
    }

    @Test
    public void testCreateMTLSClientStore() {

        setupMTLSSettings();

        ZMSFileChangeLogStoreFactory factory = new ZMSFileChangeLogStoreFactory();
        ChangeLogStore store = factory.create(ZTS_DATA_STORE_PATH, null, null);
        assertNotNull(store);
        assertTrue(store instanceof ZMSFileMTLSChangeLogStore);

        clearMTLSSettings();
    }

    @Test
    public void testCreateMTLSClientStoreInvalidUrl() {

        setupMTLSSettings();
        System.clearProperty(PROP_ATHENZ_CONF);

        ZMSFileChangeLogStoreFactory factory = new ZMSFileChangeLogStoreFactory();
        try {
            factory.create(ZTS_DATA_STORE_PATH, null, null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }

        clearMTLSSettings();
    }

    @Test
    public void testCreateMTLSClientStoreInvalidTrustStorePassword() {

        setupMTLSSettings();
        System.clearProperty("athenz.common.server.clog.zts_server_trust_store_password_name");

        ZMSFileChangeLogStoreFactory factory = new ZMSFileChangeLogStoreFactory();
        try {
            factory.create(ZTS_DATA_STORE_PATH, null, null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }

        clearMTLSSettings();
    }

    @Test
    public void testCreateMTLSClientStoreWithKeyStoree() {

        setupMTLSSettings();
        PrivateKeyStore privateKeyStore = new PrivateKeyStore() {
            @Override
            public String getApplicationSecret(String appName, String keyName) {
                return keyName;
            }
        };

        ZMSFileChangeLogStoreFactory factory = new ZMSFileChangeLogStoreFactory();
        factory.setPrivateKeyStore(privateKeyStore);
        ChangeLogStore store = factory.create(ZTS_DATA_STORE_PATH, null, null);
        assertNotNull(store);
        assertTrue(store instanceof ZMSFileMTLSChangeLogStore);

        clearMTLSSettings();
    }

    @Test
    public void testChangeLogFactoryInterface() {
        ChangeLogStoreFactory factory = (ztsHomeDir, privateKey, privateKeyId) -> null;

        // default function so no failure is expected

        factory.setPrivateKeyStore(null);
    }

    private void setupMTLSSettings() {
        ClassLoader classLoader = this.getClass().getClassLoader();

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty("athenz.common.server.clog.zts_server_trust_store_path",
                Objects.requireNonNull(classLoader.getResource("driver.truststore.jks")).getFile());
        System.setProperty("athenz.common.server.clog.zts_server_cert_path",
                Objects.requireNonNull(classLoader.getResource("driver.cert.pem")).getFile());
        System.setProperty("athenz.common.server.clog.zts_server_key_path",
                Objects.requireNonNull(classLoader.getResource("unit_test_driver.key.pem")).getFile());

        System.setProperty("athenz.common.server.clog.zts_server_trust_store_password_name", "123456");
    }

    private void clearMTLSSettings() {
        System.clearProperty("athenz.common.server.clog.zts_server_trust_store_path");
        System.clearProperty("athenz.common.server.clog.zts_server_cert_path");
        System.clearProperty("athenz.common.server.clog.zts_server_key_path");
        System.clearProperty("athenz.common.server.clog.zts_server_trust_store_password_name");
        System.clearProperty(PROP_ATHENZ_CONF);
    }

    @Test
    public void testCreateStoreDiffLocation() throws IOException {

        File privKeyFile = new File("src/test/resources/unit_test_zts_private.pem");
        String privKey = Crypto.encodedFile(privKeyFile);
        PrivateKey pkey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        System.setProperty(PROP_DATA_STORE_SUBDIR, "custom_loc");
        ZMSFileChangeLogStoreFactory factory = new ZMSFileChangeLogStoreFactory();
        ChangeLogStore store = factory.create(ZTS_DATA_STORE_PATH, pkey, "0");
        assertNotNull(store);
        Path path = Paths.get(ZTS_DATA_STORE_PATH + File.separator + "custom_loc");
        assertTrue(Files.exists(path));
        Files.delete(path);
        System.clearProperty(PROP_DATA_STORE_SUBDIR);
    }
}
