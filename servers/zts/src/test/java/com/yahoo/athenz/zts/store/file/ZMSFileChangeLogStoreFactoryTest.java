/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts.store.file;

import static org.testng.Assert.assertNotNull;

import java.io.File;
import java.security.PrivateKey;

import org.testng.annotations.Test;

import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.store.ChangeLogStore;
import com.yahoo.athenz.zts.store.file.ZMSFileChangeLogStoreFactory;

public class ZMSFileChangeLogStoreFactoryTest {

    static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    
    @Test
    public void testCreateStore() {
        
        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File privKeyFile = new File(privKeyName);
        String privKey = Crypto.encodedFile(privKeyFile);
        PrivateKey pkey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        ZMSFileChangeLogStoreFactory factory = new ZMSFileChangeLogStoreFactory();
        ChangeLogStore store = factory.create(ZTS_DATA_STORE_PATH, pkey, "0", null);
        assertNotNull(store);
    }
}
