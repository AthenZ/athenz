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
package com.yahoo.athenz.zts.pkey.file;

import static org.testng.Assert.assertNotNull;

import org.testng.annotations.Test;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;

public class FilePrivateKeyStoreTest {

    @Test
    public void testCreateStore() {
        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();
        assertNotNull(store);
    }

    @Test
    public void testGetHostPrivateKeyExist() {

        // set default filepath property
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY, "src/test/resources/zts_private.pem");

        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();

        StringBuilder sbuilder = new StringBuilder();

        assertNotNull(store.getPrivateKey("localhost", sbuilder));
    }

    @Test
    public void testGetHostPrivateKeyPkeyNotExist() {
        // set default filepath property
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY, "src/test/resources/unknown.pem");

        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();

        StringBuilder sbuilder = new StringBuilder();

        try {
            store.getPrivateKey("localhost", sbuilder);
        } catch (RuntimeException ex) {
            assertNotNull(ex.getMessage());
        }

        // fix property
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY, "src/test/resources/zts_private.pem");

    }

    @Test
    public void testGetHostPrivateKeyInvalidFormat() {
        // set default filepath property
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY, "src/test/resources/test_public.v1");

        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();

        StringBuilder sbuilder = new StringBuilder();

        try {
            store.getPrivateKey("localhost", sbuilder);
        } catch (ResourceException ex) {
            assertNotNull(ex.getCode());
        }

        // fix property
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY, "src/test/resources/zts_private.pem");

    }
}
