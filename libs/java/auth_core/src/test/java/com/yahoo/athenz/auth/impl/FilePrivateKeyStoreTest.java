/*
 * Copyright The Athenz Authors
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
package com.yahoo.athenz.auth.impl;

import static org.testng.Assert.*;

import java.security.PrivateKey;

import com.yahoo.athenz.auth.ServerPrivateKey;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.PrivateKeyStore;

public class FilePrivateKeyStoreTest {
    
    @Test
    public void testCreateStore() {
        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();
        assertNotNull(store);
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testRetrievePrivateKeyValid() {
        
        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();
        
        String saveProp = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_private_k0.key");

        StringBuilder keyId = new StringBuilder(256);
        PrivateKey privKey = store.getPrivateKey("zms", "localhost", keyId);
        assertNotNull(privKey);
        
        if (saveProp == null) {
            System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        } else {
            System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, saveProp);
        }
    }

    @Test
    public void testRetrieveRSAPrivateKeyValid() {

        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();

        String saveProp = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY);
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY,
                "src/test/resources/unit_test_zts_private_k0.key");

        ServerPrivateKey privKey = store.getPrivateKey("zms", "localhost", "us-east-1", "rsa");
        assertNotNull(privKey);

        if (saveProp == null) {
            System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY);
        } else {
            System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY, saveProp);
        }
    }

    @Test
    public void testRetrieveECPrivateKeyValid() {

        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();

        String saveProp = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY,
                "src/test/resources/unit_test_ec_private.key");

        ServerPrivateKey privKey = store.getPrivateKey("zms", "localhost", "us-east-1", "ec");
        assertNotNull(privKey);

        if (saveProp == null) {
            System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
        } else {
            System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY, saveProp);
        }
    }

    @Test
    public void testRetrieveAlgoPrivateKeyInalid() {

        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();

        String saveProp = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);

        assertNull(store.getPrivateKey("app", "localhost", "us-east-1", "ec"));
        assertNull(store.getPrivateKey("zms", "localhost", "us-east-1", "unknown"));

        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
        assertNull(store.getPrivateKey("zms", "localhost", "us-east-1", "ec"));

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY,
                "src/test/resources/ec_public_invalid.key");
        assertNull(store.getPrivateKey("zms", "localhost", "us-east-1", "ec"));

        if (saveProp == null) {
            System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
        } else {
            System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY, saveProp);
        }
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testRetrievePrivateKeyInValid() {
        
        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();
        
        String saveProp = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/zts_private_k0_invalid.pem");
        
        try {
            StringBuilder keyId = new StringBuilder(256);
            store.getPrivateKey("zts", "localhost", keyId);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        StringBuilder keyId = new StringBuilder(256);
        assertNull(store.getPrivateKey("zts", "localhost", keyId));

        if (saveProp == null) {
            System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        } else {
            System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, saveProp);
        }
    }
}
