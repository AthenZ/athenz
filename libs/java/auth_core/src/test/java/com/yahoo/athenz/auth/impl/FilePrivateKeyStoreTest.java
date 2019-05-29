/*
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
package com.yahoo.athenz.auth.impl;

import static org.testng.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import org.testng.annotations.Test;

import com.yahoo.athenz.auth.PrivateKeyStore;

public class FilePrivateKeyStoreTest {
    
    @Test
    public void testCreateStore() {
        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();
        assertNotNull(store);
    }
    
    @Test
    public void testRetrievePrivateKeyValid() {
        
        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        PrivateKeyStore store = factory.create();
        
        String saveProp = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/zts_private_k0.key");

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
        
        if (saveProp == null) {
            System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        } else {
            System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, saveProp);
        }
    }
    
    @Test
    public void testGetStringNullStream() throws IOException {

        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        FilePrivateKeyStore store = (FilePrivateKeyStore) factory.create();
        assertNull(store.getString(null));
    }
    
    @Test
    public void testGetString() throws IOException {
        String str = "This is a Unit Test String";
        
        FilePrivateKeyStoreFactory factory = new FilePrivateKeyStoreFactory();
        FilePrivateKeyStore store = (FilePrivateKeyStore) factory.create();
        try (InputStream is = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8))) {
            String getStr = store.getString(is);
            assertEquals(getStr, str);
        }
    }
}
