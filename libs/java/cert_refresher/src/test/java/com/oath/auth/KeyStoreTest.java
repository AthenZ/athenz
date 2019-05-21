/*
 * Copyright 2017 Yahoo Holdings, Inc.
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
package com.oath.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.junit.Test;

public class KeyStoreTest {

    static final String ALIAS_NAME = "cn=athenz.syncer,o=my test company,l=sunnyvale,st=ca,c=us";
    
    @Test
    public void testGetKeyStore() throws Exception {

        KeyStore keyStore = Utils.getKeyStore("truststore.jks", "123456".toCharArray());
        assertNotNull(keyStore);
        
        // default password is secret - key exception
        
        try {
            Utils.getKeyStore("truststore.jks");
            fail();
        } catch (Exception ignored) {
        }
    }


    @Test
    public void testCreateKeyStore() throws Exception {
        KeyStore keyStore = Utils.createKeyStore("rsa_public_x509.cert", "rsa_private.key");
        assertNotNull(keyStore);
        String alias = null;
        for (Enumeration<?> e = keyStore.aliases(); e.hasMoreElements(); ) {
            alias = (String)e.nextElement();
            assertEquals(ALIAS_NAME, alias);
        }
        X509Certificate[] chain = (X509Certificate[]) keyStore.getCertificateChain(alias);
        assertNotNull(chain);
        assertTrue(chain.length == 1);
    }

    @Test
    public void testCreateKeyStoreChain() throws Exception {
        KeyStore keyStore = Utils.createKeyStore("rsa_public_x510_w_intermediate.cert", "rsa_private.key");
        assertNotNull(keyStore);
        String alias = null;
        for (Enumeration<?> e = keyStore.aliases(); e.hasMoreElements(); ) {
            alias = (String)e.nextElement();
            assertEquals(ALIAS_NAME, alias);
        }
        
        X509Certificate[] chain = (X509Certificate[]) keyStore.getCertificateChain(alias);
        assertNotNull(chain);
        assertTrue(chain.length == 2);
    }
    
    @Test (expected = KeyRefresherException.class)
    public void testCreateKeyStoreEmpty() throws Exception {
        Utils.createKeyStore("rsa_public_x510_empty.cert", "rsa_private.key");
    }
}
