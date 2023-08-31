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
package com.oath.auth;

import com.google.common.io.Resources;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import static org.testng.Assert.*;

public class KeyStoreTest {

    static final String ALIAS_NAME = "cn=athenz.syncer,o=my test company,l=sunnyvale,st=ca,c=us";

    @Test
    public void testGetKeyStore() throws Exception {

        // default password is secret

        KeyStore keyStore = Utils.getKeyStore("truststore.jks", "secret".toCharArray());
        assertNotNull(keyStore);

        keyStore = Utils.getKeyStore("truststore.jks");
        assertNotNull(keyStore);

        try {
            Utils.getKeyStore("truststore.jks", "123456".toCharArray());
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testCreateKeyStoreRSA() throws Exception {
        KeyStore keyStore = Utils.createKeyStore("rsa_public_x509.cert", "unit_test_rsa_private.key");
        assertNotNull(keyStore);
        String alias = null;
        for (Enumeration<?> e = keyStore.aliases(); e.hasMoreElements(); ) {
            alias = (String) e.nextElement();
            assertEquals(ALIAS_NAME, alias);
        }
        X509Certificate[] chain = (X509Certificate[]) keyStore.getCertificateChain(alias);
        assertNotNull(chain);
        assertEquals(1, chain.length);
    }

    @Test
    public void testCreateKeyStoreEC() throws Exception {
        KeyStore keyStore = Utils.createKeyStore("ec_public_x509.cert", "unit_test_ec_private.key");
        assertNotNull(keyStore);
        String alias = null;
        for (Enumeration<?> e = keyStore.aliases(); e.hasMoreElements(); ) {
            alias = (String) e.nextElement();
            assertEquals(ALIAS_NAME, alias);
        }
        X509Certificate[] chain = (X509Certificate[]) keyStore.getCertificateChain(alias);
        assertNotNull(chain);
        assertEquals(1, chain.length);
    }

    @Test
    public void testCreateKeyStoreRSAMismatch() throws Exception {

        // first enabled public key match
        Utils.setDisablePublicKeyCheck(false);
        try {
            Utils.createKeyStore("rsa_public_x509.cert", "unit_test_rsa_private2.key");
        } catch (KeyRefresherException ex) {
            assertEquals(ex.getMessage(), "Public key mismatch");
        }
        // now disable public key match
        Utils.setDisablePublicKeyCheck(true);
        KeyStore keyStore = Utils.createKeyStore("rsa_public_x509.cert", "unit_test_rsa_private.key");
        assertNotNull(keyStore);
        Utils.setDisablePublicKeyCheck(false);
    }

    @Test
    public void testCreateKeyStoreECMismatch() throws Exception {

        // first enabled public key match
        Utils.setDisablePublicKeyCheck(false);
        try {
            Utils.createKeyStore("ec_public_x509.cert", "unit_test_ec_private2.key");
        } catch (KeyRefresherException ex) {
            assertEquals(ex.getMessage(), "Public key mismatch");
        }
        // now disable public key match
        Utils.setDisablePublicKeyCheck(true);
        KeyStore keyStore = Utils.createKeyStore("ec_public_x509.cert", "unit_test_ec_private2.key");
        assertNotNull(keyStore);
        Utils.setDisablePublicKeyCheck(false);
    }

    @Test
    public void testCreateKeyStoreChain() throws Exception {
        KeyStore keyStore = Utils.createKeyStore("rsa_public_x510_w_intermediate.cert", "unit_test_rsa_private.key");
        assertNotNull(keyStore);
        String alias = null;
        for (Enumeration<?> e = keyStore.aliases(); e.hasMoreElements(); ) {
            alias = (String) e.nextElement();
            assertEquals(ALIAS_NAME, alias);
        }

        X509Certificate[] chain = (X509Certificate[]) keyStore.getCertificateChain(alias);
        assertNotNull(chain);
        assertEquals(2, chain.length);
    }

    @Test
    public void testCreateKeyStoreFromPems() throws Exception {
        String athenzPublicCertPem = Resources.toString(
                Resources.getResource("rsa_public_x510_w_intermediate.cert"), StandardCharsets.UTF_8);
        String athenzPrivateKeyPem = Resources.toString(
                Resources.getResource("unit_test_rsa_private.key"), StandardCharsets.UTF_8);
        KeyStore keyStore = Utils.createKeyStoreFromPems(athenzPublicCertPem, athenzPrivateKeyPem);
        assertNotNull(keyStore);
        String alias = null;
        for (Enumeration<?> e = keyStore.aliases(); e.hasMoreElements(); ) {
            alias = (String) e.nextElement();
            assertEquals(ALIAS_NAME, alias);
        }

        X509Certificate[] chain = (X509Certificate[]) keyStore.getCertificateChain(alias);
        assertNotNull(chain);
        assertEquals(2, chain.length);
    }

    @Test(expectedExceptions = {KeyRefresherException.class})
    public void testCreateKeyStoreEmpty() throws Exception {
        Utils.createKeyStore("rsa_public_x510_empty.cert", "unit_test_rsa_private.key");
    }
}
