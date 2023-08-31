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

import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

public class UtilsTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @Test(expectedExceptions = {FileNotFoundException.class})
    public void getKeyStoreTest() throws IOException, KeyRefresherException {
        Utils.getKeyStore(null);
        fail("Should have thrown FileNotFoundException.");
    }
    
    @Test
    public void testCreateKeyStoreFailures() throws IOException, KeyRefresherException, InterruptedException {

        final String certPath = Objects.requireNonNull(classLoader.getResource("gdpr.aws.core.cert.pem")).getFile();
        final String keyPath = Objects.requireNonNull(classLoader.getResource("unit_test_gdpr.aws.core.key.pem")).getFile();

        try {
            Utils.createKeyStore(null, null);
            fail();
        } catch (FileNotFoundException ignored) {
        }
        try {
            Utils.createKeyStore("", keyPath);
            fail();
        } catch (FileNotFoundException ignored) {
        }
        try {
            Utils.createKeyStore(certPath, null);
            fail();
        } catch (FileNotFoundException ignored) {
        }
        try {
            Utils.createKeyStore(certPath, "");
            fail();
        } catch (FileNotFoundException ignored) {
        }
    }
    
    @Test (expectedExceptions = {FileNotFoundException.class})
    public void getKeyManagersTest() throws IOException, InterruptedException, KeyRefresherException {
        Utils.getKeyManagers(null, null);
        fail("Should have thrown FileNotFoundException.");
    }

    @Test
    public void testBuildSSLContextPEM() throws KeyRefresherException, IOException {

        String caCertsPem = new String(readFileContents(
                Objects.requireNonNull(classLoader.getResource("ca.cert.pem")).getFile()));
        String certPem = new String(readFileContents(
                Objects.requireNonNull(classLoader.getResource("gdpr.aws.core.cert.pem")).getFile()));
        String keyPem = new String(readFileContents(
                Objects.requireNonNull(classLoader.getResource("unit_test_gdpr.aws.core.key.pem")).getFile()));

        SSLContext sslContext = Utils.buildSSLContext(caCertsPem, certPem, keyPem);
        assertNotNull(sslContext);

        // now try without the ca certs pem - using jdk default truststore

        sslContext = Utils.buildSSLContext(null, certPem, keyPem);
        assertNotNull(sslContext);
    }

    public static byte[] readFileContents(final String filename) {

        File file = new File(filename);

        byte[] data = null;
        try {
            data = Files.readAllBytes(Paths.get(file.toURI()));
        } catch (Exception ex) {
            fail(ex.getMessage());
        }

        return data;
    }
}
