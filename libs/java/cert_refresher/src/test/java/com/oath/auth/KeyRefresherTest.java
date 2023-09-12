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

import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.security.*;
import java.util.Objects;

import static org.testng.Assert.*;

public class KeyRefresherTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private final MessageDigest md = MessageDigest.getInstance("MD5");

    public KeyRefresherTest() throws NoSuchAlgorithmException {
    }

    @Test
    public void haveFilesBeenChangedTestFilesAltered() throws Exception {

        TrustStore mockedTrustStore = Mockito.mock(TrustStore.class);
        TrustManagerProxy mockedTrustManagerProxy = Mockito.mock(TrustManagerProxy.class);
        KeyManagerProxy mockedKeyManagerProxy = Mockito.mock(KeyManagerProxy.class);

        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);
        assertTrue(keyRefresher.haveFilesBeenChanged(
                Objects.requireNonNull(classLoader.getResource("testFile")).getPath(), new byte[md.getDigestLength()]));
    }

    @Test
    public void haveFilesBeenChangedTestFilesMultiple() throws Exception {

        TrustStore mockedTrustStore = Mockito.mock(TrustStore.class);
        TrustManagerProxy mockedTrustManagerProxy = Mockito.mock(TrustManagerProxy.class);
        KeyManagerProxy mockedKeyManagerProxy = Mockito.mock(KeyManagerProxy.class);

        byte[] checksum = new byte[md.getDigestLength()];
        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);
        // first call is changed because we don't have checksum
        assertTrue(keyRefresher.haveFilesBeenChanged(
                Objects.requireNonNull(classLoader.getResource("testFile")).getPath(), checksum));
        // second call should be no change
        assertFalse(keyRefresher.haveFilesBeenChanged(
                Objects.requireNonNull(classLoader.getResource("testFile")).getPath(), checksum));
        // now let's modify our contents of the checksum
        checksum[0] = 0;
        checksum[1] = 1;
        checksum[2] = 2;
        assertTrue(keyRefresher.haveFilesBeenChanged(
                Objects.requireNonNull(classLoader.getResource("testFile")).getPath(), checksum));
    }

    @Test
    public void haveFilesBeenChangedTestFilesMultipleRelativePath() throws Exception {

        TrustStore mockedTrustStore = Mockito.mock(TrustStore.class);
        TrustManagerProxy mockedTrustManagerProxy = Mockito.mock(TrustManagerProxy.class);
        KeyManagerProxy mockedKeyManagerProxy = Mockito.mock(KeyManagerProxy.class);

        byte[] checksum = new byte[md.getDigestLength()];
        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);
        // when we pass relative path, it doesn't matter what is in the
        // checksum as we always return false
        assertFalse(keyRefresher.haveFilesBeenChanged("testfile", checksum));
        checksum[0] = 0;
        checksum[1] = 1;
        checksum[2] = 2;
        assertFalse(keyRefresher.haveFilesBeenChanged("testfile", checksum));
    }

    @Test
    public void filesBeenChangedTestIOException() throws Exception {

        TrustStore mockedTrustStore = Mockito.mock(TrustStore.class);
        TrustManagerProxy mockedTrustManagerProxy = Mockito.mock(TrustManagerProxy.class);
        KeyManagerProxy mockedKeyManagerProxy = Mockito.mock(KeyManagerProxy.class);

        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);
        assertFalse(keyRefresher.haveFilesBeenChanged(
                Objects.requireNonNull(classLoader.getResource("")).getPath(), new byte[md.getDigestLength()]));
    }

    @Test
    public void haveFilesBeenChangedTestFilesSame() throws Exception {

        TrustStore mockedTrustStore = Mockito.mock(TrustStore.class);
        TrustManagerProxy mockedTrustManagerProxy = Mockito.mock(TrustManagerProxy.class);
        KeyManagerProxy mockedKeyManagerProxy = Mockito.mock(KeyManagerProxy.class);

        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);

        byte[] stuff = new byte[md.getDigestLength()];
        assertTrue(keyRefresher.haveFilesBeenChanged(
                Objects.requireNonNull(classLoader.getResource("testFile")).getPath(), stuff));
        assertFalse(keyRefresher.haveFilesBeenChanged(
                Objects.requireNonNull(classLoader.getResource("testFile")).getPath(), stuff));
    }

    @Test
    public void scanForFileChangesTestNoChanges() throws Exception {

        TrustStore mockedTrustStore = Mockito.mock(TrustStore.class);
        TrustManagerProxy mockedTrustManagerProxy = Mockito.mock(TrustManagerProxy.class);
        KeyManagerProxy mockedKeyManagerProxy = Mockito.mock(KeyManagerProxy.class);

        final String certFile = Objects.requireNonNull(classLoader.getResource("gdpr.aws.core.cert.pem")).getFile();
        final String keyFile = Objects.requireNonNull(classLoader.getResource("unit_test_gdpr.aws.core.key.pem")).getFile();

        KeyRefresher keyRefresher = new KeyRefresher(certFile, keyFile, mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy) {
            @Override
            protected boolean haveFilesBeenChanged(String filePath, byte[] checksum) {
                return false;
            }
        };
        keyRefresher.startup(1);
        Thread.sleep(200);
        keyRefresher.shutdown();
    }

    @Test
    public void scanForFileChangesTestWithChanges() throws Exception {

        TrustStore mockedTrustStore = Mockito.mock(TrustStore.class);
        TrustManagerProxy mockedTrustManagerProxy = Mockito.mock(TrustManagerProxy.class);
        KeyManagerProxy mockedKeyManagerProxy = Mockito.mock(KeyManagerProxy.class);

        TestKeyRefresherListener listener = new TestKeyRefresherListener();

        final String certFile = Objects.requireNonNull(classLoader.getResource("gdpr.aws.core.cert.pem")).getFile();
        final String keyFile = Objects.requireNonNull(classLoader.getResource("unit_test_gdpr.aws.core.key.pem")).getFile();

        KeyRefresher keyRefresher = new KeyRefresher(certFile, keyFile,
            mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy, listener) {
            @Override
            protected boolean haveFilesBeenChanged(String filePath, byte[] checksum) {
                return true;
            }
        };

        keyRefresher.startup(1);
        Thread.sleep(1000);
        assertTrue(listener.keyChanged);
        keyRefresher.shutdown();
    }

    @Test
    public void testGenerateKeyRefresherFromCaCert() throws Exception {

        KeyRefresher keyRefresher = Utils.generateKeyRefresher("truststore.jks", "gdpr.aws.core.cert.pem",
                "unit_test_gdpr.aws.core.key.pem");
        assertNotNull(keyRefresher);

        keyRefresher = Utils.generateKeyRefresher("truststore.jks", "secret", "gdpr.aws.core.cert.pem",
                "unit_test_gdpr.aws.core.key.pem");
        assertNotNull(keyRefresher);

        final String caCertPath = Objects.requireNonNull(classLoader.getResource("ca.cert.pem")).getFile();
        keyRefresher = Utils.generateKeyRefresherFromCaCert(caCertPath, "gdpr.aws.core.cert.pem",
                "unit_test_gdpr.aws.core.key.pem");
        keyRefresher.startup();
        Thread.sleep(500);
        assertNotNull(keyRefresher);
        keyRefresher.shutdown();
    }

    static class TestKeyRefresherListener implements KeyRefresherListener {
        public boolean keyChanged = false;
        @Override
        public void onKeyChangeEvent() {
            keyChanged = true;
        }
    }
}
