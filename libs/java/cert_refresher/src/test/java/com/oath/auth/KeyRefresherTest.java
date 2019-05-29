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

import mockit.Expectations;
import mockit.Mocked;
import org.junit.Test;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import java.security.*;

import static org.junit.Assert.*;

public class KeyRefresherTest {

    private final MessageDigest md = MessageDigest.getInstance("MD5");
    private ClassLoader classLoader = this.getClass().getClassLoader();

    @Mocked
    private KeyManagerProxy mockedKeyManagerProxy;

    @Mocked
    private TrustManagerProxy mockedTrustManagerProxy;

    @Mocked
    private TrustStore mockedTrustStore;

    public KeyRefresherTest() throws NoSuchAlgorithmException {
    }

    @Test
    public void haveFilesBeenChangedTestFilesAltered() throws Exception {
        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);
        assertTrue(keyRefresher.haveFilesBeenChanged(classLoader.getResource("testFile").getPath(), new byte[md.getDigestLength()]));
    }

    @Test
    public void haveFilesBeenChangedTestFilesMultiple() throws Exception {
        byte[] checksum = new byte[md.getDigestLength()];
        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);
        // first call is changed because we don't have checksum
        assertTrue(keyRefresher.haveFilesBeenChanged(classLoader.getResource("testFile").getPath(), checksum));
        // second call should be no change
        assertFalse(keyRefresher.haveFilesBeenChanged(classLoader.getResource("testFile").getPath(), checksum));
        // now let's modify our contents of the checksum
        checksum[0] = 0;
        checksum[1] = 1;
        checksum[2] = 2;
        assertTrue(keyRefresher.haveFilesBeenChanged(classLoader.getResource("testFile").getPath(), checksum));
    }

    @Test
    public void haveFilesBeenChangedTestFilesMultipleRelativePath() throws Exception {
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
        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);
        assertFalse(keyRefresher.haveFilesBeenChanged(classLoader.getResource("").getPath(), new byte[md.getDigestLength()]));
    }

    @Test
    public void haveFilesBeenChangedTestFilesSame(@Mocked MessageDigest mockedMessageDigest) throws Exception {
        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);

        byte[] stuff = new byte[md.getDigestLength()];
        new Expectations() {{
           mockedMessageDigest.digest(); result = stuff;
        }};

        assertFalse(keyRefresher.haveFilesBeenChanged(classLoader.getResource("testFile").getPath(), stuff));
    }

    @Test
    public void scanForFileChangesTestNoChanges(@Mocked KeyManagerProxy mockedKeyManagerProxy,
                                                @Mocked TrustManagerProxy mockedTrustManagerProxy)
        throws Exception {

        new Expectations() {{
           mockedKeyManagerProxy.setKeyManager((KeyManager[]) any); times = 0;
           mockedTrustManagerProxy.setTrustManager((TrustManager[]) any); times = 0;
        }};

        String certFile = classLoader.getResource("gdpr.aws.core.cert.pem").getFile();
        String keyFile = classLoader.getResource("gdpr.aws.core.key.pem").getFile();

        KeyRefresher keyRefresher = new KeyRefresher(certFile, keyFile, mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy){
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
    public void scanForFileChangesTestWithChanges(@Mocked KeyManagerProxy mockedKeyManagerProxy,
        @Mocked TrustManagerProxy mockedTrustManagerProxy)
        throws Exception {

        new Expectations() {{
            mockedKeyManagerProxy.setKeyManager((KeyManager[]) any); minTimes = 1;
            mockedTrustManagerProxy.setTrustManager((TrustManager[]) any);
            minTimes = 1;
        }};

        String certFile = classLoader.getResource("gdpr.aws.core.cert.pem").getFile();
        String keyFile = classLoader.getResource("gdpr.aws.core.key.pem").getFile();

        KeyRefresher keyRefresher = new KeyRefresher(certFile, keyFile,
            mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy) {
            @Override
            protected boolean haveFilesBeenChanged(String filePath, byte[] checksum) {
                return true;
            }
        };

        keyRefresher.startup(1);
        Thread.sleep(1000);
        keyRefresher.shutdown();
    }

    @Test
    public void testGenerateKeyRefresherFromCaCert() throws Exception {
        
        KeyRefresher keyRefresher = Utils.generateKeyRefresher("ca.cert.pem", "gdpr.aws.core.cert.pem",
                "gdpr.aws.core.key.pem");
        assertNotNull(keyRefresher);
        
        keyRefresher = Utils.generateKeyRefresherFromCaCert("ca.cert.pem", "gdpr.aws.core.cert.pem",
                "gdpr.aws.core.key.pem");
        keyRefresher.startup();
        Thread.sleep(500);
        assertNotNull(keyRefresher);
        keyRefresher.shutdown();
    }
}
