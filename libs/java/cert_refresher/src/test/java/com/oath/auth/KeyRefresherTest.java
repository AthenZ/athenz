package com.oath.auth;

/**
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

import com.google.common.io.Resources;
import mockit.Expectations;
import mockit.Mocked;
import org.junit.Test;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import java.security.MessageDigest;

import static org.junit.Assert.*;

public class KeyRefresherTest {

    @Mocked
    private KeyManagerProxy mockedKeyManagerProxy;

    @Mocked
    private TrustManagerProxy mockedTrustManagerProxy;

    @Mocked
    private TrustStore mockedTrustStore;

    @Test
    public void haveFilesBeenChangedTestFilesAltered() throws Exception {
        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);
        assertTrue(keyRefresher.haveFilesBeenChanged(Resources.getResource("testFile").getPath(), new byte[0]));
    }

    @Test
    public void filesBeenChangedTestIOException() throws Exception {
        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);
        assertFalse(keyRefresher.haveFilesBeenChanged(Resources.getResource("").getPath(), new byte[0]));
    }

    @Test
    public void haveFilesBeenChangedTestFilesSame(@Mocked MessageDigest mockedMessageDigest) throws Exception {
        KeyRefresher keyRefresher = new KeyRefresher("", "", mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy);

        byte[] stuff = new byte[0];
        new Expectations() {{
           mockedMessageDigest.digest(); result = stuff;
        }};

        assertFalse(keyRefresher.haveFilesBeenChanged(Resources.getResource("testFile").getPath(), stuff));
    }

    @Test
    public void scanForFileChangesTestNoChanges(@Mocked KeyManagerProxy mockedKeyManagerProxy,
                                                @Mocked TrustManagerProxy mockedTrustManagerProxy)
        throws Exception {

        new Expectations() {{
           mockedKeyManagerProxy.setKeyManager((KeyManager[]) any); times = 0;
           mockedTrustManagerProxy.setTrustManager((TrustManager[]) any); times = 0;
        }};

        String certFile = Resources.getResource("gdpr.aws.core.cert.pem").getFile();
        String keyFile = Resources.getResource("gdpr.aws.core.key.pem").getFile();

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

        String certFile = Resources.getResource("gdpr.aws.core.cert.pem").getFile();
        String keyFile = Resources.getResource("gdpr.aws.core.key.pem").getFile();

        KeyRefresher keyRefresher = new KeyRefresher(certFile, keyFile,
            mockedTrustStore, mockedKeyManagerProxy, mockedTrustManagerProxy) {
            @Override
            protected boolean haveFilesBeenChanged(String filePath, byte[] checksum) {
                return true;
            }
        };

        keyRefresher.startup(1);
        Thread.sleep(500);
        keyRefresher.shutdown();
    }

    @Test
    public void testGenerateKeyRefresherFromCaCert() throws Exception {
        
        KeyRefresher keyRefresher = Utils.generateKeyRefresher("ca.cert.pem", "gdpr.aws.core.cert.pem",
                "gdpr.aws.core.key.pem");
        assertNotNull(keyRefresher);
        
        keyRefresher = Utils.generateKeyRefresherFromCaCert("ca.cert.pem", "gdpr.aws.core.cert.pem",
                "gdpr.aws.core.key.pem");
        assertNotNull(keyRefresher);
    }
}
