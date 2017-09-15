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
import mockit.Deencapsulation;
import mockit.Expectations;
import mockit.Mock;
import mockit.MockUp;
import mockit.Mocked;
import org.junit.Test;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class KeyRefresherTest {

    @Mocked
    private KeyManagerProxy mockedKeyManagerProxy;

    @Mocked
    private TrustManagerProxy mockedTrustManagerProxy;

    @Test
    public void haveFilesBeenChangedTestFilesAltered() throws NoSuchAlgorithmException {
        KeyRefresher keyRefresher = new KeyRefresher("", "", "", mockedKeyManagerProxy, mockedTrustManagerProxy);
        assertTrue(keyRefresher.haveFilesBeenChanged(Resources.getResource("testFile").getPath(), new byte[0]));
    }

    @Test
    public void filesBeenChangedTestIOException() throws NoSuchAlgorithmException {
        KeyRefresher keyRefresher = new KeyRefresher("", "", "", mockedKeyManagerProxy, mockedTrustManagerProxy);
        assertFalse(keyRefresher.haveFilesBeenChanged(Resources.getResource("").getPath(), new byte[0]));
    }

    @Test
    public void haveFilesBeenChangedTestFilesSame(@Mocked MessageDigest mockedMessageDigest) throws NoSuchAlgorithmException {
        KeyRefresher keyRefresher = new KeyRefresher("", "", "", mockedKeyManagerProxy, mockedTrustManagerProxy);

        byte[] stuff = new byte[0];
        new Expectations() {{
           mockedMessageDigest.digest(); result = stuff;
        }};

        assertFalse(keyRefresher.haveFilesBeenChanged(Resources.getResource("testFile").getPath(), stuff));
    }

    @Test
    public void scanForFileChangesTestNoChanges(@Mocked KeyManagerProxy mockedKeyManagerProxy,
                                                @Mocked TrustManagerProxy mockedTrustManagerProxy) throws NoSuchAlgorithmException, InterruptedException {

        new Expectations() {{
           mockedKeyManagerProxy.setKeyManager((KeyManager[]) any); times = 0;
           mockedTrustManagerProxy.setTrustManager((TrustManager[]) any); times = 0;
        }};

        new MockUp<KeyRefresher>() {

            @Mock
            boolean haveFilesBeenChanged(String filePath, byte[] checksum) {
                return false;
            }

        };
        KeyRefresher keyRefresher = new KeyRefresher("", "", "", mockedKeyManagerProxy, mockedTrustManagerProxy);
        Deencapsulation.setField(keyRefresher, "RETRY_CHECK_FRQUENCY", 1);
        keyRefresher.startup();
        Thread.sleep(2);
        keyRefresher.shutdown();
    }

    @Test
    public void scanForFileChangesTestWithChanges(@Mocked KeyManagerProxy mockedKeyManagerProxy,
                                                @Mocked TrustManagerProxy mockedTrustManagerProxy) throws NoSuchAlgorithmException, InterruptedException {

        new Expectations() {{
            mockedKeyManagerProxy.setKeyManager((KeyManager[]) any); minTimes = 1;
            mockedTrustManagerProxy.setTrustManager((TrustManager[]) any); minTimes = 1;
        }};

        new MockUp<KeyRefresher>() {

            @Mock
            boolean haveFilesBeenChanged(String filePath, byte[] checksum) {
                return true;
            }

        };
        KeyRefresher keyRefresher = new KeyRefresher("", "", "", mockedKeyManagerProxy, mockedTrustManagerProxy);
        Deencapsulation.setField(keyRefresher, "RETRY_CHECK_FRQUENCY", 1);
        keyRefresher.startup();
        Thread.sleep(2);
        keyRefresher.shutdown();
    }
}
