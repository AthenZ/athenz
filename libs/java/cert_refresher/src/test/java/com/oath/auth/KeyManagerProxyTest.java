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

import javax.net.ssl.KeyManager;
import javax.net.ssl.X509ExtendedKeyManager;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.assertNull;

public class KeyManagerProxyTest {

    @Test
    public void testKeyManagerProxyGeClientAliases() {

        X509ExtendedKeyManager mockedKeyManager = Mockito.mock(X509ExtendedKeyManager.class);
        Mockito.when(mockedKeyManager.getClientAliases("cert", null)).thenReturn(null);
        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(new KeyManager[]{mockedKeyManager});
        assertNull(keyManagerProxy.getClientAliases("cert", null));
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    public void testKeyManagerProxyChooseClientAlias() {

        X509ExtendedKeyManager mockedKeyManager = Mockito.mock(X509ExtendedKeyManager.class);
        Mockito.when(mockedKeyManager.chooseClientAlias(null, null, null)).thenReturn(null);
        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(new KeyManager[]{mockedKeyManager});
        assertNull(keyManagerProxy.chooseClientAlias(null, null, null));
    }

    @Test
    public void testKeyManagerProxyGetServerAliases() {

        X509ExtendedKeyManager mockedKeyManager = Mockito.mock(X509ExtendedKeyManager.class);
        Mockito.when(mockedKeyManager.getServerAliases("cert", null)).thenReturn(null);
        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(new KeyManager[]{mockedKeyManager});
        assertNull(keyManagerProxy.getServerAliases("cert", null));
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    public void testKeyManagerProxyChooseServerAlias() {

        X509ExtendedKeyManager mockedKeyManager = Mockito.mock(X509ExtendedKeyManager.class);
        Mockito.when(mockedKeyManager.chooseServerAlias("cert", null, null)).thenReturn(null);
        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(new KeyManager[]{mockedKeyManager});
        assertNull(keyManagerProxy.chooseServerAlias("cert", null, null));
    }

    @Test
    public void testKeyManagerProxyGetCertificateChain() {

        X509ExtendedKeyManager mockedKeyManager = Mockito.mock(X509ExtendedKeyManager.class);
        Mockito.when(mockedKeyManager.getCertificateChain("cert")).thenReturn(null);
        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(new KeyManager[]{mockedKeyManager});
        assertNull(keyManagerProxy.getCertificateChain("cert"));
    }

    @Test
    public void testKeyManagerProxyGetPrivateKey() {

        X509ExtendedKeyManager mockedKeyManager = Mockito.mock(X509ExtendedKeyManager.class);
        Mockito.when(mockedKeyManager.getPrivateKey("cert")).thenReturn(null);
        KeyManagerProxy keyManagerProxy = new KeyManagerProxy(new KeyManager[]{mockedKeyManager});
        assertNull(keyManagerProxy.getPrivateKey("cert"));
    }
}
