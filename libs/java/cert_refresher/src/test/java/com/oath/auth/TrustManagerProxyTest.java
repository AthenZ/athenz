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

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import java.security.cert.CertificateException;

import static org.testng.Assert.assertNull;

public class TrustManagerProxyTest {

    @Test
    public void testTrustManagerProxyCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager mockedTrustManager = Mockito.mock(X509ExtendedTrustManager.class);
        Mockito.doNothing().when(mockedTrustManager).checkClientTrusted(null, "cert");
        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(new TrustManager[]{mockedTrustManager});
        trustManagerProxy.checkClientTrusted(null, "cert");
        Mockito.verify(mockedTrustManager, Mockito.times(1)).checkClientTrusted(null, "cert");
    }

    @Test
    public void testTrustManagerProxyCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager mockedTrustManager = Mockito.mock(X509ExtendedTrustManager.class);
        Mockito.doNothing().when(mockedTrustManager).checkServerTrusted(null, "cert");
        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(new TrustManager[]{mockedTrustManager});
        trustManagerProxy.checkServerTrusted(null, "cert");
        Mockito.verify(mockedTrustManager, Mockito.times(1)).checkServerTrusted(null, "cert");
    }

    @Test
    public void testTrustManagerProxyGetAcceptedIssuers() {
        X509ExtendedTrustManager mockedTrustManager = Mockito.mock(X509ExtendedTrustManager.class);
        Mockito.when(mockedTrustManager.getAcceptedIssuers()).thenReturn(null);
        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(new TrustManager[]{mockedTrustManager});
        assertNull(trustManagerProxy.getAcceptedIssuers());
    }
}
