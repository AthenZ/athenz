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

import mockit.Deencapsulation;
import mockit.Expectations;
import mockit.Mocked;
import org.junit.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

public class TrustManagerProxyTest {

    @Test
    public void testTrustManagerProxySetTrustManger() {
        TrustManager[] trustManagers = new TrustManager[] { new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            }
        }};

        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(trustManagers);
        X509ExtendedTrustManager trustManagerFirst = Deencapsulation.getField(trustManagerProxy, "trustManager");

        assertNotNull(trustManagerFirst);

        trustManagerProxy.setTrustManager(new TrustManager[] { new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            }
        }});

        X509ExtendedTrustManager trustManagerSecond = Deencapsulation.getField(trustManagerProxy, "trustManager");
        assertNotNull(trustManagerSecond);
        assertNotSame(trustManagerFirst, trustManagerSecond);
    }

    @Test
    public void testTrustManagerProxyCheckClientTrusted(@Mocked X509ExtendedTrustManager mockedTrustManager) throws CertificateException {
        new Expectations() {{
            mockedTrustManager.checkClientTrusted((X509Certificate[]) any, "cert"); times = 1;
        }};

        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(new TrustManager[]{mockedTrustManager});
        trustManagerProxy.checkClientTrusted(null, "cert");
    }

    @Test
    public void testTrustManagerProxyCheckServerTrusted(@Mocked X509ExtendedTrustManager mockedTrustManager) throws CertificateException {
        new Expectations() {{
            mockedTrustManager.checkServerTrusted((X509Certificate[]) any, "cert"); times = 1;
        }};

        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(new TrustManager[]{mockedTrustManager});

        trustManagerProxy.checkServerTrusted(null, "cert");
    }

    @Test
    public void testTrustManagerProxyGetAcceptedIssuers(@Mocked X509ExtendedTrustManager mockedTrustManager) {
        new Expectations() {{
            mockedTrustManager.getAcceptedIssuers(); times = 1; result = null;
        }};

        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(new TrustManager[]{mockedTrustManager});
        assertNull(trustManagerProxy.getAcceptedIssuers());
    }

}
