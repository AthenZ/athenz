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

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * This class creates a key manager that wraps the existing X509TrustManager. The goal is that it watches
 * the 'key' files and when they are updated, it updates the TrustManager under the covers.  This may
 * cause connections that are in the middle of a handshake to fail, but must NOT cause any already
 * established connections to fail.  This allow the changing of the SSL context on the fly without creating
 * new server / httpClient objects
 */
public class TrustManagerProxy implements X509TrustManager {

    private volatile X509TrustManager trustManager;

    public TrustManagerProxy(TrustManager[] trustManagers) {
        this.setTrustManager(trustManagers);
    }

    /**
     * overwrites the existing key manager.
     * @param trustManagers only the first element will be used, and MUST be a X509TrustManager
     */
    public void setTrustManager(final TrustManager[] trustManagers) {
        trustManager = (X509TrustManager) trustManagers[0];
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        trustManager.checkClientTrusted(x509Certificates, s);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        trustManager.checkServerTrusted(x509Certificates, s);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustManager.getAcceptedIssuers();
    }
}
