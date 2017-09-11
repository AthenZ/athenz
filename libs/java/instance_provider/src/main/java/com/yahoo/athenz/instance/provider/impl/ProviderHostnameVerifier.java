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
package com.yahoo.athenz.instance.provider.impl;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import com.yahoo.athenz.auth.util.Crypto;

public class ProviderHostnameVerifier implements HostnameVerifier {

    String serviceName = null;
    
    public ProviderHostnameVerifier(String serviceName) {
        this.serviceName = serviceName;
    }
    
    @Override
    public boolean verify(String hostname, SSLSession session) {

        Certificate[] certs = null;
        try {
            certs = session.getPeerCertificates();
        } catch (SSLPeerUnverifiedException e) {
        }
        if (certs == null) {
            return false;
        }
        
        for (Certificate cert : certs) {
            final X509Certificate x509Cert = (X509Certificate) cert;
            if (serviceName.equals(Crypto.extractX509CertCommonName(x509Cert))) {
                return true;
            }
        }
        return false;
    }
}
