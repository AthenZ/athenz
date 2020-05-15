/*
 * Copyright 2020 Yahoo Inc.
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
package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.cert.CertSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class KeyStoreCertSigner implements CertSigner, AutoCloseable {

    private X509Certificate caCertificate;
    private PrivateKey caPrivateKey;
    private int maxCertExpiryTimeMins;

    public KeyStoreCertSigner(X509Certificate caCertificate, PrivateKey caPrivateKey, int maxCertExpiryTimeMins) {
        this.caCertificate = caCertificate;
        this.caPrivateKey = caPrivateKey;
        this.maxCertExpiryTimeMins = maxCertExpiryTimeMins;
    }

    @Override
    public String generateX509Certificate(String csr, String keyUsage, int certExpiryMins) {
        int certExpiryTime = (certExpiryMins == 0) ? this.maxCertExpiryTimeMins : certExpiryMins;

        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        // keyUsage is ignored
        X509Certificate cert = Crypto.generateX509Certificate(certReq, caPrivateKey, caCertificate, certExpiryTime, false);

        return Crypto.convertToPEMFormat(cert);
    }

    @Override
    public String getCACertificate() {
        return Crypto.convertToPEMFormat(caCertificate);
    }

    @Override
    public int getMaxCertExpiryTimeMins() {
        return this.maxCertExpiryTimeMins;
    }

    @Override
    public void close() {
    }
}
