/**
 * Copyright 2016 Yahoo Inc.
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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.cert.CertSigner;

public class SelfCertSigner implements CertSigner {

    X509Certificate caCertificate = null;
    PrivateKey caPrivateKey = null;
    int certValidityTime = (int) TimeUnit.SECONDS.convert(30, TimeUnit.DAYS);

    public SelfCertSigner(PrivateKey caPrivateKey, X509Certificate caCertificate) {
        this.caCertificate = caCertificate;
        this.caPrivateKey = caPrivateKey;
    }

    @Override
    public String generateX509Certificate(String csr) {
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        X509Certificate cert = Crypto.generateX509Certificate(certReq, caPrivateKey,
                caCertificate, certValidityTime, false);
        return Crypto.convertToPEMFormat(cert);
    }

    @Override
    public String getCACertificate() {
        return Crypto.convertToPEMFormat(caCertificate);
    }

    @Override
    public void close() {
    }
}
