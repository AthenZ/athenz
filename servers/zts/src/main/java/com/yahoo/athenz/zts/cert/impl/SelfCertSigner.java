/*
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

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.zts.ZTSConsts;

public class SelfCertSigner implements CertSigner {

    private X509Certificate caCertificate;
    private PrivateKey caPrivateKey;
    private int maxCertExpiryTimeMins;

    public SelfCertSigner(PrivateKey caPrivateKey, X509Certificate caCertificate) {
        
        this.caCertificate = caCertificate;
        this.caPrivateKey = caPrivateKey;
        
        // max certificate validity time in minutes
        
        maxCertExpiryTimeMins = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME, "43200"));
    }

    @Override
    public String generateX509Certificate(String csr, String keyUsage, int expiryTime) {
        int certExpiryTime = expiryTime == 0 ? maxCertExpiryTimeMins : expiryTime;
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        X509Certificate cert = Crypto.generateX509Certificate(certReq, caPrivateKey,
                caCertificate, certExpiryTime, false);
        return Crypto.convertToPEMFormat(cert);
    }

    @Override
    public String getCACertificate() {
        return Crypto.convertToPEMFormat(caCertificate);
    }

    @Override
    public int getMaxCertExpiryTimeMins() {
        return maxCertExpiryTimeMins;
    }
    
    @Override
    public void close() {
    }
}
