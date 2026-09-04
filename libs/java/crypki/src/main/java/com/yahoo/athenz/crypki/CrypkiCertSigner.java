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
package com.yahoo.athenz.crypki;

import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.Priority;

/**
 * ZTS {@link CertSigner} adapter: generate a {@link X509SignRequest} and
 * call a pluggable {@link CrypkiSigner}.
 */
public class CrypkiCertSigner implements CertSigner {

    private final CrypkiSigner signer;
    private final CrypkiRequestFactory requestFactory;

    public CrypkiCertSigner(CrypkiSigner signer) {
        this(signer, new CrypkiRequestFactory());
    }

    public CrypkiCertSigner(CrypkiSigner signer, CrypkiRequestFactory requestFactory) {
        this.signer = signer;
        this.requestFactory = requestFactory;
    }

    @Override
    public String generateX509Certificate(String provider, String certIssuer, String csr,
            String keyUsage, int expiryTime, Priority priority, String signerKeyId) {
        return signer.sign(requestFactory.create(provider, csr, keyUsage, expiryTime, priority, signerKeyId));
    }

    @Override
    public String getCACertificate(String provider, String signerKeyId) {
        return signer.getCACertificate(requestFactory.resolveKeyId(provider, signerKeyId));
    }

    @Override
    public int getMaxCertExpiryTimeMins() {
        return signer.getMaxCertExpiryTimeMins();
    }

    @Override
    public void close() {
        signer.close();
    }

    public CrypkiSigner getSigner() {
        return signer;
    }

    public CrypkiRequestFactory getRequestFactory() {
        return requestFactory;
    }
}
