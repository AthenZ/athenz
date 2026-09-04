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
package com.yahoo.athenz.crypki.signer;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.CrypkiSigner;
import com.yahoo.athenz.crypki.X509SignRequest;
import com.yahoo.athenz.crypki.x509.X509CertificateMinter;

/**
 * In-process signer over a {@link SigningKeyProvider} (local PEM, HSM, or a
 * KMS-backed PrivateKey).
 */
public class DefaultCrypkiSigner implements CrypkiSigner {

    private final SigningKeyProvider keyProvider;
    private final X509CertificateMinter minter;
    private final int maxCertExpiryTimeMins;

    public DefaultCrypkiSigner(SigningKeyProvider keyProvider) {
        this(keyProvider, CrypkiConsts.DEFAULT_MAX_CERT_EXPIRY_TIME_MINS);
    }

    public DefaultCrypkiSigner(SigningKeyProvider keyProvider, int maxCertExpiryTimeMins) {
        this.keyProvider = keyProvider;
        this.maxCertExpiryTimeMins = maxCertExpiryTimeMins;
        this.minter = new X509CertificateMinter(Math.multiplyExact(maxCertExpiryTimeMins, 60));
    }

    @Override
    public String sign(X509SignRequest request) {
        return minter.sign(keyProvider.get(request.getKeyId()), request);
    }

    @Override
    public String getCACertificate(String keyId) {
        return Crypto.convertToPEMFormat(keyProvider.get(keyId).getCaCertificate());
    }

    @Override
    public int getMaxCertExpiryTimeMins() {
        return maxCertExpiryTimeMins;
    }
}
