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
package com.yahoo.athenz.crypki.kms;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.CrypkiSigner;
import com.yahoo.athenz.crypki.X509SignRequest;
import com.yahoo.athenz.crypki.x509.X509CertificateMinter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * In-process X.509 minting that asks a {@link KmsClient} to produce the
 * signature. AWS KMS and GCP KMS plug in by implementing {@link KmsClient}.
 */
public class KmsCrypkiSigner implements CrypkiSigner {

    private final KmsClient kmsClient;
    private final String defaultKeyId;
    private final String signingAlgorithm;
    private final X509CertificateMinter minter;
    private final int maxCertExpiryTimeMins;

    public KmsCrypkiSigner(KmsClient kmsClient) {
        this(kmsClient, System.getProperty(CrypkiConsts.PROP_KMS_KEY_ID, CrypkiConsts.DEFAULT_KEY_ID),
                System.getProperty(CrypkiConsts.PROP_KMS_SIGNING_ALGORITHM, "SHA256withRSA"),
                CrypkiConsts.DEFAULT_MAX_CERT_EXPIRY_TIME_MINS);
    }

    public KmsCrypkiSigner(KmsClient kmsClient, String defaultKeyId, String signingAlgorithm,
            int maxCertExpiryTimeMins) {
        this.kmsClient = kmsClient;
        this.defaultKeyId = defaultKeyId;
        this.signingAlgorithm = signingAlgorithm;
        this.maxCertExpiryTimeMins = maxCertExpiryTimeMins;
        this.minter = new X509CertificateMinter(Math.multiplyExact(maxCertExpiryTimeMins, 60));
    }

    @Override
    public String sign(X509SignRequest request) {
        String keyId = resolveKeyId(request.getKeyId());
        return minter.sign(new KmsContentSigner(kmsClient, keyId, signingAlgorithm),
                kmsClient.getCaCertificate(keyId), request);
    }

    @Override
    public String getCACertificate(String keyId) {
        return Crypto.convertToPEMFormat(kmsClient.getCaCertificate(resolveKeyId(keyId)));
    }

    /**
     * ZTS leaves {@code signerKeyId} empty, so {@link com.yahoo.athenz.crypki.CrypkiRequestFactory}
     * fills in the HTTP Crypki default {@code x509-key}. That name is not a
     * KMS key id (and {@code alias/...} cannot be sent as an RDL SimpleName).
     * Use the configured {@code athenz.crypki.kms.key_id} instead.
     */
    public String resolveKeyId(String requested) {
        if (requested == null || requested.isEmpty() || CrypkiConsts.DEFAULT_KEY_ID.equals(requested)) {
            return defaultKeyId;
        }
        return requested;
    }

    @Override
    public int getMaxCertExpiryTimeMins() {
        return maxCertExpiryTimeMins;
    }

    static final class KmsContentSigner implements ContentSigner {
        private final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        private final KmsClient kmsClient;
        private final String keyId;
        private final String signingAlgorithm;

        KmsContentSigner(KmsClient kmsClient, String keyId, String signingAlgorithm) {
            this.kmsClient = kmsClient;
            this.keyId = keyId;
            this.signingAlgorithm = signingAlgorithm;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new DefaultSignatureAlgorithmIdentifierFinder().find(signingAlgorithm);
        }

        @Override
        public OutputStream getOutputStream() {
            return stream;
        }

        @Override
        public byte[] getSignature() {
            return kmsClient.sign(keyId, stream.toByteArray(), signingAlgorithm);
        }
    }
}
