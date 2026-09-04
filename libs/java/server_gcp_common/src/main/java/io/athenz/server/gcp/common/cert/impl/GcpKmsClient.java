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
package io.athenz.server.gcp.common.cert.impl;

import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.CrypkiException;
import com.yahoo.athenz.crypki.kms.KmsClient;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Locale;

/**
 * GCP Cloud KMS implementation of the Crypki {@link KmsClient} SPI.
 */
public class GcpKmsClient implements KmsClient {

    private final KeyManagementServiceClient client;
    private final String caCertPath;

    public GcpKmsClient(KeyManagementServiceClient client) {
        this(client, System.getProperty(CrypkiConsts.PROP_KMS_CA_CERT_PATH));
    }

    public GcpKmsClient(KeyManagementServiceClient client, String caCertPath) {
        this.client = client;
        this.caCertPath = caCertPath;
    }

    @Override
    public byte[] sign(String keyId, byte[] data, String signingAlgorithm) {
        try {
            return client.asymmetricSign(AsymmetricSignRequest.newBuilder()
                    .setName(keyId)
                    .setDigest(toDigest(data, signingAlgorithm))
                    .build()).getSignature().toByteArray();
        } catch (CrypkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new CrypkiException("GCP KMS sign failed for " + keyId + ": " + ex.getMessage(), ex);
        }
    }

    static Digest toDigest(byte[] data, String signingAlgorithm) {
        String jcaDigest = digestAlgorithm(signingAlgorithm);
        try {
            byte[] hash = MessageDigest.getInstance(jcaDigest).digest(data);
            Digest.Builder digest = Digest.newBuilder();
            switch (jcaDigest) {
                case "SHA-512":
                    return digest.setSha512(ByteString.copyFrom(hash)).build();
                case "SHA-384":
                    return digest.setSha384(ByteString.copyFrom(hash)).build();
                default:
                    return digest.setSha256(ByteString.copyFrom(hash)).build();
            }
        } catch (Exception ex) {
            throw new CrypkiException("Unable to hash TBS for " + signingAlgorithm, ex);
        }
    }

    static String digestAlgorithm(String signingAlgorithm) {
        if (signingAlgorithm == null || signingAlgorithm.isEmpty()) {
            throw new CrypkiException("Missing KMS signing algorithm");
        }
        String upper = signingAlgorithm.toUpperCase(Locale.ROOT);
        if (upper.contains("SHA512")) {
            return "SHA-512";
        }
        if (upper.contains("SHA384")) {
            return "SHA-384";
        }
        if (upper.contains("SHA256")) {
            return "SHA-256";
        }
        throw new CrypkiException("Unsupported KMS signing algorithm: " + signingAlgorithm);
    }

    @Override
    public PublicKey getPublicKey(String keyId) {
        String pem = client.getPublicKey(GetPublicKeyRequest.newBuilder().setName(keyId).build()).getPem();
        return Crypto.loadPublicKey(pem);
    }

    @Override
    public X509Certificate getCaCertificate(String keyId) {
        if (caCertPath == null || caCertPath.isEmpty()) {
            throw new CrypkiException("Missing " + CrypkiConsts.PROP_KMS_CA_CERT_PATH
                    + " for KMS key " + keyId);
        }
        try {
            return Crypto.loadX509Certificate(Files.readString(Path.of(caCertPath)));
        } catch (Exception ex) {
            throw new CrypkiException("Unable to load KMS CA certificate: " + caCertPath, ex);
        }
    }
}
