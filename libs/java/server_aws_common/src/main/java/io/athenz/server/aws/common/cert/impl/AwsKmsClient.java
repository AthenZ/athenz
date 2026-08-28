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
package io.athenz.server.aws.common.cert.impl;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.CrypkiException;
import com.yahoo.athenz.crypki.kms.KmsClient;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * AWS KMS implementation of the Crypki {@link KmsClient} SPI.
 */
public class AwsKmsClient implements KmsClient {

    private final software.amazon.awssdk.services.kms.KmsClient client;
    private final String caCertPath;

    public AwsKmsClient() {
        this(software.amazon.awssdk.services.kms.KmsClient.create(),
                System.getProperty(CrypkiConsts.PROP_KMS_CA_CERT_PATH));
    }

    public AwsKmsClient(software.amazon.awssdk.services.kms.KmsClient client, String caCertPath) {
        this.client = client;
        this.caCertPath = caCertPath;
    }

    @Override
    public byte[] sign(String keyId, byte[] data, String signingAlgorithm) {
        return client.sign(SignRequest.builder()
                .keyId(keyId)
                .message(SdkBytes.fromByteArray(data))
                .messageType(MessageType.RAW)
                .signingAlgorithm(toAwsAlgorithm(signingAlgorithm))
                .build()).signature().asByteArray();
    }

    @Override
    public PublicKey getPublicKey(String keyId) {
        byte[] der = client.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build())
                .publicKey().asByteArray();
        try {
            return java.security.KeyFactory.getInstance("RSA")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(der));
        } catch (Exception ex) {
            throw new CrypkiException("Unable to parse KMS public key for " + keyId, ex);
        }
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

    static SigningAlgorithmSpec toAwsAlgorithm(String signingAlgorithm) {
        if (signingAlgorithm != null && signingAlgorithm.contains("ECDSA")) {
            return SigningAlgorithmSpec.ECDSA_SHA_256;
        }
        return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;
    }
}
