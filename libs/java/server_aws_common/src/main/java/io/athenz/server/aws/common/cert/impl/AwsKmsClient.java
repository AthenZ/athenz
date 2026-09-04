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
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

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
        GetPublicKeyResponse response = client.getPublicKey(
                GetPublicKeyRequest.builder().keyId(keyId).build());
        byte[] der = response.publicKey().asByteArray();
        try {
            return KeyFactory.getInstance(publicKeyAlgorithm(response.keySpec(), der))
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception ex) {
            throw new CrypkiException("Unable to parse KMS public key for " + keyId, ex);
        }
    }

    static String publicKeyAlgorithm(software.amazon.awssdk.services.kms.model.KeySpec keySpec,
            byte[] der) {
        if (keySpec != null) {
            String name = keySpec.toString();
            if (name.startsWith("ECC") || name.startsWith("SM2")) {
                return "EC";
            }
            if (name.startsWith("RSA")) {
                return "RSA";
            }
        }
        return encodedKeyAlgorithm(der);
    }

    static String encodedKeyAlgorithm(byte[] der) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        try {
            KeyFactory.getInstance("EC").generatePublic(spec);
            return "EC";
        } catch (InvalidKeySpecException | java.security.NoSuchAlgorithmException ignored) {
            return "RSA";
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

    private static final Map<String, SigningAlgorithmSpec> AWS_ALGORITHMS = Map.ofEntries(
            Map.entry("SHA256withRSA", SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256),
            Map.entry("SHA384withRSA", SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384),
            Map.entry("SHA512withRSA", SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512),
            Map.entry("SHA256withRSAandMGF1", SigningAlgorithmSpec.RSASSA_PSS_SHA_256),
            Map.entry("SHA384withRSAandMGF1", SigningAlgorithmSpec.RSASSA_PSS_SHA_384),
            Map.entry("SHA512withRSAandMGF1", SigningAlgorithmSpec.RSASSA_PSS_SHA_512),
            Map.entry("SHA256withECDSA", SigningAlgorithmSpec.ECDSA_SHA_256),
            Map.entry("SHA384withECDSA", SigningAlgorithmSpec.ECDSA_SHA_384),
            Map.entry("SHA512withECDSA", SigningAlgorithmSpec.ECDSA_SHA_512));

    static SigningAlgorithmSpec toAwsAlgorithm(String signingAlgorithm) {
        if (signingAlgorithm == null || signingAlgorithm.isEmpty()) {
            throw new CrypkiException("Missing KMS signing algorithm");
        }
        SigningAlgorithmSpec spec = AWS_ALGORITHMS.get(signingAlgorithm);
        if (spec == null) {
            throw new CrypkiException("Unsupported KMS signing algorithm: " + signingAlgorithm);
        }
        return spec;
    }
}
