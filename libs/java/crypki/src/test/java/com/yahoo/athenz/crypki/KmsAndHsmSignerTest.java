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

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.hsm.HsmClient;
import com.yahoo.athenz.crypki.hsm.HsmCrypkiSigner;
import com.yahoo.athenz.crypki.kms.KmsClient;
import com.yahoo.athenz.crypki.kms.KmsCrypkiSigner;
import com.yahoo.athenz.crypki.signer.SigningKey;
import org.testng.annotations.Test;

import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class KmsAndHsmSignerTest {

    @Test
    public void testKmsSigner() throws Exception {
        SigningKey ca = DefaultCrypkiSignerTest.selfSigned("x509-key");
        KmsClient kms = new KmsClient() {
            @Override
            public byte[] sign(String keyId, byte[] data, String signingAlgorithm) {
                try {
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(ca.getPrivateKey());
                    signature.update(data);
                    return signature.sign();
                } catch (Exception ex) {
                    throw new CrypkiException("sign failed", ex);
                }
            }

            @Override
            public PublicKey getPublicKey(String keyId) {
                return ca.getCaCertificate().getPublicKey();
            }

            @Override
            public X509Certificate getCaCertificate(String keyId) {
                return ca.getCaCertificate();
            }
        };
        KmsCrypkiSigner signer = new KmsCrypkiSigner(kms, "x509-key", "SHA256withRSA", 60);
        String csr = Crypto.generateX509CSR(Crypto.generateRSAPrivateKey(2048),
                "CN=svc,O=Athenz,C=US", null);
        String pem = signer.sign(X509SignRequest.builder().csrPem(csr).keyId("").validitySeconds(60).build());
        assertTrue(pem.contains("BEGIN CERTIFICATE"));
        assertTrue(signer.getCACertificate(null).contains("BEGIN CERTIFICATE"));
        assertEquals(signer.getMaxCertExpiryTimeMins(), 60);
    }

    @Test
    public void testKmsSignerUsesConfiguredKeyWhenRequestIsHttpDefault() throws Exception {
        SigningKey ca = DefaultCrypkiSignerTest.selfSigned("alias/example-ca");
        java.util.List<String> signedKeyIds = new java.util.ArrayList<>();
        KmsClient kms = new KmsClient() {
            @Override
            public byte[] sign(String keyId, byte[] data, String signingAlgorithm) {
                signedKeyIds.add(keyId);
                try {
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(ca.getPrivateKey());
                    signature.update(data);
                    return signature.sign();
                } catch (Exception ex) {
                    throw new CrypkiException("sign failed", ex);
                }
            }

            @Override
            public PublicKey getPublicKey(String keyId) {
                return ca.getCaCertificate().getPublicKey();
            }

            @Override
            public X509Certificate getCaCertificate(String keyId) {
                signedKeyIds.add("ca:" + keyId);
                return ca.getCaCertificate();
            }
        };
        KmsCrypkiSigner signer = new KmsCrypkiSigner(kms, "alias/example-ca", "SHA256withRSA", 60);
        assertEquals(signer.resolveKeyId(null), "alias/example-ca");
        assertEquals(signer.resolveKeyId(""), "alias/example-ca");
        assertEquals(signer.resolveKeyId(CrypkiConsts.DEFAULT_KEY_ID), "alias/example-ca");
        assertEquals(signer.resolveKeyId("explicit-key-id"), "explicit-key-id");
        String csr = Crypto.generateX509CSR(Crypto.generateRSAPrivateKey(2048),
                "CN=svc,O=Athenz,C=US", null);
        signer.sign(X509SignRequest.builder().csrPem(csr).keyId(CrypkiConsts.DEFAULT_KEY_ID)
                .validitySeconds(60).build());
        assertTrue(signedKeyIds.contains("alias/example-ca"));
        assertTrue(signer.getCACertificate(CrypkiConsts.DEFAULT_KEY_ID).contains("BEGIN CERTIFICATE"));
    }

    @Test
    public void testHsmSigner() throws Exception {
        SigningKey ca = DefaultCrypkiSignerTest.selfSigned("x509-key");
        HsmClient hsm = keyId -> ca;
        HsmCrypkiSigner signer = new HsmCrypkiSigner(hsm, 60);
        String csr = Crypto.generateX509CSR(Crypto.generateRSAPrivateKey(2048),
                "CN=svc,O=Athenz,C=US", null);
        String pem = signer.sign(X509SignRequest.builder().csrPem(csr).keyId("x509-key").build());
        assertTrue(pem.contains("BEGIN CERTIFICATE"));
    }

    @Test
    public void testException() {
        CrypkiException ex = new CrypkiException("msg");
        assertEquals(ex.getCode(), 500);
        assertEquals(ex.getMessage(), "msg");
        assertEquals(new CrypkiException(400, "bad").getCode(), 400);
        assertEquals(new CrypkiException("x", new IllegalStateException()).getCode(), 500);
    }

    @Test
    public void testKmsDefaultConstructorAndHsmMaxExpiry() throws Exception {
        SigningKey ca = DefaultCrypkiSignerTest.selfSigned("x509-key");
        KmsClient kms = new KmsClient() {
            @Override
            public byte[] sign(String keyId, byte[] data, String signingAlgorithm) {
                try {
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(ca.getPrivateKey());
                    signature.update(data);
                    return signature.sign();
                } catch (Exception ex) {
                    throw new CrypkiException("sign failed", ex);
                }
            }

            @Override
            public PublicKey getPublicKey(String keyId) {
                return ca.getCaCertificate().getPublicKey();
            }

            @Override
            public X509Certificate getCaCertificate(String keyId) {
                return ca.getCaCertificate();
            }
        };
        KmsCrypkiSigner signer = new KmsCrypkiSigner(kms);
        assertEquals(signer.getMaxCertExpiryTimeMins(), CrypkiConsts.DEFAULT_MAX_CERT_EXPIRY_TIME_MINS);
        HsmCrypkiSigner hsm = new HsmCrypkiSigner(keyId -> ca);
        assertTrue(hsm.getMaxCertExpiryTimeMins() > 0);
    }
}
