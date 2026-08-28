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
import com.google.cloud.kms.v1.AsymmetricSignResponse;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;
import com.google.protobuf.ByteString;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiCertSigner;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.CrypkiException;
import com.yahoo.athenz.crypki.kms.KmsClient;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.security.cert.X509Certificate;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.expectThrows;

public class GcpKmsCrypkiTest {

    @Test
    public void testFactoryWithInjectedClient() {
        KmsClient kms = Mockito.mock(KmsClient.class);
        GcpKmsCrypkiSignerFactory factory = new GcpKmsCrypkiSignerFactory(kms);
        assertNotNull(factory.createSigner());
        assertNotNull(factory.create());
    }

    @Test
    public void testFactoryWiresConfiguredKeyId() {
        System.setProperty(CrypkiConsts.PROP_KMS_KEY_ID,
                "projects/example/locations/global/keyRings/ring/cryptoKeys/ca");
        try {
            KmsClient kms = Mockito.mock(KmsClient.class);
            CrypkiCertSigner signer = (CrypkiCertSigner) new GcpKmsCrypkiSignerFactory(kms).create();
            assertEquals(signer.getRequestFactory().resolveKeyId(null, null),
                    "projects/example/locations/global/keyRings/ring/cryptoKeys/ca");
        } finally {
            System.clearProperty(CrypkiConsts.PROP_KMS_KEY_ID);
        }
    }

    @Test
    public void testNewKmsClientWrapsFailure() {
        GcpKmsCrypkiSignerFactory factory = new GcpKmsCrypkiSignerFactory() {
            @Override
            KeyManagementServiceClient createKeyManagementServiceClient() throws java.io.IOException {
                throw new java.io.IOException("no adc");
            }
        };
        expectThrows(CrypkiException.class, factory::createSigner);
    }

    @Test
    public void testNewKmsClientUsesAdcClient() {
        KeyManagementServiceClient grpc = Mockito.mock(KeyManagementServiceClient.class);
        GcpKmsCrypkiSignerFactory factory = new GcpKmsCrypkiSignerFactory() {
            @Override
            KeyManagementServiceClient createKeyManagementServiceClient() {
                return grpc;
            }
        };
        assertNotNull(factory.createSigner());
        assertNotNull(factory.create());
    }

    @Test
    public void testNewKmsClientCallsCreate() {
        KeyManagementServiceClient grpc = Mockito.mock(KeyManagementServiceClient.class);
        try (org.mockito.MockedStatic<KeyManagementServiceClient> mocked =
                Mockito.mockStatic(KeyManagementServiceClient.class)) {
            mocked.when(KeyManagementServiceClient::create).thenReturn(grpc);
            assertNotNull(new GcpKmsCrypkiSignerFactory().createSigner());
        }
    }

    @Test
    public void testGcpKmsClient() throws Exception {
        KeyManagementServiceClient grpc = Mockito.mock(KeyManagementServiceClient.class);
        Mockito.when(grpc.asymmetricSign(Mockito.any(AsymmetricSignRequest.class)))
                .thenReturn(AsymmetricSignResponse.newBuilder()
                        .setSignature(ByteString.copyFrom(new byte[]{4, 5})).build());
        var caKey = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(caKey, "CN=ca,O=Athenz,C=US", null);
        X509Certificate ca = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr), caKey,
                new org.bouncycastle.asn1.x500.X500Name("CN=ca,O=Athenz,C=US"), 60, true);
        Mockito.when(grpc.getPublicKey(Mockito.any(GetPublicKeyRequest.class)))
                .thenReturn(PublicKey.newBuilder().setPem(Crypto.convertToPEMFormat(ca.getPublicKey())).build());

        java.io.File certFile = java.io.File.createTempFile("gca", ".pem");
        certFile.deleteOnExit();
        Files.writeString(certFile.toPath(), Crypto.convertToPEMFormat(ca));

        GcpKmsClient client = new GcpKmsClient(grpc, certFile.getAbsolutePath());
        assertEquals(client.sign("projects/p/locations/l/keyRings/r/cryptoKeys/k", new byte[]{1}, "SHA256withRSA"),
                new byte[]{4, 5});
        assertNotNull(client.getPublicKey("projects/p/locations/l/keyRings/r/cryptoKeys/k"));
        assertNotNull(client.getCaCertificate("k"));
        expectThrows(CrypkiException.class, () -> new GcpKmsClient(grpc, null).getCaCertificate("k"));
        expectThrows(CrypkiException.class, () -> new GcpKmsClient(grpc, "/missing.pem").getCaCertificate("k"));
        Mockito.when(grpc.asymmetricSign(Mockito.any(AsymmetricSignRequest.class)))
                .thenThrow(new RuntimeException("kms denied"));
        expectThrows(CrypkiException.class, () -> client.sign("projects/p/locations/l/keyRings/r/cryptoKeys/k",
                new byte[]{1}, "SHA256withRSA"));
        new GcpKmsClient(grpc);
    }
}
