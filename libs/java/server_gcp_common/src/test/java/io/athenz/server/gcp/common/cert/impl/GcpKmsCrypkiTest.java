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
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.security.cert.X509Certificate;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
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
                "projects/example/locations/global/keyRings/ring/cryptoKeys/ca/cryptoKeyVersions/1");
        try {
            KmsClient kms = Mockito.mock(KmsClient.class);
            CrypkiCertSigner signer = (CrypkiCertSigner) new GcpKmsCrypkiSignerFactory(kms).create();
            assertEquals(signer.getRequestFactory().resolveKeyId(null, null),
                    "projects/example/locations/global/keyRings/ring/cryptoKeys/ca/cryptoKeyVersions/1");
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

        final String versionedKey = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
        GcpKmsClient client = new GcpKmsClient(grpc, certFile.getAbsolutePath());
        assertEquals(client.sign(versionedKey, new byte[]{1}, "SHA256withRSA"),
                new byte[]{4, 5});
        ArgumentCaptor<AsymmetricSignRequest> captor = ArgumentCaptor.forClass(AsymmetricSignRequest.class);
        Mockito.verify(grpc).asymmetricSign(captor.capture());
        assertEquals(captor.getValue().getName(), versionedKey);
        assertTrue(captor.getValue().hasDigest());
        assertTrue(captor.getValue().getDigest().hasSha256());

        client.sign(versionedKey, new byte[]{1}, "SHA384withECDSA");
        client.sign(versionedKey, new byte[]{1}, "SHA512withRSA");
        assertEquals(GcpKmsClient.digestAlgorithm("SHA256withRSA"), "SHA-256");
        assertEquals(GcpKmsClient.digestAlgorithm("SHA384withECDSA"), "SHA-384");
        assertEquals(GcpKmsClient.digestAlgorithm("SHA512withRSA"), "SHA-512");
        expectThrows(CrypkiException.class, () -> GcpKmsClient.digestAlgorithm(null));
        expectThrows(CrypkiException.class, () -> GcpKmsClient.digestAlgorithm(""));
        expectThrows(CrypkiException.class, () -> GcpKmsClient.digestAlgorithm("MD5withRSA"));
        assertTrue(GcpKmsClient.toDigest(new byte[]{1}, "SHA256withRSA").hasSha256());
        assertTrue(GcpKmsClient.toDigest(new byte[]{1}, "SHA384withECDSA").hasSha384());
        assertTrue(GcpKmsClient.toDigest(new byte[]{1}, "SHA512withRSA").hasSha512());
        expectThrows(CrypkiException.class, () -> GcpKmsClient.toDigest(null, "SHA256withRSA"));
        expectThrows(CrypkiException.class, () -> client.sign(
                versionedKey, new byte[]{1}, "MD5withRSA"));

        assertNotNull(client.getPublicKey(versionedKey));
        assertNotNull(client.getCaCertificate("k"));
        expectThrows(CrypkiException.class, () -> new GcpKmsClient(grpc, null).getCaCertificate("k"));
        expectThrows(CrypkiException.class, () -> new GcpKmsClient(grpc, "/missing.pem").getCaCertificate("k"));
        var tenantKey = Crypto.generateRSAPrivateKey(2048);
        X509Certificate tenantCa = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(
                Crypto.generateX509CSR(tenantKey, "CN=tenant-a,O=Athenz,C=US", null)),
                tenantKey, new org.bouncycastle.asn1.x500.X500Name("CN=tenant-a,O=Athenz,C=US"), 60, true);
        java.io.File tenantCert = java.io.File.createTempFile("gtenant", ".pem");
        tenantCert.deleteOnExit();
        Files.writeString(tenantCert.toPath(), Crypto.convertToPEMFormat(tenantCa));
        java.io.File mapFile = java.io.File.createTempFile("gcamap", ".json");
        mapFile.deleteOnExit();
        final String tenantVersion = "projects/p/locations/l/keyRings/r/cryptoKeys/tenant-a/cryptoKeyVersions/1";
        Files.writeString(mapFile.toPath(), "{ \"tenant-a-ca\": { \"keyId\": \"" + tenantVersion + "\","
                + " \"caCertPath\": \"" + tenantCert.getAbsolutePath() + "\" } }\n");
        System.setProperty(CrypkiConsts.PROP_KMS_CA_CERT_MAP_PATH, mapFile.getAbsolutePath());
        try {
            GcpKmsClient mapped = new GcpKmsClient(grpc, certFile.getAbsolutePath());
            assertEquals(mapped.getCaCertificate("tenant-a-ca")
                    .getSubjectX500Principal(), tenantCa.getSubjectX500Principal());
            assertEquals(mapped.getCaCertificate("k").getSubjectX500Principal(), ca.getSubjectX500Principal());
            mapped.sign("tenant-a-ca", new byte[]{1}, "SHA256withRSA");
            ArgumentCaptor<AsymmetricSignRequest> mappedSign =
                    ArgumentCaptor.forClass(AsymmetricSignRequest.class);
            Mockito.verify(grpc, Mockito.atLeastOnce()).asymmetricSign(mappedSign.capture());
            assertEquals(mappedSign.getValue().getName(), tenantVersion);
            ArgumentCaptor<GetPublicKeyRequest> mappedPublicKey =
                    ArgumentCaptor.forClass(GetPublicKeyRequest.class);
            mapped.getPublicKey("tenant-a-ca");
            Mockito.verify(grpc, Mockito.atLeastOnce()).getPublicKey(mappedPublicKey.capture());
            assertEquals(mappedPublicKey.getValue().getName(), tenantVersion);
        } finally {
            System.clearProperty(CrypkiConsts.PROP_KMS_CA_CERT_MAP_PATH);
        }
        Mockito.when(grpc.asymmetricSign(Mockito.any(AsymmetricSignRequest.class)))
                .thenThrow(new RuntimeException("kms denied"));
        expectThrows(CrypkiException.class, () -> client.sign(versionedKey,
                new byte[]{1}, "SHA256withRSA"));
        new GcpKmsClient(grpc);
    }
}
