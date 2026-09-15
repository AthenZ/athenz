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

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.provider.StubKeyStoreSpi;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiCertSigner;
import com.yahoo.athenz.crypki.CrypkiException;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.hsm.HsmClient;
import com.yahoo.athenz.crypki.kms.KmsCaCertificateStore;
import com.yahoo.athenz.crypki.kms.KmsClient;
import com.yahoo.athenz.crypki.signer.SigningKey;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

public class AwsCrypkiSignerFactoryTest {

    @AfterMethod
    public void resetCloudHsmStubs() {
        StubKeyStoreSpi.key = null;
        CloudHsmProvider.failLogin = false;
        CloudHsmProvider.failLoginAlready = false;
        CloudHsmProvider.throwOnConstruct = false;
        KeyStoreWithAttributes.throwOnGetInstance = false;
        KeyStoreWithAttributes.returnNonPrivateKey = false;
        KeyStoreWithAttributes.returnNullKey = false;
        Security.removeProvider("CloudHsmProvider");
        Security.removeProvider("OddHsmName");
        Security.removeProvider("AthenzCrypkiHsm");
    }

    @Test
    public void testKmsFactoryWithInjectedClient() {
        KmsClient kms = Mockito.mock(KmsClient.class);
        AwsKmsCrypkiSignerFactory factory = new AwsKmsCrypkiSignerFactory(kms);
        assertNotNull(factory.createSigner());
        assertNotNull(factory.create());
    }

    @Test
    public void testKmsFactoryWiresConfiguredKeyId() {
        System.setProperty(CrypkiConsts.PROP_KMS_KEY_ID, "alias/example-ca");
        try {
            KmsClient kms = Mockito.mock(KmsClient.class);
            CrypkiCertSigner signer = (CrypkiCertSigner) new AwsKmsCrypkiSignerFactory(kms).create();
            assertEquals(signer.getRequestFactory().resolveKeyId(null, null), "alias/example-ca");
        } finally {
            System.clearProperty(CrypkiConsts.PROP_KMS_KEY_ID);
        }
    }

    @Test
    public void testCloudHsmFactoryWithInjectedClient() {
        HsmClient hsm = Mockito.mock(HsmClient.class);
        System.setProperty(CrypkiConsts.PROP_HSM_KEY_LABEL, "example-hsm-label");
        try {
            AwsCloudHsmCrypkiSignerFactory factory = new AwsCloudHsmCrypkiSignerFactory(hsm);
            assertNotNull(factory.createSigner());
            CrypkiCertSigner signer = (CrypkiCertSigner) factory.create();
            assertNotNull(signer);
            assertEquals(signer.getRequestFactory().resolveKeyId(null, null), "example-hsm-label");
        } finally {
            System.clearProperty(CrypkiConsts.PROP_HSM_KEY_LABEL);
        }
    }

    @Test
    public void testCloudHsmDefaultMissingModule() {
        AwsCloudHsmCrypkiSignerFactory factory = new AwsCloudHsmCrypkiSignerFactory();
        expectThrows(CrypkiException.class, factory::createSigner);
    }

    @Test
    public void testAwsKmsClientSignAndCert() throws Exception {
        software.amazon.awssdk.services.kms.KmsClient aws = Mockito.mock(
                software.amazon.awssdk.services.kms.KmsClient.class);
        Mockito.when(aws.sign(Mockito.any(SignRequest.class))).thenReturn(
                SignResponse.builder().signature(SdkBytes.fromByteArray(new byte[]{1, 2, 3})).build());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        Mockito.when(aws.getPublicKey(Mockito.any(GetPublicKeyRequest.class))).thenReturn(
                GetPublicKeyResponse.builder().publicKey(SdkBytes.fromByteArray(pair.getPublic().getEncoded())).build());

        java.io.File certFile = java.io.File.createTempFile("cacert", ".pem");
        certFile.deleteOnExit();
        // minimal self-signed via Crypto
        var caKey = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(caKey, "CN=ca,O=Athenz,C=US", null);
        X509Certificate ca = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr), caKey,
                new org.bouncycastle.asn1.x500.X500Name("CN=ca,O=Athenz,C=US"), 60, true);
        Files.writeString(certFile.toPath(), Crypto.convertToPEMFormat(ca));

        AwsKmsClient client = new AwsKmsClient(aws, certFile.getAbsolutePath());
        assertEquals(client.sign("kid", new byte[]{9}, "SHA256withRSA"), new byte[]{1, 2, 3});
        assertEquals(AwsKmsClient.toAwsKeyId("kid"), "alias/kid");
        assertEquals(AwsKmsClient.toAwsKeyId("alias/athenz-crypki-ca"), "alias/athenz-crypki-ca");
        assertEquals(AwsKmsClient.toAwsKeyId("arn:aws:kms:us-west-2:1:key/abc"),
                "arn:aws:kms:us-west-2:1:key/abc");
        assertEquals(AwsKmsClient.toAwsKeyId("c6d64533-4780-4e12-8138-7ded9f4d65b7"),
                "c6d64533-4780-4e12-8138-7ded9f4d65b7");
        assertEquals(AwsKmsClient.toAwsKeyId(null), null);
        assertEquals(AwsKmsClient.toAwsKeyId(""), "");
        assertTrue(AwsKmsClient.isUuid("c6d64533-4780-4e12-8138-7ded9f4d65b7"));
        assertTrue(!AwsKmsClient.isUuid("notauuid-name-with-hyph-ens12345678"));
        assertEquals(AwsKmsClient.toAwsKeyId("notauuid-name-with-hyph-ens12345678"),
                "alias/notauuid-name-with-hyph-ens12345678");
        assertEquals(AwsKmsClient.toAwsKeyId("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
                "alias/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assertEquals(AwsKmsClient.toAwsKeyId("mrk-1234abcd12ab34cd56ef1234567890ab"),
                "mrk-1234abcd12ab34cd56ef1234567890ab");
        assertTrue(AwsKmsClient.isMultiRegionKeyId("MRK-1234ABCD12AB34CD56EF1234567890AB"));
        assertEquals(AwsKmsClient.toAwsKeyId("mrk-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
                "alias/mrk-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assertNotNull(client.getPublicKey("kid"));
        assertNotNull(client.getCaCertificate("kid"));
        assertEquals(AwsKmsClient.toAwsAlgorithm("SHA256withECDSA"), SigningAlgorithmSpec.ECDSA_SHA_256);
        assertEquals(AwsKmsClient.toAwsAlgorithm("SHA384withECDSA"), SigningAlgorithmSpec.ECDSA_SHA_384);
        assertEquals(AwsKmsClient.toAwsAlgorithm("SHA512withECDSA"), SigningAlgorithmSpec.ECDSA_SHA_512);
        assertEquals(AwsKmsClient.toAwsAlgorithm("SHA256withRSA"), SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256);
        assertEquals(AwsKmsClient.toAwsAlgorithm("SHA384withRSA"), SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384);
        assertEquals(AwsKmsClient.toAwsAlgorithm("SHA512withRSA"), SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512);
        assertEquals(AwsKmsClient.toAwsAlgorithm("SHA256withRSAandMGF1"), SigningAlgorithmSpec.RSASSA_PSS_SHA_256);
        assertEquals(AwsKmsClient.toAwsAlgorithm("SHA384withRSAandMGF1"), SigningAlgorithmSpec.RSASSA_PSS_SHA_384);
        assertEquals(AwsKmsClient.toAwsAlgorithm("SHA512withRSAandMGF1"), SigningAlgorithmSpec.RSASSA_PSS_SHA_512);
        expectThrows(CrypkiException.class, () -> AwsKmsClient.toAwsAlgorithm(null));
        expectThrows(CrypkiException.class, () -> AwsKmsClient.toAwsAlgorithm("SHA1withRSA"));
        expectThrows(CrypkiException.class, () -> new AwsKmsClient(aws, null).getCaCertificate("kid"));
        expectThrows(CrypkiException.class, () -> new AwsKmsClient(aws, "/missing.pem").getCaCertificate("kid"));

        var tenantKey = Crypto.generateRSAPrivateKey(2048);
        X509Certificate tenantCa = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(
                Crypto.generateX509CSR(tenantKey, "CN=tenant-a,O=Athenz,C=US", null)),
                tenantKey, new org.bouncycastle.asn1.x500.X500Name("CN=tenant-a,O=Athenz,C=US"), 60, true);
        java.io.File tenantCert = java.io.File.createTempFile("tenantca", ".pem");
        tenantCert.deleteOnExit();
        Files.writeString(tenantCert.toPath(), Crypto.convertToPEMFormat(tenantCa));
        java.io.File mapFile = java.io.File.createTempFile("camap", ".json");
        mapFile.deleteOnExit();
        Files.writeString(mapFile.toPath(), "{ \"tenant-a-ca\": { \"keyId\": \"alias/tenant-a-ca\","
                + " \"caCertPath\": \"" + tenantCert.getAbsolutePath() + "\" } }\n");
        System.setProperty(CrypkiConsts.PROP_KMS_CA_CERT_MAP_PATH, mapFile.getAbsolutePath());
        try {
            AwsKmsClient mapped = new AwsKmsClient(aws, certFile.getAbsolutePath());
            assertEquals(mapped.getCaCertificate("tenant-a-ca").getSubjectX500Principal().getName(),
                    tenantCa.getSubjectX500Principal().getName());
            assertEquals(mapped.getCaCertificate("alias/other").getSubjectX500Principal().getName(),
                    ca.getSubjectX500Principal().getName());
            mapped.sign("tenant-a-ca", new byte[]{9}, "SHA256withRSA");
        } finally {
            System.clearProperty(CrypkiConsts.PROP_KMS_CA_CERT_MAP_PATH);
        }
        assertEquals(AwsKmsClient.publicKeyAlgorithm(KeySpec.RSA_2048, pair.getPublic().getEncoded()), "RSA");
        assertEquals(AwsKmsClient.publicKeyAlgorithm(KeySpec.ECC_NIST_P256, pair.getPublic().getEncoded()), "EC");
        assertEquals(AwsKmsClient.encodedKeyAlgorithm(pair.getPublic().getEncoded()), "RSA");
    }

    @Test
    public void testAwsKmsClientEcPublicKey() throws Exception {
        software.amazon.awssdk.services.kms.KmsClient aws = Mockito.mock(
                software.amazon.awssdk.services.kms.KmsClient.class);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair pair = kpg.generateKeyPair();
        Mockito.when(aws.getPublicKey(Mockito.any(GetPublicKeyRequest.class))).thenReturn(
                GetPublicKeyResponse.builder()
                        .keySpec(KeySpec.ECC_NIST_P256)
                        .publicKey(SdkBytes.fromByteArray(pair.getPublic().getEncoded())).build());
        AwsKmsClient client = new AwsKmsClient(aws, null);
        assertEquals(client.getPublicKey("kid").getAlgorithm(), "EC");
        assertEquals(AwsKmsClient.encodedKeyAlgorithm(pair.getPublic().getEncoded()), "EC");
        assertEquals(AwsKmsClient.encodedKeyAlgorithm(new byte[]{1, 2, 3}), "RSA");
    }

    @Test
    public void testCloudHsmClientResolvesHttpDefaultLabel() throws Exception {
        var caKey = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(caKey, "CN=hsm-ca,O=Athenz,C=US", null);
        X509Certificate ca = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr), caKey,
                new org.bouncycastle.asn1.x500.X500Name("CN=hsm-ca,O=Athenz,C=US"), 60, true);
        AwsCloudHsmClient client = new AwsCloudHsmClient(
                new com.yahoo.athenz.crypki.signer.SigningKey("athenz-crypki-ca", caKey, ca),
                "athenz-crypki-ca");
        assertEquals(client.resolveLabel(null), "athenz-crypki-ca");
        assertEquals(client.resolveLabel(""), "athenz-crypki-ca");
        assertEquals(client.resolveLabel(CrypkiConsts.DEFAULT_KEY_ID), "athenz-crypki-ca");
        assertTrue(AwsCloudHsmClient.cloudHsmJcePresent());
        assertEquals(AwsCloudHsmClient.loadCloudHsmJcePrivateKeyByAttributes(
                null, "athenz-crypki-ca", new char[]{'x'}), null);
        assertEquals(client.getSigningKey(CrypkiConsts.DEFAULT_KEY_ID).getIdentifier(), "athenz-crypki-ca");
        expectThrows(CrypkiException.class, () -> client.getSigningKey("other-label"));
        assertEquals(AwsCloudHsmClient.pkcs11Config("/opt/cloudhsm/lib/libcloudhsm_pkcs11.so", null),
                "--name=AthenzCrypkiHsm\nlibrary=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so\nslotListIndex=0\n");
        assertEquals(AwsCloudHsmClient.pkcs11Config("/opt/cloudhsm/lib/libcloudhsm_pkcs11.so", "1"),
                "--name=AthenzCrypkiHsm\nlibrary=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so\nslot=1\n");
        expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.readPin(null));
        expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.readPin("/missing-pin.txt"));
        expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.loadCaCertificate(null));
        expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.loadCaCertificate("/missing-ca.pem"));
        java.io.File emptyPin = java.io.File.createTempFile("pin", ".txt");
        emptyPin.deleteOnExit();
        Files.writeString(emptyPin.toPath(), "\n");
        expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.readPin(emptyPin.getAbsolutePath()));
        java.io.File pin = java.io.File.createTempFile("pin", ".txt");
        pin.deleteOnExit();
        Files.writeString(pin.toPath(), "crypto-user:example-pin\n");
        assertEquals(new String(AwsCloudHsmClient.readPin(pin.getAbsolutePath())), "crypto-user:example-pin");

        java.io.File certFile = java.io.File.createTempFile("hsmca", ".pem");
        certFile.deleteOnExit();
        Files.writeString(certFile.toPath(), Crypto.convertToPEMFormat(ca));
        expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.loadSigningKey(
                "/missing-module.so", null, "athenz-crypki-ca", pin.getAbsolutePath(),
                certFile.getAbsolutePath()));
        KeyPair jcePair = rsaKeyPair();
        StubKeyStoreSpi.key = jcePair.getPrivate();
        assertEquals(AwsCloudHsmClient.loadSigningKey("/missing-module.so", null,
                "athenz-crypki-ca", pin.getAbsolutePath(), certFile.getAbsolutePath())
                .getPrivateKey(), jcePair.getPrivate());
        StubKeyStoreSpi.key = null;
        expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.loadSigningKey(
                modulePathForCoverage(), null, "athenz-crypki-ca", pin.getAbsolutePath(),
                certFile.getAbsolutePath()));
        expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.pkcs11Provider(
                modulePathForCoverage(), null));
        expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.loadSunPkcs11(
                modulePathForCoverage(), "1", "athenz-crypki-ca",
                "crypto-user:example-pin".toCharArray(), ca));
        assertNotNull(AwsCloudHsmClient.loadCaCertificate(certFile.getAbsolutePath()));
        expectThrows(CrypkiException.class, AwsCloudHsmClient::new);
        expectThrows(CrypkiException.class, () -> new AwsCloudHsmClient(
                "/missing-module.so", null, "", pin.getAbsolutePath(), certFile.getAbsolutePath()));
    }

    private static String modulePathForCoverage() throws Exception {
        java.io.File module = java.io.File.createTempFile("pkcs11", ".so");
        module.deleteOnExit();
        return module.getAbsolutePath();
    }

    @Test
    public void testCloudHsmModulePresentWithoutPinFails() throws Exception {
        java.io.File module = java.io.File.createTempFile("pkcs11", ".so");
        module.deleteOnExit();
        System.setProperty(CrypkiConsts.PROP_HSM_MODULE_PATH, module.getAbsolutePath());
        try {
            expectThrows(CrypkiException.class, () -> new AwsCloudHsmCrypkiSignerFactory().newCloudHsmClient());
        } finally {
            System.clearProperty(CrypkiConsts.PROP_HSM_MODULE_PATH);
        }
    }

    @Test
    public void testKmsFactoryDefaultNewClientOverride() {
        KmsClient kms = Mockito.mock(KmsClient.class);
        AwsKmsCrypkiSignerFactory factory = new AwsKmsCrypkiSignerFactory() {
            @Override
            KmsClient newKmsClient() {
                return kms;
            }
        };
        assertNotNull(factory.create());
    }

    @Test
    public void testAwsKmsClientInvalidPublicKeyAndDefaultCtor() throws Exception {
        software.amazon.awssdk.services.kms.KmsClient aws = Mockito.mock(
                software.amazon.awssdk.services.kms.KmsClient.class);
        Mockito.when(aws.getPublicKey(Mockito.any(GetPublicKeyRequest.class))).thenReturn(
                GetPublicKeyResponse.builder().publicKey(SdkBytes.fromByteArray(new byte[]{1, 2, 3})).build());
        AwsKmsClient client = new AwsKmsClient(aws, null);
        expectThrows(CrypkiException.class, () -> client.getPublicKey("kid"));

        try (MockedStatic<software.amazon.awssdk.services.kms.KmsClient> mocked =
                Mockito.mockStatic(software.amazon.awssdk.services.kms.KmsClient.class)) {
            mocked.when(software.amazon.awssdk.services.kms.KmsClient::create).thenReturn(aws);
            assertNotNull(new AwsKmsClient());
            assertNotNull(new AwsKmsCrypkiSignerFactory().newKmsClient());
        }
    }

    @Test
    public void testCloudHsmJceLoadsPrivateKeyByAttributes() throws Exception {
        KeyPair pair = rsaKeyPair();
        StubKeyStoreSpi.key = pair.getPrivate();
        CloudHsmProvider alreadyRegistered = new CloudHsmProvider();
        Security.addProvider(alreadyRegistered);
        try {
            SigningKey key = loadJceSigningKey("example-hsm-label");
            assertEquals(key.getIdentifier(), "example-hsm-label");
            assertEquals(key.getPrivateKey(), pair.getPrivate());
            assertTrue(alreadyRegistered.loggedIn);
            assertNotNull(new AwsCloudHsmClient(modulePathForCoverage(), null, "",
                    pinFile("crypto-user:example-pin"), caCertFile()).getSigningKey(null));
        } finally {
            Security.removeProvider(alreadyRegistered.getName());
        }
    }

    @Test
    public void testCloudHsmJceFallsBackToKeyStoreWhenAttributesMiss() throws Exception {
        KeyPair pair = rsaKeyPair();
        StubKeyStoreSpi.key = pair.getPrivate();
        KeyStoreWithAttributes.returnNullKey = true;
        SigningKey key = loadJceSigningKey("fallback-label");
        assertEquals(key.getPrivateKey(), pair.getPrivate());
    }

    @Test
    public void testCloudHsmJceIgnoresNonPrivateAttributeKey() throws Exception {
        KeyStoreWithAttributes.returnNonPrivateKey = true;
        expectThrows(CrypkiException.class, () -> loadJceSigningKey("missing-label"));
    }

    @Test
    public void testCloudHsmJceAttributeLookupFailure() {
        KeyStoreWithAttributes.throwOnGetInstance = true;
        expectThrows(CrypkiException.class, () -> loadJceSigningKey("broken-label"));
    }

    @Test
    public void testCloudHsmJceLoginFailureIsWrapped() {
        CloudHsmProvider.failLogin = true;
        expectThrows(CrypkiException.class, () -> loadJceSigningKey("login-label"));
    }

    @Test
    public void testCloudHsmClientLoadsMappedTenantLabels() throws Exception {
        KeyPair pair = rsaKeyPair();
        StubKeyStoreSpi.key = pair.getPrivate();
        X509Certificate defaultCa = hsmCertificate("CN=hsm-default");
        X509Certificate tenantCa = hsmCertificate("CN=hsm-tenant-b");
        String defaultPath = writeCert(defaultCa);
        String tenantPath = writeCert(tenantCa);
        String mapPath = writeJson("{ \"tenant-b-ca\": { \"keyId\": \"athenz-crypki-tenant-b-ca\","
                + " \"caCertPath\": \"" + jsonPath(tenantPath) + "\" },"
                + " \"tenant-c-ca\": \"" + jsonPath(tenantPath) + "\" }\n");
        System.setProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH, mapPath);
        try {
            AwsCloudHsmClient client = new AwsCloudHsmClient(modulePathForCoverage(), null,
                    "athenz-crypki-ca", pinFile("crypto-user:example-pin"), defaultPath);
            assertEquals(client.getSigningKey(null).getIdentifier(), "athenz-crypki-ca");
            assertEquals(client.getSigningKey(CrypkiConsts.DEFAULT_KEY_ID).getCaCertificate()
                    .getSubjectX500Principal(), defaultCa.getSubjectX500Principal());
            assertEquals(client.getSigningKey("tenant-b-ca").getIdentifier(),
                    "athenz-crypki-tenant-b-ca");
            assertEquals(client.getSigningKey("tenant-b-ca").getCaCertificate()
                    .getSubjectX500Principal(), tenantCa.getSubjectX500Principal());
            assertEquals(client.getSigningKey("tenant-c-ca").getIdentifier(), "tenant-c-ca");
            assertEquals(client.resolveLabel("tenant-b-ca"), "athenz-crypki-tenant-b-ca");
            expectThrows(CrypkiException.class, () -> client.getSigningKey("other-label"));
        } finally {
            System.clearProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH);
        }
    }

    @Test
    public void testCloudHsmRejectsSharedLabelWithDifferentCa() throws Exception {
        StubKeyStoreSpi.key = rsaKeyPair().getPrivate();
        String defaultPath = writeCert(hsmCertificate("CN=hsm-default"));
        String tenantPath = writeCert(hsmCertificate("CN=hsm-other"));
        String mapPath = writeJson("{ \"tenant-b-ca\": { \"keyId\": \"athenz-crypki-ca\","
                + " \"caCertPath\": \"" + jsonPath(tenantPath) + "\" } }\n");
        System.setProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH, mapPath);
        try {
            expectThrows(CrypkiException.class, () -> new AwsCloudHsmClient(modulePathForCoverage(),
                    null, "athenz-crypki-ca", pinFile("crypto-user:example-pin"), defaultPath));
        } finally {
            System.clearProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH);
        }
    }

    @Test
    public void testCloudHsmAllowsSharedLabelWithSameCa() throws Exception {
        StubKeyStoreSpi.key = rsaKeyPair().getPrivate();
        X509Certificate ca = hsmCertificate("CN=hsm-shared");
        String defaultPath = writeCert(ca);
        String mapPath = writeJson("{ \"tenant-b-ca\": { \"keyId\": \"athenz-crypki-ca\","
                + " \"caCertPath\": \"" + jsonPath(defaultPath) + "\" } }\n");
        KmsCaCertificateStore store = new KmsCaCertificateStore(defaultPath, mapPath,
                CrypkiConsts.PROP_HSM_CA_CERT_PATH);
        AwsCloudHsmClient client = new AwsCloudHsmClient(modulePathForCoverage(), null,
                "athenz-crypki-ca", pinFile("crypto-user:example-pin"), store);
        assertEquals(client.getSigningKey("tenant-b-ca").getIdentifier(), "athenz-crypki-ca");
        assertEquals(client.getSigningKey("tenant-b-ca").getCaCertificate().getSubjectX500Principal(),
                ca.getSubjectX500Principal());
    }

    @Test
    public void testCloudHsmLookupNormalizesDefaultHttpKeyId() throws Exception {
        StubKeyStoreSpi.key = rsaKeyPair().getPrivate();
        X509Certificate ca = hsmCertificate("CN=hsm-http-default");
        String defaultPath = writeCert(ca);
        String mapPath = writeJson("{ \"tenant-b-ca\": { \"keyId\": \"x509-key\","
                + " \"caCertPath\": \"" + jsonPath(defaultPath) + "\" } }\n");
        KmsCaCertificateStore store = new KmsCaCertificateStore(defaultPath, mapPath,
                CrypkiConsts.PROP_HSM_CA_CERT_PATH);
        AwsCloudHsmClient client = new AwsCloudHsmClient(modulePathForCoverage(), null,
                "athenz-crypki-ca", pinFile("crypto-user:example-pin"), store);
        assertEquals(client.resolveLabel("tenant-b-ca"), "athenz-crypki-ca");
        assertEquals(client.getSigningKey("tenant-b-ca").getIdentifier(), "athenz-crypki-ca");
    }

    @Test
    public void testCloudHsmJceReusesRegisteredProviderForSecondLabel() throws Exception {
        KeyPair pair = rsaKeyPair();
        StubKeyStoreSpi.key = pair.getPrivate();
        CloudHsmProvider registered = new CloudHsmProvider();
        Security.addProvider(registered);
        CloudHsmProvider.throwOnConstruct = true;
        try {
            X509Certificate defaultCa = hsmCertificate("CN=hsm-default");
            X509Certificate tenantCa = hsmCertificate("CN=hsm-tenant-b");
            String defaultPath = writeCert(defaultCa);
            String tenantPath = writeCert(tenantCa);
            String mapPath = writeJson("{ \"tenant-b-ca\": { \"keyId\": \"athenz-crypki-tenant-b-ca\","
                    + " \"caCertPath\": \"" + jsonPath(tenantPath) + "\" } }\n");
            System.setProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH, mapPath);
            AwsCloudHsmClient client = new AwsCloudHsmClient(modulePathForCoverage(), null,
                    "athenz-crypki-ca", pinFile("crypto-user:example-pin"), defaultPath);
            assertEquals(client.getSigningKey(null).getIdentifier(), "athenz-crypki-ca");
            assertEquals(client.getSigningKey("tenant-b-ca").getIdentifier(),
                    "athenz-crypki-tenant-b-ca");
            assertEquals(client.getSigningKey("tenant-b-ca").getCaCertificate()
                    .getSubjectX500Principal(), tenantCa.getSubjectX500Principal());
        } finally {
            System.clearProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH);
            CloudHsmProvider.throwOnConstruct = false;
            Security.removeProvider(registered.getName());
        }
    }

    @Test
    public void testCloudHsmJceProviderHelpers() throws Exception {
        assertEquals(AwsCloudHsmClient.cloudHsmProviderNames(CloudHsmProvider.class)[0],
                CloudHsmProvider.PROVIDER_NAME);
        assertEquals(AwsCloudHsmClient.cloudHsmProviderNames(String.class)[0], "CloudHSM");
        assertEquals(AwsCloudHsmClient.cloudHsmProviderNames(EmptyNameProvider.class)[0], "CloudHSM");
        assertEquals(AwsCloudHsmClient.findRegisteredCloudHsmProvider(CloudHsmProvider.class), null);

        CloudHsmProvider oddName = new CloudHsmProvider("OddHsmName");
        Security.addProvider(oddName);
        try {
            assertEquals(AwsCloudHsmClient.findRegisteredCloudHsmProvider(CloudHsmProvider.class),
                    oddName);
        } finally {
            Security.removeProvider(oddName.getName());
        }

        CloudHsmProvider registered = new CloudHsmProvider();
        Security.addProvider(registered);
        CloudHsmProvider.throwOnConstruct = true;
        try {
            assertEquals(AwsCloudHsmClient.cloudHsmJceProvider(), registered);
            assertEquals(AwsCloudHsmClient.createCloudHsmProvider(CloudHsmProvider.class),
                    registered);
        } finally {
            CloudHsmProvider.throwOnConstruct = false;
            Security.removeProvider(registered.getName());
        }

        Provider created = AwsCloudHsmClient.cloudHsmJceProvider();
        try {
            assertNotNull(created);
            assertEquals(created.getName(), CloudHsmProvider.PROVIDER_NAME);
            assertEquals(AwsCloudHsmClient.createCloudHsmProvider(CloudHsmProvider.class),
                    Security.getProvider(CloudHsmProvider.PROVIDER_NAME));
        } finally {
            Security.removeProvider(created.getName());
        }

        expectThrows(IllegalStateException.class, () -> {
            CloudHsmProvider.throwOnConstruct = true;
            try {
                AwsCloudHsmClient.createCloudHsmProvider(CloudHsmProvider.class);
            } finally {
                CloudHsmProvider.throwOnConstruct = false;
            }
        });
        expectThrows(java.lang.reflect.InvocationTargetException.class,
                () -> AwsCloudHsmClient.createCloudHsmProvider(ErrorCtorProvider.class));

        AwsCloudHsmClient.loginCloudHsmJce(new java.security.Provider("plain", 1.0, "plain") { },
                "pin".toCharArray());
        CloudHsmProvider.failLoginAlready = true;
        try {
            CloudHsmProvider already = new CloudHsmProvider();
            AwsCloudHsmClient.loginCloudHsmJce(already, "pin".toCharArray());
            assertTrue(already.loggedIn);
        } finally {
            CloudHsmProvider.failLoginAlready = false;
        }
        assertTrue(AwsCloudHsmClient.alreadyConnected(
                new IllegalStateException("HSM connection is already initialized")));
        assertTrue(!AwsCloudHsmClient.alreadyConnected(new IllegalStateException("other")));
        assertTrue(!AwsCloudHsmClient.alreadyConnected(new IllegalStateException()));
        assertTrue(!AwsCloudHsmClient.alreadyConnected(
                new IllegalStateException("credentials already expired")));
    }

    public static class EmptyNameProvider {
        public static final String PROVIDER_NAME = "";
    }

    public static class ErrorCtorProvider extends Provider {
        public ErrorCtorProvider() {
            super("ErrorCtor", 1.0, "boom");
            throw new Error("boom");
        }
    }

    @Test
    public void testCloudHsmGetKeyFallsBackToAttributesMap() throws Exception {
        class LegacyStore {
            public Object getKey(KeyAttributesMap spec) {
                return "legacy-map-key";
            }
        }
        assertEquals(AwsCloudHsmClient.invokeCloudHsmGetKey(LegacyStore.class,
                new LegacyStore(), new KeyAttributesMap(), KeyAttributesMap.class),
                "legacy-map-key");
    }

    @Test
    public void testCloudHsmMappedLabelFallbacks() throws Exception {
        KmsCaCertificateStore empty = new KmsCaCertificateStore(null, null,
                CrypkiConsts.PROP_HSM_CA_CERT_PATH);
        assertEquals(AwsCloudHsmClient.mappedLabel("", "default-label", empty), "default-label");
        String mapPath = writeJson("{ \"tenant-b-ca\": { \"keyId\": \"x509-key\","
                + " \"caCertPath\": \"/tmp/x.pem\" } }\n");
        KmsCaCertificateStore mapped = new KmsCaCertificateStore("/tmp/default.pem", mapPath,
                CrypkiConsts.PROP_HSM_CA_CERT_PATH);
        assertEquals(AwsCloudHsmClient.mappedLabel("tenant-b-ca", "default-label", mapped),
                "default-label");
    }

    @Test
    public void testCloudHsmInjectedMapResolvesLabels() throws Exception {
        var caKey = Crypto.generateRSAPrivateKey(2048);
        X509Certificate defaultCa = hsmCertificate("CN=hsm-default");
        X509Certificate tenantCa = hsmCertificate("CN=hsm-tenant-b");
        SigningKey defaultKey = new SigningKey("athenz-crypki-ca", caKey, defaultCa);
        SigningKey tenantKey = new SigningKey("athenz-crypki-tenant-b-ca", caKey, tenantCa);
        String mapPath = writeJson("{ \"tenant-b-ca\": { \"keyId\": \"athenz-crypki-tenant-b-ca\","
                + " \"caCertPath\": \"" + jsonPath(writeCert(tenantCa)) + "\" } }\n");
        KmsCaCertificateStore store = new KmsCaCertificateStore(writeCert(defaultCa), mapPath,
                CrypkiConsts.PROP_HSM_CA_CERT_PATH);
        Map<String, SigningKey> keys = new LinkedHashMap<>();
        keys.put("athenz-crypki-ca", defaultKey);
        keys.put("athenz-crypki-tenant-b-ca", tenantKey);
        AwsCloudHsmClient client = new AwsCloudHsmClient(keys, "athenz-crypki-ca", store);
        assertEquals(client.getSigningKey("tenant-b-ca").getIdentifier(),
                "athenz-crypki-tenant-b-ca");
        assertEquals(client.getSigningKey(null).getIdentifier(), "athenz-crypki-ca");

        AwsCloudHsmClient withoutDefault = new AwsCloudHsmClient(
                Map.of("only-label", defaultKey), "configured-label", store);
        assertEquals(withoutDefault.getSigningKey(null).getIdentifier(), "athenz-crypki-ca");
        assertEquals(withoutDefault.getSigningKey("only-label").getIdentifier(), "athenz-crypki-ca");

        AwsCloudHsmClient empty = new AwsCloudHsmClient(Map.of(), "configured-label", store);
        expectThrows(CrypkiException.class, () -> empty.getSigningKey(null));
    }

    @Test
    public void testGetSigningKeyMatchesLoadedIdentifier() throws Exception {
        var caKey = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(caKey, "CN=hsm-ca,O=Athenz,C=US", null);
        X509Certificate ca = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr), caKey,
                new org.bouncycastle.asn1.x500.X500Name("CN=hsm-ca,O=Athenz,C=US"), 60, true);
        AwsCloudHsmClient client = new AwsCloudHsmClient(
                new SigningKey("loaded-label", caKey, ca), "configured-label");
        assertEquals(client.getSigningKey("loaded-label").getIdentifier(), "loaded-label");
    }

    @Test
    public void testLoadSunPkcs11WithMockedProvider() throws Exception {
        KeyPair pair = rsaKeyPair();
        Provider prototype = Mockito.mock(Provider.class);
        Provider configured = Mockito.mock(Provider.class);
        Mockito.when(configured.getName()).thenReturn("AthenzCrypkiHsm");
        Mockito.when(prototype.configure(Mockito.anyString())).thenReturn(configured);
        KeyStore store = Mockito.mock(KeyStore.class);
        Mockito.when(store.getKey(Mockito.eq("pkcs11-label"), Mockito.any())).thenReturn(pair.getPrivate());

        var caKey = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(caKey, "CN=hsm-ca,O=Athenz,C=US", null);
        X509Certificate ca = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr), caKey,
                new org.bouncycastle.asn1.x500.X500Name("CN=hsm-ca,O=Athenz,C=US"), 60, true);

        try (MockedStatic<Security> security = Mockito.mockStatic(Security.class, Mockito.CALLS_REAL_METHODS);
                MockedStatic<KeyStore> keyStores = Mockito.mockStatic(KeyStore.class, Mockito.CALLS_REAL_METHODS)) {
            security.when(() -> Security.getProvider("SunPKCS11")).thenReturn(prototype);
            security.when(() -> Security.getProvider("AthenzCrypkiHsm")).thenReturn(null);
            keyStores.when(() -> KeyStore.getInstance("PKCS11", configured)).thenReturn(store);

            SigningKey key = AwsCloudHsmClient.loadSunPkcs11(
                    "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so", null, "pkcs11-label",
                    "pin".toCharArray(), ca);
            assertEquals(key.getPrivateKey(), pair.getPrivate());

            Mockito.when(store.getKey(Mockito.eq("missing"), Mockito.any())).thenReturn(null);
            expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.loadSunPkcs11(
                    "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so", "1", "missing",
                    "pin".toCharArray(), ca));

            security.when(() -> Security.getProvider("AthenzCrypkiHsm")).thenReturn(configured);
            assertNotNull(AwsCloudHsmClient.pkcs11Provider(
                    "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so", "1"));

            security.when(() -> Security.getProvider("SunPKCS11")).thenReturn(null);
            expectThrows(CrypkiException.class, () -> AwsCloudHsmClient.pkcs11Provider("/x.so", null));
        }
    }

    private static SigningKey loadJceSigningKey(String label) throws Exception {
        return AwsCloudHsmClient.loadSigningKey(modulePathForCoverage(), null, label,
                pinFile("crypto-user:example-pin"), caCertFile());
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static String pinFile(String pin) throws Exception {
        java.io.File file = java.io.File.createTempFile("pin", ".txt");
        file.deleteOnExit();
        Files.writeString(file.toPath(), pin + "\n");
        return file.getAbsolutePath();
    }

    private static String caCertFile() throws Exception {
        return writeCert(hsmCertificate("CN=hsm-ca"));
    }

    private static X509Certificate hsmCertificate(String cn) throws Exception {
        var caKey = Crypto.generateRSAPrivateKey(2048);
        String dn = cn + ",O=Athenz,C=US";
        String csr = Crypto.generateX509CSR(caKey, dn, null);
        return Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr), caKey,
                new org.bouncycastle.asn1.x500.X500Name(dn), 60, true);
    }

    private static String writeCert(X509Certificate ca) throws Exception {
        java.io.File certFile = java.io.File.createTempFile("hsmca", ".pem");
        certFile.deleteOnExit();
        Files.writeString(certFile.toPath(), Crypto.convertToPEMFormat(ca));
        return certFile.getAbsolutePath();
    }

    private static String writeJson(String json) throws Exception {
        java.io.File file = java.io.File.createTempFile("hsmmap", ".json");
        file.deleteOnExit();
        Files.writeString(file.toPath(), json);
        return file.getAbsolutePath();
    }

    private static String jsonPath(String path) {
        return path.replace("\\", "\\\\");
    }
}
