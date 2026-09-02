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
package com.yahoo.athenz.crypki.x509;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiException;
import com.yahoo.athenz.crypki.X509SignRequest;
import com.yahoo.athenz.crypki.signer.SigningKey;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.testng.annotations.Test;

import javax.security.auth.x500.X500Principal;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

public class X509CertificateMinterTest {

    @Test
    public void testMintsLeafWithSanAndDefaultEku() throws Exception {
        SigningKey ca = rsaCa();
        PrivateKey leafKey = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(leafKey, "CN=athenz.api,O=Athenz,C=US",
                new GeneralName[]{
                        new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://athenz/sa/api"),
                        new GeneralName(GeneralName.dNSName, "api.athenz.example")
                });
        X509CertificateMinter minter = new X509CertificateMinter(3600);
        X509Certificate cert = minter.signCertificate(ca.getPrivateKey(), ca.getCaCertificate(),
                X509SignRequest.builder().csrPem(csr).validitySeconds(60).build());
        assertNotNull(cert);
        assertTrue(Crypto.convertToPEMFormat(cert).contains("BEGIN CERTIFICATE"));
        List<String> eku = cert.getExtendedKeyUsage();
        assertTrue(eku.contains("1.3.6.1.5.5.7.3.1"));
        assertTrue(eku.contains("1.3.6.1.5.5.7.3.2"));
    }

    @Test
    public void testEkuMappingAndInvalidCsr() throws Exception {
        assertEquals(X509CertificateMinter.toKeyPurposeId(X509CertificateMinter.EKU_SERVER_AUTH),
                KeyPurposeId.id_kp_serverAuth);
        assertEquals(X509CertificateMinter.toKeyPurposeId(X509CertificateMinter.EKU_CLIENT_AUTH),
                KeyPurposeId.id_kp_clientAuth);
        assertEquals(X509CertificateMinter.toKeyPurposeId(X509CertificateMinter.EKU_CODE_SIGNING),
                KeyPurposeId.id_kp_codeSigning);
        assertEquals(X509CertificateMinter.toKeyPurposeId(X509CertificateMinter.EKU_TIME_STAMPING),
                KeyPurposeId.id_kp_timeStamping);
        assertEquals(X509CertificateMinter.toKeyPurposeId(99), KeyPurposeId.id_kp_clientAuth);

        X509CertificateMinter minter = new X509CertificateMinter(60);
        expectThrows(CrypkiException.class, () -> minter.sign(rsaCa(), null));
        expectThrows(CrypkiException.class, () -> minter.sign(rsaCa(),
                X509SignRequest.builder().csrPem("").build()));
        expectThrows(CrypkiException.class, () -> minter.sign(rsaCa(),
                X509SignRequest.builder().csrPem("not-a-csr").build()));
    }

    @Test
    public void testCodeSigningAndTimestamping() throws Exception {
        SigningKey ca = rsaCa();
        PrivateKey leafKey = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(leafKey, "CN=code.client,O=Athenz,C=US", null);
        String codeSigning = new X509CertificateMinter(120).sign(ca,
                X509SignRequest.builder().csrPem(csr).validitySeconds(30)
                        .extKeyUsage(List.of(X509CertificateMinter.EKU_CODE_SIGNING)).build());
        assertTrue(codeSigning.contains("BEGIN CERTIFICATE"));
        String timestamping = new X509CertificateMinter(120).sign(ca,
                X509SignRequest.builder().csrPem(csr).validitySeconds(30)
                        .extKeyUsage(List.of(X509CertificateMinter.EKU_TIME_STAMPING)).build());
        assertTrue(timestamping.contains("BEGIN CERTIFICATE"));
    }

    @Test
    public void testSanIpEmailAndIgnoredTags() throws Exception {
        SigningKey ca = rsaCa();
        PrivateKey leafKey = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(leafKey, "CN=mixed.san,O=Athenz,C=US",
                new GeneralName[]{
                        new GeneralName(GeneralName.iPAddress, "192.0.2.10"),
                        new GeneralName(GeneralName.rfc822Name, "ops@athenz.example"),
                        new GeneralName(new X500Name("CN=directory-name"))
                });
        X509Certificate cert = new X509CertificateMinter(60).signCertificate(ca.getPrivateKey(),
                ca.getCaCertificate(), X509SignRequest.builder().csrPem(csr).validitySeconds(0).build());
        boolean sawIp = false;
        boolean sawEmail = false;
        boolean sawDirectory = false;
        for (java.util.List<?> entry : cert.getSubjectAlternativeNames()) {
            String value = String.valueOf(entry.get(1));
            sawIp |= "192.0.2.10".equals(value);
            sawEmail |= "ops@athenz.example".equals(value);
            sawDirectory |= value.contains("directory-name");
        }
        assertTrue(sawIp);
        assertTrue(sawEmail);
        assertFalse(sawDirectory);
    }

    @Test
    public void testExtensionRequestWithoutSan() throws Exception {
        SigningKey ca = rsaCa();
        KeyPair leaf = rsaKeyPair();
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=ext-only,O=Athenz,C=US"), leaf.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        String csr = Crypto.convertToPEMFormat(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(leaf.getPrivate())));
        X509Certificate cert = new X509CertificateMinter(60).signCertificate(ca.getPrivateKey(),
                ca.getCaCertificate(), X509SignRequest.builder().csrPem(csr).build());
        assertNotNull(cert);
        assertTrue(cert.getSubjectAlternativeNames() == null
                || cert.getSubjectAlternativeNames().isEmpty());
    }

    @Test
    public void testEcContentSignerAndInvalidPrivateKey() {
        PrivateKey invalidEc = dummyPrivateKey("EC");
        expectThrows(CrypkiException.class, () -> X509CertificateMinter.contentSigner(invalidEc));

        Provider fakePkcs11 = new Provider("SunPKCS11-Test", "1.0", "test") {
        };
        Security.insertProviderAt(fakePkcs11, 1);
        try {
            expectThrows(CrypkiException.class, () -> X509CertificateMinter.contentSigner(dummyPrivateKey("RSA")));
        } finally {
            Security.removeProvider("SunPKCS11-Test");
        }
    }

    private static SigningKey rsaCa() throws Exception {
        PrivateKey caKey = Crypto.generateRSAPrivateKey(2048);
        String csrPem = Crypto.generateX509CSR(caKey, "CN=Athenz Test CA,O=Athenz,C=US", null);
        PKCS10CertificationRequest csr = Crypto.getPKCS10CertRequest(csrPem);
        X509Certificate caCert = Crypto.generateX509Certificate(csr, caKey,
                new X500Name("CN=Athenz Test CA,O=Athenz,C=US"), 365 * 24 * 60, true);
        return new SigningKey("ca", caKey, caCert);
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static PrivateKey dummyPrivateKey(String algorithm) {
        return new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return algorithm;
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };
    }
}
