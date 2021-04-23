/*
 * Copyright 2019 Oath Holdings, Inc.
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
package com.yahoo.athenz.auth.util;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import static com.yahoo.athenz.auth.AuthorityConsts.ATHENZ_PROP_RESTRICTED_OU;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class CryptoTest {

    private final File rsaPrivateKey = new File("./src/test/resources/unit_test_rsa_private.key");
    private final File rsaPublicKey = new File("./src/test/resources/rsa_public.key");
    private final File rsaPublicX590Cert = new File("./src/test/resources/rsa_public_x509.cert");
    private final File rsaPublicInvalidKey = new File("./src/test/resources/rsa_public_invalid.key");

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");
    private final File ecPublicX509Cert = new File("./src/test/resources/ec_public_x509.cert");
    private final File ecPublicInvalidKey = new File("./src/test/resources/ec_public_invalid.key");
    private final File ecPrivateParamPrime256v1Key = new File("./src/test/resources/unit_test_ec_private_param_prime256v1.key");
    private final File ecPublicParamPrime256v1Key = new File("./src/test/resources/ec_public_param_prime256v1.key");
    private final File ecPrivateParamSecp384r1Key = new File("./src/test/resources/unit_test_ec_private_param_secp384r1.key");
    private final File ecPublicParamSecp384r1Key = new File("./src/test/resources/ec_public_param_secp384r1.key");
    private final File ecPrivateParamsKey = new File("./src/test/resources/unit_test_ec_private_params.key");
    private final File ecPublicParamsKey = new File("./src/test/resources/ec_public_params.key");
    private final File argFile = new File("./src/test/resources/arg_file");
    private final File noFile = new File("./src/test/resources/ec_private_test_not_exist.key");

    private final File privateEncryptedKey = new File("./src/test/resources/unit_test_private_encrypted.key");
    private final String encryptedKeyPassword = "athenz";

    private final String serviceToken = "v=S1;d=coretech;n=storage;t=1234567000;e=123456800;h=localhost";
    private final String serviceRSASignature = "VsUlcNozK4as1FjPbowEE_DFDD8KWpQzphadfbt_TsMoCTLFpYrMzKTu_nHKemJmEi0bbPwj7hRLrIKEFu2VjQ--";
    private final String serviceECSignature = "MEQCIEBnyNCxp5GSeua3K9OenyetmVs4F68VB.Md1JRaU4OXAiBWAxlJLe74ZV4QDqapsD4FJm.MA3mv0FMcq.LEevJa0g--";

    @Test
    public void testSignVerifyRSAKey() {

        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
        assertNotNull(privateKey);

        String signature = Crypto.sign(serviceToken, privateKey);
        assertEquals(signature, serviceRSASignature);

        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicKey);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken, publicKey, signature));
    }

    @Test
    public void testSignVerifyExtractedRSAKey() {

        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
        assertNotNull(privateKey);

        String signature = Crypto.sign(serviceToken, privateKey);
        assertEquals(signature, serviceRSASignature);

        PublicKey publicKey = Crypto.extractPublicKey(privateKey);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken, publicKey, signature));
    }

    @Test
    public void testSignVerifyRSAKey_Invalid() {

        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicInvalidKey);
        assertNotNull(publicKey);

        assertFalse(Crypto.verify(serviceToken, publicKey, serviceRSASignature));
    }

    @Test
    public void testSignVerifyRSAKey_X509() {

        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicX590Cert);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken, publicKey, serviceRSASignature));
    }

    @Test
    public void testSignVerifyECKey() {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        assertNotNull(privateKey);

        String signature = Crypto.sign(serviceToken, privateKey);

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken, publicKey, signature));
    }

    @Test
    public void testSignVerifyExtractedECKey() {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        assertNotNull(privateKey);

        String signature = Crypto.sign(serviceToken, privateKey);

        PublicKey publicKey = Crypto.extractPublicKey(privateKey);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken, publicKey, signature));
    }

    @Test
    public void testExtractPublicKeyECException() {
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        assertNotNull(privateKey);


        System.setProperty(Crypto.ATHENZ_CRYPTO_ALGO_ECDSA, "abcd");
        assertThrows(CryptoException.class, () -> Crypto.extractPublicKey(privateKey));
        System.clearProperty(Crypto.ATHENZ_CRYPTO_ALGO_ECDSA);

        System.setProperty(Crypto.ATHENZ_CRYPTO_BC_PROVIDER, "C");
        assertThrows(CryptoException.class, () -> Crypto.extractPublicKey(privateKey));
        System.clearProperty(Crypto.ATHENZ_CRYPTO_BC_PROVIDER);
    }

    @Test
    public void testExtractPublicKeyRSAException() {

        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
        assertNotNull(privateKey);

        System.setProperty(Crypto.ATHENZ_CRYPTO_ALGO_RSA, "abcd");
        assertThrows(CryptoException.class, () -> Crypto.extractPublicKey(privateKey));
        System.clearProperty(Crypto.ATHENZ_CRYPTO_ALGO_RSA);

        System.setProperty(Crypto.ATHENZ_CRYPTO_BC_PROVIDER, "C");
        assertThrows(CryptoException.class, () -> Crypto.extractPublicKey(privateKey));
        System.clearProperty(Crypto.ATHENZ_CRYPTO_BC_PROVIDER);
    }

    @Test
    public void testExctractPublicKeyDefault() {
        PrivateKey privateKey = mock(PrivateKey.class);
        when(privateKey.getAlgorithm()).thenReturn("TestAlgo");

        assertThrows(CryptoException.class, () -> Crypto.extractPublicKey(privateKey));
    }

    @Test
    public void testSignVerifyECKey_Invalid() {

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicInvalidKey);
        assertNotNull(publicKey);

        boolean result;
        try {
            result = Crypto.verify(serviceToken, publicKey, serviceECSignature);
        } catch (CryptoException ignored) {
            result = false;
        }
        assertFalse(result);
    }

    @Test
    public void testSignVerifyECKey_X509() {

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicX509Cert);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken, publicKey, serviceECSignature));
    }

    @Test
    public void testLoadX509CertificateFile() {

        X509Certificate cert = Crypto.loadX509Certificate(ecPublicX509Cert);
        assertNotNull(cert);

        assertEquals(cert.getSubjectX500Principal().getName(),
                "CN=athenz.syncer,O=My Test Company,L=Sunnyvale,ST=CA,C=US");
    }

    @Test
    public void testLoadX509CertificateString() throws IOException {

        Path path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertNotNull(cert);

        assertEquals(cert.getSubjectX500Principal().getName(),
                "CN=athenz.syncer,O=My Test Company,L=Sunnyvale,ST=CA,C=US");
    }


    @Test
    public void testLoadX509CertificateInvalid() throws IOException {

        Path path = Paths.get("src/test/resources/invalid_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        try {
            Crypto.loadX509Certificate(certStr);
            fail();
        } catch (CryptoException ex) {
            assertTrue(true, "Caught expected CryptoException");
        }

        File failX509Cert = new File("./src/test/resources/fail_x509.cert");
        try {
            Crypto.loadX509Certificate(failX509Cert);
            fail();
        } catch (CryptoException e) {
            assertTrue(true, "Caught FileNotFoundException while");
        }
    }

    @Test
    public void testLoadPrivateEncryptedKey() {
        PrivateKey privateKey = Crypto.loadPrivateKey(privateEncryptedKey, encryptedKeyPassword);
        assertNotNull(privateKey);
    }

    @Test
    public void testLoadPrivateEncryptedKeyInvalidPassword() {

        // first try with no password

        try {
            Crypto.loadPrivateKey(privateEncryptedKey, null);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("No password specified"));
        }

        // now let's try with invalid password

        try {
            Crypto.loadPrivateKey(privateEncryptedKey, "InvalidPassword");
            fail();
        } catch (CryptoException ex) {
            assertTrue(true, "Invalid password specified");
        }
    }

    @Test
    public void testLoadPrivateKeyInvalidFile() {
        File temp = new File("test/Invalid/File/path.key");
        assertThrows(CryptoException.class, () -> Crypto.loadPrivateKey(temp, "test"));
    }


    @Test
    public void testSignVerifyECParamPrime256v1Key() {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateParamPrime256v1Key);
        assertNotNull(privateKey);

        String signature = Crypto.sign(serviceToken, privateKey);

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicParamPrime256v1Key);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken, publicKey, signature));
    }

    @Test
    public void testSignVerifyECParamsKey() {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateParamsKey);
        assertNotNull(privateKey);

        String signature = Crypto.sign(serviceToken, privateKey);

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicParamsKey);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken, publicKey, signature));
    }
    @Test
    public void testSignVerifyECParamsKeyException() {
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateParamsKey);
        assertNotNull(privateKey);

        Crypto.sign(serviceToken, privateKey);

        System.setProperty(Crypto.ATHENZ_CRYPTO_BC_PROVIDER, "C");
        assertThrows(CryptoException.class, () -> Crypto.loadPublicKey(ecPublicParamsKey));
        System.clearProperty(Crypto.ATHENZ_CRYPTO_BC_PROVIDER);

        System.setProperty(Crypto.ATHENZ_CRYPTO_ALGO_ECDSA, "TESTAlgo");
        assertThrows(CryptoException.class, () -> Crypto.loadPublicKey(ecPublicParamsKey));
        System.clearProperty(Crypto.ATHENZ_CRYPTO_ALGO_ECDSA);

    }

    @Test
    public void testSignVerifyECParamSecp384r1Key() {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateParamSecp384r1Key);
        assertNotNull(privateKey);

        String signature = Crypto.sign(serviceToken, privateKey);

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicParamSecp384r1Key);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken, publicKey, signature));
    }

    @Test
    public void testLoadPublicKeyException() {
        assertThrows(CryptoException.class, () -> Crypto.loadPublicKey(noFile));
    }
    @Test
    public void testSignVerifyECParamMixCurvesFail() {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateParamPrime256v1Key);
        assertNotNull(privateKey);

        String signature = Crypto.sign(serviceToken, privateKey);

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicParamSecp384r1Key);
        assertNotNull(publicKey);

        assertFalse(Crypto.verify(serviceToken, publicKey, signature));
    }

    @Test
    public void testSignVerifyECParamKeyOpenssl() {

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicParamPrime256v1Key);
        assertNotNull(publicKey);

        // this test case is from ysecure using openssl

        String plainText = "This is a test of the ysecure public key interface.  This is only a test.";
        String signature = "MEUCIBjTLIhH_Rc3fkRXJ8CvzSqkIwxXqReg7nOe_q1t_C73AiEAky4NAP.CwlYKXlto93f_JTYOQqDpZSJeTYSe80fQ5vY-";

        assertTrue(Crypto.verify(plainText, publicKey, signature));
    }

    @Test
    public void testGetSignatureAlgorithmRSA() {
        try {
            assertEquals(Crypto.getSignatureAlgorithm("RSA"), "SHA256withRSA");
            assertEquals(Crypto.getSignatureAlgorithm("RSA", "SHA256"), "SHA256withRSA");
            assertEquals(Crypto.getSignatureAlgorithm("RSA", "SHA1"), "SHA1withRSA");
        } catch (NoSuchAlgorithmException e) {
            fail();
        }
    }

    @Test
    public void testGetSignatureAlgorithmEC() {
        try {
            assertEquals(Crypto.getSignatureAlgorithm("ECDSA"), "SHA256withECDSA");
            assertEquals(Crypto.getSignatureAlgorithm("ECDSA", "SHA256"), "SHA256withECDSA");
            assertEquals(Crypto.getSignatureAlgorithm("ECDSA", "SHA1"), "SHA1withECDSA");
        } catch (NoSuchAlgorithmException e) {
            fail();
        }
    }

    @Test
    public void testGetSignatureAlgorithmUnknown() {

        try {
            assertEquals(Crypto.getSignatureAlgorithm("DSA", "SHA256"), "SHA256withDSA");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof NoSuchAlgorithmException, ex.getMessage());
        }
        try {
            assertEquals(Crypto.getSignatureAlgorithm("RSA", "SHA555"), "SHA555withRSA");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof NoSuchAlgorithmException, ex.getMessage());
        }
        try {
            assertEquals(Crypto.getSignatureAlgorithm("ECDSA", "SHA999"), "SHA999withECDSA");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof NoSuchAlgorithmException, ex.getMessage());
        }
    }

    @Test
    public void testGetPKCS10CertRequest() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String certStr = new String(Files.readAllBytes(path));

        PKCS10CertificationRequest req = Crypto.getPKCS10CertRequest(certStr);
        assertNotNull(req);
        assertEquals(req.getSubject().toString(), "C=US,ST=CA,L=Sunnyvale,O=My Test Company,CN=athenz.syncer");

        Crypto.extractX509CSRPublicKey(req);
    }

    @Test
    public void testGetPKCS10CertRequestInvalid() throws IOException {

        // first try with empty values

        try {
            Crypto.getPKCS10CertRequest(null);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("CSR is null"));
        }

        try {
            Crypto.getPKCS10CertRequest("");
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("CSR is null"));
        }

        // now let's try with invalid csr

        Path path = Paths.get("src/test/resources/invalid.csr");
        String certStr = new String(Files.readAllBytes(path));

        try {
            Crypto.getPKCS10CertRequest(certStr);
            fail();
        } catch (CryptoException ex) {
            assertTrue(true, "Caught expected crypto exception");
        }
    }

    @Test
    public void testGenerateX509Certificate() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String certStr = new String(Files.readAllBytes(path));

        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(certStr);
        X509Certificate caCertificate = Crypto.loadX509Certificate(ecPublicX509Cert);
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(privateEncryptedKey, encryptedKeyPassword);

        X509Certificate cert = Crypto.generateX509Certificate(certReq, caPrivateKey,
                caCertificate, 600, false);
        assertNotNull(cert);
        assertEquals(cert.getIssuerX500Principal().getName(),
                "CN=athenz.syncer,O=My Test Company,L=Sunnyvale,ST=CA,C=US");

        Date notAfter = cert.getNotAfter();
        long diff = notAfter.getTime() - System.currentTimeMillis();
        assertTrue(diff <= 600 * 60 * 1000); // convert minutes to milliseconds
    }

    @Test
    public void testGenerateX509CertificateAltNames() throws IOException {

        Path path = Paths.get("src/test/resources/csr_altnames.csr");
        String certStr = new String(Files.readAllBytes(path));

        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(certStr);
        X509Certificate caCertificate = Crypto.loadX509Certificate(ecPublicX509Cert);
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(privateEncryptedKey, encryptedKeyPassword);

        X509Certificate cert = Crypto.generateX509Certificate(certReq, caPrivateKey,
                caCertificate, 600, true);
        assertNotNull(cert);
    }

    @Test
    public void testGenerateX509CertificateReqPrivateKey() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String certStr = new String(Files.readAllBytes(path));

        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(certStr);
        X509Certificate caCertificate = Crypto.loadX509Certificate(ecPublicX509Cert);
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(rsaPrivateKey);

        X509Certificate cert = Crypto.generateX509Certificate(certReq, caPrivateKey,
                caCertificate, 600, false);
        assertNotNull(cert);
        assertEquals(cert.getIssuerX500Principal().getName(),
                "CN=athenz.syncer,O=My Test Company,L=Sunnyvale,ST=CA,C=US");
    }

    @Test
    public void testGenerateX509CertificateInvalid() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String certStr = new String(Files.readAllBytes(path));

        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(certStr);
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(rsaPrivateKey);

        try {
            Crypto.generateX509Certificate(certReq, caPrivateKey, (X500Name) null, 600, true);
            fail();
        } catch (CryptoException ex) {
            assertTrue(true, "Caught excepted exception");
        }
    }

    @Test
    public void testX509CertificateToPem() {
        X509Certificate cert = Crypto.loadX509Certificate(ecPublicX509Cert);
        String pem = Crypto.convertToPEMFormat(cert);
        assertNotNull(pem);
        assertTrue(pem.contains("BEGIN CERTIFICATE"), pem);
        assertTrue(pem.contains("END CERTIFICATE"), pem);
    }

    @Test
    public void testLoadReaderPrivateKey() {
        try (java.io.FileReader fileReader = new java.io.FileReader(rsaPrivateKey)) {
            PrivateKey privateKey = Crypto.loadPrivateKey(fileReader);
            assertNotNull(privateKey);
        } catch (IOException e) {
            fail();
        }
    }

    @Test
    public void testEnDecodedFile() {
        String encoded = Crypto.encodedFile(argFile);
        assertNotNull(encoded);

    }

    @Test
    public void testEncodedFileStream() {
        try (FileInputStream in = new FileInputStream(argFile)) {
            String encoded = Crypto.encodedFile(in);
            assertNotNull(encoded);

            String decoded = Crypto.ybase64DecodeString(encoded);
            assertEquals(decoded, "check");
        } catch (Exception e) {
            fail();
        }
    }


    @Test
    public void testSHA256() {
        byte [] checkByte = Crypto.sha256("check");
        assertNotNull(checkByte);
    }

    @DataProvider
    public Object[][] x500Principal() {
        return new Object[][] {
                {"CN=athenzcompany.com,O=foo", false},
                {"CDDN=athenzcompany.com", true},
        };
    }

    @Test(dataProvider = "x500Principal")
    public void testX509CSRrequest(String x500Principal, boolean badRequest) {
        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicKey);
        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
        String certRequest = null;
        GeneralName otherName1 = new GeneralName(GeneralName.otherName, new DERIA5String("role1"));
        GeneralName otherName2 = new GeneralName(GeneralName.otherName, new DERIA5String("role2"));
        GeneralName[] sanArray = new GeneralName[]{otherName1, otherName2};
        try {
            certRequest = Crypto.generateX509CSR(privateKey, publicKey, x500Principal, sanArray);
        } catch (Exception e) {
            if (!badRequest) {
                fail("Should not have failed to create csr");
            }
        }
        if (!badRequest) {
            //Now validate the csr
            Crypto.getPKCS10CertRequest(certRequest);
        }
    }

    @Test(dataProvider = "x500Principal")
    public void testX509CSRrequestWithPrivateKeyOnly(String x500Principal, boolean badRequest) {
        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
        String certRequest = null;
        GeneralName otherName1 = new GeneralName(GeneralName.otherName, new DERIA5String("role1"));
        GeneralName otherName2 = new GeneralName(GeneralName.otherName, new DERIA5String("role2"));
        GeneralName[] sanArray = new GeneralName[]{otherName1, otherName2};
        try {
            certRequest = Crypto.generateX509CSR(privateKey, x500Principal, sanArray);
        } catch (Exception e) {
            if (!badRequest) {
                fail("Should not have failed to create csr");
            }
        }
        if (!badRequest) {
            //Now validate the csr
            Crypto.getPKCS10CertRequest(certRequest);
        }
    }

    @Test
    public void testExtractX509CertCommonName() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertEquals(Crypto.extractX509CertCommonName(cert), "athenz.syncer");
        }
    }

    @Test
    public void testIsRestrictedCertificateNotSet() throws Exception {
        GlobStringsMatcher globStringsMatcher = new GlobStringsMatcher(ATHENZ_PROP_RESTRICTED_OU);

        try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_1.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            assertFalse(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
        }
    }

    @Test
    public void testIsRestrictedCertificateSuffix() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_4.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            assertTrue(Crypto.isRestrictedCertificate(cert, null));
        }
    }

    @Test
    public void testIsRestrictedCertificateNullArguments() throws Exception {
        System.setProperty("athenz.crypto.restricted_ou", "other.ou");
        GlobStringsMatcher globStringsMatcher = new GlobStringsMatcher(ATHENZ_PROP_RESTRICTED_OU);

        try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_1.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            // If one of the arguments is null return true (assume restricted cert)
            assertTrue(Crypto.isRestrictedCertificate(cert, null));
            assertTrue(Crypto.isRestrictedCertificate(null, globStringsMatcher));
            assertTrue(Crypto.isRestrictedCertificate(null, null));

            // Both arguments set
            assertFalse(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
        }
    }

    @Test
    public void testIsRestrictedCertificate() throws Exception {
        System.setProperty("athenz.crypto.restricted_ou", "restricted.ou.1");
        GlobStringsMatcher globStringsMatcher = new GlobStringsMatcher(ATHENZ_PROP_RESTRICTED_OU);
        try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_1.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            assertTrue(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
        } finally {
            System.clearProperty("athenz.crypto.restricted_ou");
        }
    }

    @Test
    public void testIsRestrictedCertificatePartial() throws Exception {
        System.setProperty("athenz.crypto.restricted_ou", "restricted.ou*");
        GlobStringsMatcher globStringsMatcher = new GlobStringsMatcher(ATHENZ_PROP_RESTRICTED_OU);
        try {
            // First three should match
            try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_1.pem")) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                assertTrue(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
            }
            try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_2.pem")) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                assertTrue(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
            }
            try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_3.pem")) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                assertTrue(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
            }
            // This one's OU doesn't match the pattern (regular_ou)
            try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/regular_ou.pem")) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                assertFalse(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
            }
        } finally {
            System.clearProperty("athenz.crypto.restricted_ou");
        }
    }

    @Test
    public void testIsRestrictedCertificateMultipleValues() throws Exception {
        System.setProperty("athenz.crypto.restricted_ou", "restricted.ou.1, regular.ou");
        GlobStringsMatcher globStringsMatcher = new GlobStringsMatcher(ATHENZ_PROP_RESTRICTED_OU);

        try {
            // restricted_ou_1 should match
            try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_1.pem")) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                assertTrue(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
            }
            // The others that begin with "restricted_ou" shouldn't
            try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_2.pem")) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                assertFalse(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
            }
            try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/restricted_ou_3.pem")) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                assertFalse(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
            }
            // regular_ou should match
            try (InputStream inStream = new FileInputStream("src/test/resources/ou_tests/regular_ou.pem")) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                assertTrue(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
            }
        } finally {
            System.clearProperty("athenz.crypto.restricted_ou");
        }
    }

    @Test
    public void testIsRestrictedCertificateNotMatched() throws Exception {
        System.setProperty("athenz.crypto.restricted_ou", "other.ou");
        GlobStringsMatcher globStringsMatcher = new GlobStringsMatcher(ATHENZ_PROP_RESTRICTED_OU);

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            assertFalse(Crypto.isRestrictedCertificate(cert, globStringsMatcher));
        } finally {
            System.clearProperty("athenz.crypto.restricted_ou");
        }
    }

    @Test
    public void testExtractX509CertOField() throws Exception{
        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertEquals(Crypto.extractX509CertSubjectOField(cert), "My Test Company");
        }
    }

    @Test
    public void testExtractX509CertOUField() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertNull(Crypto.extractX509CertSubjectOUField(cert));
        }

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_email_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            assertEquals(Crypto.extractX509CertSubjectOUField(cert), "Testing Domain");
        }
    }

    @Test
    public void testExtractX509CertIpAddressesNull() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> ips = Crypto.extractX509CertIPAddresses(cert);
            assertTrue(ips.isEmpty());
        }

        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_noip.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> ips = Crypto.extractX509CertIPAddresses(cert);
            assertTrue(ips.isEmpty());
        }
    }

    @Test
    public void testExtractX509CertIpAddressesSingle() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_singleip.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> ips = Crypto.extractX509CertIPAddresses(cert);
            assertEquals(ips.size(), 1);
            assertEquals(ips.get(0), "10.11.12.13");
        }
    }

    @Test
    public void testExtractX509CertPublicKey() throws Exception {
        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_singleip.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            Crypto.extractX509CertPublicKey(cert);
        }
    }

    @Test
    public void testExtractX509CertIpAddressesDouble() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_doubleip.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> ips = Crypto.extractX509CertIPAddresses(cert);
            assertEquals(2, ips.size());
            assertEquals(ips.get(0), "10.11.12.13");
            assertEquals(ips.get(1), "10.11.12.14");
        }
    }

    @Test
    public void testExtractX509CertURIsNull() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> uris = Crypto.extractX509CertURIs(cert);
            assertTrue(uris.isEmpty());

            // no spiffe uri - returning null
            assertNull(Crypto.extractX509CertSpiffeUri(cert));
        }

        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_noip.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> uris = Crypto.extractX509CertURIs(cert);
            assertTrue(uris.isEmpty());

            // no spiffe uri - returning null
            assertNull(Crypto.extractX509CertSpiffeUri(cert));
        }
    }

    @Test
    public void testExtractX509CertURIsNullSingle() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_singleuri.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> uris = Crypto.extractX509CertURIs(cert);
            assertEquals(1, uris.size());
            assertEquals(uris.get(0), "spiffe://athenz/domain1/service1");

            // single spiffe uri - successfully validated
            assertEquals(Crypto.extractX509CertSpiffeUri(cert), "spiffe://athenz/domain1/service1");
        }
    }

    @Test
    public void testExtractX509CertURIsNullDouble() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_doubleuri.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> uris = Crypto.extractX509CertURIs(cert);
            assertEquals(2, uris.size());
            assertEquals(uris.get(0), "spiffe://athenz/domain1/service1");
            assertEquals(uris.get(1), "spiffe://athenz/domain1/service2");

            // multiple spiffe uri - invalid - returning null
            assertNull(Crypto.extractX509CertSpiffeUri(cert));
        }
    }

    @Test
    public void testExtractX509CertSpifeeURINull() throws Exception {

        try (InputStream inStream = new FileInputStream("src/test/resources/role_cert_principal_uri_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> uris = Crypto.extractX509CertURIs(cert);
            assertEquals(2, uris.size());
            assertEquals(uris.get(0), "athenz://instanceid/sys.auth.zts/id001");
            assertEquals(uris.get(1), "athenz://principal/athenz.production");

            // valid uris - but not spiffe - returning null
            assertNull(Crypto.extractX509CertSpiffeUri(cert));
        }
    }

    @Test
    public void testExtractX509CSRFields() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq1 = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq1);
        PKCS10CertificationRequest certReq = Mockito.spy(certReq1);
        assertNotNull(certReq);
        assertEquals(Crypto.extractX509CSRCommonName(certReq), "athenz.syncer");
        assertEquals(Crypto.extractX509CSRSubjectOField(certReq), "My Test Company");
        assertNull(Crypto.extractX509CSRSubjectOUField(certReq));
        assertNull(Crypto.extractX509CSREmail(certReq));
    }

    @Test
    public void testExtractX509CSRFieldsWithRfc822() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq);

        assertEquals(Crypto.extractX509CSRCommonName(certReq), "sports:role.readers");
        assertEquals(Crypto.extractX509CSREmail(certReq), "sports.scores@aws.yahoo.cloud");
    }

    @Test
    public void testExtractX509CSRFieldsWithRfc822s() throws IOException {

        Path path = Paths.get("src/test/resources/valid_emails.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq);

        assertEquals(Crypto.extractX509CSRCommonName(certReq), "athenz.production");
        List<String> emails = Crypto.extractX509CSREmails(certReq);
        assertEquals(2, emails.size());
        assertEquals(emails.get(0), "sports.scores@aws.yahoo.cloud");
        assertEquals(emails.get(1), "nhl.scores@aws.yahoo.cloud");
    }

    @Test
    public void testExtractX509CSRDnsNames() throws IOException {
        Path path = Paths.get("src/test/resources/valid_emails.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq);

        List<String> dnsNames = new LinkedList<>();
        dnsNames.add("production.athenz.ostk.athenz.cloud");
        dnsNames.add("1001.instanceid.athenz.ostk.athenz.cloud");
        assertEquals(Crypto.extractX509CSRDnsNames(certReq), dnsNames);
    }

    @Test
    public void testExtractX509CSRFieldsURINull() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq);

        List<String> uris = Crypto.extractX509CSRURIs(certReq);
        assertEquals(0, uris.size());
    }

    @Test
    public void testExtractX509CSRFieldsURISingle() throws IOException {

        Path path = Paths.get("src/test/resources/valid_single_uri.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq);

        List<String> uris = Crypto.extractX509CSRURIs(certReq);
        assertEquals(1, uris.size());
        assertEquals(uris.get(0), "spiffe://athenz/domain1/service1");
    }

    @Test
    public void testExtractX509CSRFieldsURIDouble() throws IOException {

        Path path = Paths.get("src/test/resources/valid_multiple_uri.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq);

        List<String> uris = Crypto.extractX509CSRURIs(certReq);
        assertEquals(2, uris.size());
        assertEquals(uris.get(0), "spiffe://athenz/domain1/service1");
        assertEquals(uris.get(1), "spiffe://athenz/domain1/service2");
    }

    @Test
    public void testExtractX509CSRFieldsWithOU() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_ips.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq);

        assertEquals(Crypto.extractX509CSRSubjectOUField(certReq), "Testing Domain");
    }

    @Test
    public void testExtractX509IPAddressesNoAddresses() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq);
        List<String> ips = Crypto.extractX509CSRIPAddresses(certReq);
        assertTrue(ips.isEmpty());
    }

    @Test
    public void testExtractX509IPAddressesMultipleAddresses() throws IOException {

        Path path = Paths.get("src/test/resources/multiple_ips.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq);

        List<String> ips = Crypto.extractX509CSRIPAddresses(certReq);
        assertEquals(2, ips.size());
        assertEquals(ips.get(0), "10.11.12.13");
        assertEquals(ips.get(1), "10.11.12.14");
    }

    @Test
    public void testGenerateRSAPrivateKey() {
        PrivateKey pkey = Crypto.generateRSAPrivateKey(1024);
        assertNotNull(pkey);
    }

    @Test
    public void testExtractX509CertDnsNmaes() throws Exception{
        try (InputStream inStream = new FileInputStream("src/test/resources/x509_altnames_singleip.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            List<String> dnsNames = Crypto.extractX509CertDnsNames(cert);
            assertEquals(dnsNames.get(0), "production.athenz.ostk.athenz.cloud");
            assertEquals(dnsNames.get(1), "1001.instanceid.athenz.ostk.athenz.cloud");
        }
    }

    @Test
    public void testExtractX509CSRSubjectField() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq1 = Crypto.getPKCS10CertRequest(csr);
        assertNotNull(certReq1);
        PKCS10CertificationRequest certReq = Mockito.spy(certReq1);
        assertNotNull(certReq);
        assertEquals(Crypto.extractX509CSRCommonName(certReq), "athenz.syncer");
        assertEquals(Crypto.extractX509CSRSubjectOField(certReq), "My Test Company");
        assertNull(Crypto.extractX509CSRSubjectOUField(certReq));
        assertNull(Crypto.extractX509CSREmail(certReq));
    }

    @Test
    public void testLoadPrivateKeyPem() throws IOException {
        Path path = Paths.get("./src/test/resources/unit_test_private_encrypted.key");
        String keyStr = new String(Files.readAllBytes(path));
        assertThrows(CryptoException.class, () -> Crypto.loadPrivateKey(keyStr, "testPWD"));
    }

    @Test
    public void testExtractX509CSRSubjectFieldNull() {
        PKCS10CertificationRequest certReq = mock(PKCS10CertificationRequest.class);
        when(certReq.getSubject()).thenReturn(null);
        assertNull(Crypto.extractX509CSRSubjectField(certReq, null));

        X500Name x500Name = mock(X500Name.class);
        when(certReq.getSubject()).thenReturn(x500Name);
        RDN[] rdns = new RDN[2];
        when(x500Name.getRDNs(null)).thenReturn(rdns);
        assertThrows(CryptoException.class, () -> Crypto.extractX509CSRSubjectField(certReq, null));
    }

    @Test
    public void testHmacSign() {
        assertNotNull(Crypto.hmac("testMessage", "testSharedSecret"));
    }

    @Test
    public void testYBase64EncodeString() {
        assertNotNull(Crypto.ybase64EncodeString("testString"));
    }

    @Test
    public void testLoadX509Certificates() {

        X509Certificate[] certs = Crypto.loadX509Certificates("src/test/resources/x509_certs_comments.pem");
        assertEquals(certs.length, 3);

        certs = Crypto.loadX509Certificates("src/test/resources/x509_certs_no_comments.pem");
        assertEquals(certs.length, 3);

        // invalid file

        try {
            Crypto.loadX509Certificates("src/test/resources/not_present_certs");
            fail();
        } catch (CryptoException ignored) {
        }

        // invalid cert

        try {
            Crypto.loadX509Certificates("src/test/resources/invalid_x509.cert");
            fail();
        } catch (CryptoException ignored) {
        }

        // no cert

        try {
            Crypto.loadX509Certificates("src/test/resources/ec_public.key");
            fail();
        } catch (CryptoException ignored) {
        }
    }

    @Test
    public void testX509CertificatesToPEM() throws IOException {

        X509Certificate[] certs1 = Crypto.loadX509Certificates("src/test/resources/x509_certs_comments.pem");
        final String certs1PEM = Crypto.x509CertificatesToPEM(certs1);
        assertNotNull(certs1PEM);

        X509Certificate[] certs2 = Crypto.loadX509Certificates("src/test/resources/x509_certs_no_comments.pem");
        final String certs2PEM = Crypto.x509CertificatesToPEM(certs2);
        assertNotNull(certs2PEM);

        assertEquals(certs1PEM, certs2PEM);

        File caFile = new File("src/test/resources/x509_certs_no_comments.pem");
        byte[] data = Files.readAllBytes(Paths.get(caFile.toURI()));
        assertEquals(certs1PEM, new String(data));
    }

    @Test
    public void testSignVerifyByteArrayECKey() {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        assertNotNull(privateKey);

        byte[] signature = Crypto.sign(serviceToken.getBytes(StandardCharsets.UTF_8), privateKey, Crypto.SHA256);
        assertNotNull(signature);

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken.getBytes(StandardCharsets.UTF_8), publicKey, signature, Crypto.SHA256));

        // using rsa key we should get failure

        publicKey = Crypto.loadPublicKey(rsaPublicKey);
        assertNotNull(publicKey);

        assertFalse(Crypto.verify(serviceToken.getBytes(StandardCharsets.UTF_8), publicKey, signature, Crypto.SHA256));
    }

    @Test
    public void testSignVerifyByteArrayRSAKey() {

        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
        assertNotNull(privateKey);

        byte[] signature = Crypto.sign(serviceToken.getBytes(StandardCharsets.UTF_8), privateKey, Crypto.SHA256);
        assertNotNull(signature);

        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicKey);
        assertNotNull(publicKey);

        assertTrue(Crypto.verify(serviceToken.getBytes(StandardCharsets.UTF_8), publicKey, signature, Crypto.SHA256));

        // using ec key we should get failure

        publicKey = Crypto.loadPublicKey(ecPublicKey);
        assertNotNull(publicKey);

        try {
            Crypto.verify(serviceToken.getBytes(StandardCharsets.UTF_8), publicKey, signature, Crypto.SHA256);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("SignatureException"));
        }
    }

}
