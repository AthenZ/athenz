/**
 * Copyright 2016 Yahoo Inc.
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.testng.Assert.*;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.rdl.Array;
import com.yahoo.rdl.Struct;

public class CryptoTest {

    final File rsaPrivateKey = new File("./src/test/resources/rsa_private.key");
    final File rsaPublicKey = new File("./src/test/resources/rsa_public.key");
    final File rsaPublicX590Cert = new File("./src/test/resources/rsa_public_x509.cert");
    final File rsaPublicInvalidKey = new File("./src/test/resources/rsa_public_invalid.key");

    final File ecPrivateKey = new File("./src/test/resources/ec_private.key");
    final File ecPublicKey = new File("./src/test/resources/ec_public.key");
    final File ecPublicX509Cert = new File("./src/test/resources/ec_public_x509.cert");
    final File ecPublicInvalidKey = new File("./src/test/resources/ec_public_invalid.key");
    final File ecPrivateParamPrime256v1Key = new File("./src/test/resources/ec_private_param_prime256v1.key");
    final File ecPublicParamPrime256v1Key = new File("./src/test/resources/ec_public_param_prime256v1.key");
    final File ecPrivateParamSecp384r1Key = new File("./src/test/resources/ec_private_param_secp384r1.key");
    final File ecPublicParamSecp384r1Key = new File("./src/test/resources/ec_public_param_secp384r1.key");
    final File ecPrivateParamsKey = new File("./src/test/resources/ec_private_params.key");
    final File ecPublicParamsKey = new File("./src/test/resources/ec_public_params.key");
    final File argFile = new File("./src/test/resources/arg_file");
    
    final File privateEncryptedKey = new File("./src/test/resources/private_encrypted.key");
    final String encryptedKeyPassword = "athenz";
    
    final String serviceToken = "v=S1;d=coretech;n=storage;t=1234567000;e=123456800;h=localhost";
    final String serviceRSASignature = "VsUlcNozK4as1FjPbowEE_DFDD8KWpQzphadfbt_TsMoCTLFpYrMzKTu_nHKemJmEi0bbPwj7hRLrIKEFu2VjQ--";
    final String serviceECSignature = "MEQCIEBnyNCxp5GSeua3K9OenyetmVs4F68VB.Md1JRaU4OXAiBWAxlJLe74ZV4QDqapsD4FJm.MA3mv0FMcq.LEevJa0g--";
    
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
    public void testSignVerifyECKey_Invalid() {
        
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicInvalidKey);
        assertNotNull(publicKey);
        
        assertFalse(Crypto.verify(serviceToken, publicKey, serviceECSignature));
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
    public void testSignVerifyECParamSecp384r1Key() {
        
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateParamSecp384r1Key);
        assertNotNull(privateKey);
        
        String signature = Crypto.sign(serviceToken, privateKey);
        
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicParamSecp384r1Key);
        assertNotNull(publicKey);
        
        assertTrue(Crypto.verify(serviceToken, publicKey, signature));
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
            assertEquals(Crypto.getSignatureAlgorithm("RSA", "SHA555"), "SHA555withRSA");
            assertEquals(Crypto.getSignatureAlgorithm("ECDSA", "SHA999"), "SHA999withECDSA");
            fail();
        } catch (NoSuchAlgorithmException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testGetPKCS10CertRequest() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid.csr");
        String certStr = new String(Files.readAllBytes(path));
        
        PKCS10CertificationRequest req = Crypto.getPKCS10CertRequest(certStr);
        assertNotNull(req);
        assertEquals(req.getSubject().toString(), "C=US,ST=CA,L=Sunnyvale,O=My Test Company,CN=athenz.syncer");
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
    public void testLoadReaderPrivateKey() throws IOException{
        try (java.io.FileReader fileReader = new java.io.FileReader(rsaPrivateKey)) {
            PrivateKey privateKey = Crypto.loadPrivateKey(fileReader);
            assertNotNull(privateKey);
        } catch (IOException e) {
            fail();
        }
    }
    
    @Test
    public void testEnDecodedFile(){
        String encoded = Crypto.encodedFile(argFile);
        assertNotNull(encoded);
        
        String decoded = Crypto.ybase64DecodeString(encoded);
        assertEquals(decoded, "check\n");
    }

    @Test
    public void testEncodedFileStream() throws Exception {
        try (FileInputStream in = new FileInputStream(argFile)) {
            String encoded = Crypto.encodedFile(in);
            assertNotNull(encoded);
            
            String decoded = Crypto.ybase64DecodeString(encoded);
            assertEquals(decoded, "check");
        } catch (Exception e){
            fail();
        }
    }

    @Test
    public void testSHA256() {
        byte [] checkByte = Crypto.sha256("check");
        assertNotNull(checkByte);
    }

    @Test
    public void testHmac() throws Exception {
        Struct argData =  new Struct(3);
        argData.append("00", 0);
        argData.append("01", 1);
        argData.append("02", 2);
        
        String hmac = Crypto.hmac(argData, "check");
        
        assertNotNull(hmac);

        boolean checkStringNum = false;
        if(hmac.length() == 44){
            checkStringNum = true;
        }
        assertTrue(checkStringNum);
    }

    @Test
    public void testSign(){
        Struct argData = new Struct(3);
        argData.append("00", 0);
        argData.append("01", 1);
        argData.append("02", 2);

        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
        String checkSign = Crypto.sign(argData,privateKey);
        
        assertNotNull(checkSign);
        assertEquals(checkSign.length(),88);
    }

    @Test
    public void testCanonical() throws NoSuchMethodException, SecurityException, IllegalAccessException,
            IllegalArgumentException, InvocationTargetException {
        Class<Crypto> c = Crypto.class;
        Crypto check = new Crypto();

        Method m = c.getDeclaredMethod("canonical", Object.class );
        m.setAccessible(true);
        Array p = null; 
        Object a = (Object) m.invoke(check, p);
        assertNull(a);
        Array az = new Array();
        az.add("aa");
        a = (Object) m.invoke(check, az);
        assertNotNull(a);
    }
    
    @DataProvider
    public Object[][] x500Principal() {
        return new Object[][] {
                {"CN=athenzcompany.com,O=foo", false},
                {"CDDN=athenzcompany.com", true},
            };
    }

    @Test(dataProvider = "x500Principal")
    public void testX509CSRrequest(String x500Principal, boolean badRequest) throws Exception{
        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicKey);
        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
        String certRequest = null;
        GeneralName otherName1 = new GeneralName(GeneralName.otherName, new DERIA5String("role1"));
        GeneralName otherName2 = new GeneralName(GeneralName.otherName, new DERIA5String("role2"));
        GeneralName[] sanArray = new GeneralName[]{otherName1, otherName2};
        try {
            certRequest = Crypto.generateX509CSR(privateKey, publicKey, x500Principal, sanArray);
        } catch (Exception e){
            if (!badRequest){
                fail("Should not have failed to create csr");
            }
        }
        if (!badRequest){
            //Now validate the csr
            Crypto.getPKCS10CertRequest(certRequest);
        }
    }
    
    @Test(dataProvider = "x500Principal")
    public void testX509CSRrequestWithPrivateKeyOnly(String x500Principal, boolean badRequest) throws Exception {
        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);
        String certRequest = null;
        GeneralName otherName1 = new GeneralName(GeneralName.otherName, new DERIA5String("role1"));
        GeneralName otherName2 = new GeneralName(GeneralName.otherName, new DERIA5String("role2"));
        GeneralName[] sanArray = new GeneralName[]{otherName1, otherName2};
        try {
            certRequest = Crypto.generateX509CSR(privateKey, x500Principal, sanArray);
        } catch (Exception e){
            if (!badRequest){
                fail("Should not have failed to create csr");
            }
        }
        if (!badRequest){
            //Now validate the csr
            Crypto.getPKCS10CertRequest(certRequest);
        }
    }
    
    @Test
    public void testExtractX509CertCommonName() throws Exception, IOException {
        
        try (InputStream inStream = new FileInputStream("src/test/resources/valid_cn_x509.cert")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            
            String cn = Crypto.extractX509CertCommonName(cert);
            assertEquals("athenz.syncer", cn);
        }
    }
    
    @Test
    public void testExtractCsrFieldsNoRfc822() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);

        assertEquals(Crypto.extractX509CSRCommonName(certReq), "athenz.syncer");
        assertNull(Crypto.extractX509CSREmail(certReq));
    }
    
    @Test
    public void testExtractCsrFieldsWithRfc822() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);

        assertEquals(Crypto.extractX509CSRCommonName(certReq), "sports:role.readers");
        assertEquals(Crypto.extractX509CSREmail(certReq), "sports.scores@aws.yahoo.cloud");
    }
}
