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
package com.yahoo.athenz.zpe;

import com.google.common.primitives.Bytes;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zts.DomainSignedPolicyData;
import com.yahoo.athenz.zts.JWSPolicyData;
import com.yahoo.athenz.zts.SignedPolicyData;
import com.yahoo.rdl.JSON;
import org.apache.commons.io.FileUtils;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.zpe.match.ZpeMatch;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchAll;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchEqual;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchRegex;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchStartsWith;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.*;

public class TestZpeUpdPolLoader {

    static String TEST_POL_DIR  = "./src/test/resources/upd_pol_dir/";
    static String TEST_POL_FILE = "angler.pol";
    static String TEST_ORIG_POL_FILE = "./src/test/resources/angler.pol";
    static String TEST_SIGNED_POL_GOOD_FILE = "./src/test/resources/pol_dir/angler.pol";
    static String TEST_JWS_POL_GOOD_FILE = "./src/test/resources/pol_dir/angler.jws";

    private static final byte[] PERIOD = { 46 };

    @BeforeClass
    public void init() {
        AuthZpeClient.init();
        try {
            Thread.sleep(5000);
        } catch (InterruptedException ignored) {
        }
    }

    private void setupJWSPolicyFile(SignedPolicyData signedPolicyData, PrivateKey privateKey, final String keyId,
                                    final String algorithm, boolean p1363Format, final String fileName) throws IOException {

        signedPolicyData.setZmsSignature("");
        signedPolicyData.setZmsKeyId("");
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final byte[] jsonPolicyData = JSON.bytes(signedPolicyData);
        final byte[] encodedPolicyData = encoder.encode(jsonPolicyData);
        final String protectedHeader = "{\"kid\":\"" + keyId + "\",\"alg\":\"" + algorithm + "\"}";
        final byte[] encodedHeader = encoder.encode(protectedHeader.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Crypto.sign(Bytes.concat(encodedHeader, PERIOD, encodedPolicyData),
                privateKey, Crypto.SHA256);
        if (p1363Format) {
            signatureBytes = Crypto.convertSignatureFromDERToP1363Format(signatureBytes, Crypto.SHA256);
        }
        final Map<String, String> headerMap = new HashMap<>();
        headerMap.put("kid", keyId);
        JWSPolicyData jwsPolicyData = new JWSPolicyData().setHeader(headerMap)
                .setPayload(new String(encodedPolicyData))
                .setProtectedHeader(new String(encodedHeader))
                .setSignature(encoder.encodeToString(signatureBytes));
        File file = new File("./src/test/resources/pol_dir/angler.jws.gen");
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(jwsPolicyData));
        File renamedFile = new File(fileName);
        file.renameTo(renamedFile);
    }

    private void setupPolicyFiles(final String ztsPrivateKeyFile, final String zmsPrivateKeyFile,
                                  final String keyVersion, final String algorithm, boolean p1363Format) throws IOException {

        Path path = Paths.get(ztsPrivateKeyFile);
        PrivateKey ztsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        path = Paths.get(zmsPrivateKeyFile);
        PrivateKey zmsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        // generate the signed policy file data

        path = Paths.get(TEST_ORIG_POL_FILE);
        DomainSignedPolicyData domainSignedPolicyData = JSON.fromBytes(Files.readAllBytes(path),
                DomainSignedPolicyData.class);
        SignedPolicyData signedPolicyData = domainSignedPolicyData.getSignedPolicyData();
        String signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData.getPolicyData()), zmsPrivateKeyK0);
        signedPolicyData.setZmsSignature(signature).setZmsKeyId(keyVersion);
        signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData), ztsPrivateKeyK0);
        domainSignedPolicyData.setSignature(signature).setKeyId(keyVersion);
        File file = new File("./src/test/resources/pol_dir/angler.gen");
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(domainSignedPolicyData));
        File renamedFile = new File(TEST_SIGNED_POL_GOOD_FILE);
        file.renameTo(renamedFile);

        // generate the jws policy data

        setupJWSPolicyFile(signedPolicyData, ztsPrivateKeyK0, keyVersion, algorithm,
                p1363Format, TEST_JWS_POL_GOOD_FILE);
    }

    private void setupInvalidJsonPolicyDataInvalidVersion(final String ztsPrivateKeyFile, final String ztsKeyVersion,
            final String zmsPrivateKeyFile, final String zmsKeyVersion) throws IOException {

        Path path = Paths.get(ztsPrivateKeyFile);
        PrivateKey ztsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        path = Paths.get(zmsPrivateKeyFile);
        PrivateKey zmsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        // generate the signed policy file data

        path = Paths.get(TEST_ORIG_POL_FILE);
        DomainSignedPolicyData domainSignedPolicyData = JSON.fromBytes(Files.readAllBytes(path),
                DomainSignedPolicyData.class);
        SignedPolicyData signedPolicyData = domainSignedPolicyData.getSignedPolicyData();
        String signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData.getPolicyData()), zmsPrivateKeyK0);
        signedPolicyData.setZmsSignature(signature).setZmsKeyId(zmsKeyVersion);
        signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData), ztsPrivateKeyK0);
        domainSignedPolicyData.setSignature(signature).setKeyId(ztsKeyVersion);
        File file = new File("./src/test/resources/pol_dir/angler.gen");
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(domainSignedPolicyData));
        File renamedFile = new File(TEST_SIGNED_POL_GOOD_FILE);
        file.renameTo(renamedFile);
    }

    private void setupInvalidJWSPolicyDataInvalidVersion(final String privateKeyPath, final String keyVersion,
            final String algorithm, boolean p1363Format) throws IOException {

        Path path = Paths.get(privateKeyPath);
        PrivateKey ztsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        // generate the signed policy file data

        path = Paths.get(TEST_ORIG_POL_FILE);
        DomainSignedPolicyData domainSignedPolicyData = JSON.fromBytes(Files.readAllBytes(path),
                DomainSignedPolicyData.class);
        SignedPolicyData signedPolicyData = domainSignedPolicyData.getSignedPolicyData();

        // generate the jws policy data

        setupJWSPolicyFile(signedPolicyData, ztsPrivateKeyK0, keyVersion, algorithm, p1363Format, TEST_JWS_POL_GOOD_FILE);
    }

    private void setupInvalidJWSPolicyDataInvalidData() throws IOException {

        Path path = Paths.get("./src/test/resources/unit_test_zts_private_k0.pem");
        PrivateKey ztsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        // generate the signed policy file data

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final byte[] jsonPolicyData = JSON.bytes("policy-data");
        final byte[] encodedPolicyData = encoder.encode(jsonPolicyData);
        final String protectedHeader = "{\"kid\":\"0\",\"alg\":\"RS256\"}";
        final byte[] encodedHeader = encoder.encode(protectedHeader.getBytes(StandardCharsets.UTF_8));
        final byte[] signatureBytes = encoder.encode(Crypto.sign(
                Bytes.concat(encodedHeader, PERIOD, encodedPolicyData), ztsPrivateKeyK0, Crypto.SHA256));
        final Map<String, String> headerMap = new HashMap<>();
        headerMap.put("kid", "0");
        JWSPolicyData jwsPolicyData = new JWSPolicyData().setHeader(headerMap)
                .setPayload(new String(encodedPolicyData))
                .setProtectedHeader(new String(encodedHeader))
                .setSignature(new String(signatureBytes));
        File file = new File("./src/test/resources/pol_dir/angler.jws.gen");
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(jwsPolicyData));
        File renamedFile = new File(TEST_JWS_POL_GOOD_FILE);
        file.renameTo(renamedFile);
    }

    private void setupInvalidJWSPolicyDataInvalidSignature(final String algorithm) throws IOException {

        // generate the signed policy file data

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final byte[] jsonPolicyData = JSON.bytes("policy-data");
        final byte[] encodedPolicyData = encoder.encode(jsonPolicyData);
        final String protectedHeader = "{\"kid\":\"0\",\"alg\":\"" + algorithm + "\"}";
        final byte[] encodedHeader = encoder.encode(protectedHeader.getBytes(StandardCharsets.UTF_8));
        final Map<String, String> headerMap = new HashMap<>();
        headerMap.put("kid", "0");
        JWSPolicyData jwsPolicyData = new JWSPolicyData().setHeader(headerMap)
                .setPayload(new String(encodedPolicyData))
                .setProtectedHeader(new String(encodedHeader))
                .setSignature("invalid-signature");
        File file = new File("./src/test/resources/pol_dir/angler.jws.gen");
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(jwsPolicyData));
        File renamedFile = new File(TEST_JWS_POL_GOOD_FILE);
        file.renameTo(renamedFile);
    }

    @Test
    public void testGetMatchObject() {
        
        try (ZpeUpdPolLoader loader = new ZpeUpdPolLoader(null)) {
            
            ZpeMatch matchObject = loader.getMatchObject("*");
            assertTrue(matchObject instanceof ZpeMatchAll);
            
            matchObject = loader.getMatchObject("**");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("?*");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("?");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("test?again*");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("*test");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("test");
            assertTrue(matchObject instanceof ZpeMatchEqual);
            
            matchObject = loader.getMatchObject("(test|again)");
            assertTrue(matchObject instanceof ZpeMatchEqual);
            
            matchObject = loader.getMatchObject("test*");
            assertTrue(matchObject instanceof ZpeMatchStartsWith);
        }
    }
    @Test
    public void testLoadDBCasesRSAKey() throws Exception {
        testLoadDBCases("./src/test/resources/unit_test_zts_private_k0.pem",
                "./src/test/resources/unit_test_zms_private_k0.pem", "0", "RS256", false);
    }

    @Test
    public void testLoadDBCasesECKey() throws Exception {
        testLoadDBCases("./src/test/resources/unit_test_zts_private_ec_k0.pem",
                "./src/test/resources/unit_test_zms_private_ec_k0.pem", "2", "ES256", false);
        testLoadDBCases("./src/test/resources/unit_test_zts_private_ec_k0.pem",
                "./src/test/resources/unit_test_zms_private_ec_k0.pem", "2", "ES256", true);
    }

    void testLoadDBCases(final String ztsPrivateKeyFile, final String zmsPrivateKeyFile,
                         final String keyVersion, final String algorithm, boolean p1363Format) throws Exception {

        // setup our policy files

        setupPolicyFiles(ztsPrivateKeyFile, zmsPrivateKeyFile, keyVersion, algorithm, p1363Format);

        // save the current value for the check policy

        boolean savedValue = ZpeUpdPolLoader.checkPolicyZMSSignature;

        // verify both test cases where the zms check signature
        // is set to true and false with signed domain policy file

        testLoadDb(TEST_SIGNED_POL_GOOD_FILE, true);
        testLoadDb(TEST_SIGNED_POL_GOOD_FILE, false);

        // verify jws domain data, zms check signature does not
        // apply to the jws case, so we'll just pass false

        testLoadDb(TEST_JWS_POL_GOOD_FILE, false);

        // reset the config value

        ZpeUpdPolLoader.checkPolicyZMSSignature = savedValue;
    }

    void testLoadDb(final String goodPolicyFile, boolean checkZMSSignature) throws Exception {

        System.out.println("TestZpeUpdPolLoader: testLoadDb: dir=" + TEST_POL_DIR);

        java.nio.file.Path dirPath  = java.nio.file.Paths.get(TEST_POL_DIR);
        try {
            FileUtils.deleteDirectory(dirPath.toFile());
        } catch (Exception ignored) {
        }
        try {
            java.nio.file.Files.createDirectory(dirPath);
        } catch (java.nio.file.FileAlreadyExistsException ignored) {
        }

        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        assertEquals(loader.getDomainCount(), 0);

        ZpeUpdPolLoader.checkPolicyZMSSignature = checkZMSSignature;

        java.nio.file.Path badFile = java.nio.file.Paths.get(TEST_POL_DIR, TEST_POL_FILE);
        java.nio.file.Files.deleteIfExists(badFile);
        java.io.File polFile = new java.io.File(TEST_POL_DIR, TEST_POL_FILE);
        //noinspection ResultOfMethodCallIgnored
        polFile.createNewFile();
        java.io.File [] files = { polFile };
        loader.loadDb(files);
        assertEquals(loader.getDomainCount(), 0);

        long lastModMilliSeconds = polFile.lastModified();
        java.util.Map<String, ZpeUpdPolLoader.ZpeFileStatus> fsmap = loader.getFileStatusMap();
        ZpeUpdPolLoader.ZpeFileStatus fstat = fsmap.get(polFile.getName());
        assertFalse(fstat.validPolFile);

        // move good policy file over the bad one
        java.nio.file.Path goodFile = java.nio.file.Paths.get(goodPolicyFile);
        java.nio.file.Files.copy(goodFile, badFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        loader.loadDb(files);
        long lastModMilliSeconds2 = polFile.lastModified();
        fsmap = loader.getFileStatusMap();
        fstat = fsmap.get(polFile.getName());
        assertTrue(fstat.validPolFile);
        assertEquals(loader.getDomainCount(), 1);
        loader.close();

        // mock a deleted file scenario

        File polMockFile = Mockito.mock(File.class);
        Mockito.when(polMockFile.getName()).thenReturn(polFile.getName());
        Mockito.when(polMockFile.lastModified()).thenReturn(System.currentTimeMillis());
        Mockito.when(polMockFile.exists()).thenReturn(false);

        java.io.File [] mockFiles = { polMockFile };
        loader.loadDb(mockFiles);
        assertNull(fsmap.get(polFile.getName()));

        System.out.println("TestZpeUpdPolLoader: testLoadDb: timestamp1=" + lastModMilliSeconds
                + " timestamp2=" + lastModMilliSeconds2);
    }

    @Test
    public void testLoadDBJWSInvalidRSAKeyVersion() throws IOException {
        testLoadDBJWSInvalidKeyVersion("./src/test/resources/unit_test_zts_private_k0.pem", "1001", "RS256", false);
    }

    @Test
    public void testLoadDBJWSInvalidECKeyVersion() throws IOException {
        testLoadDBJWSInvalidKeyVersion("./src/test/resources/unit_test_zts_private_ec_k0.pem", "1001", "ES256", true);
        testLoadDBJWSInvalidKeyVersion("./src/test/resources/unit_test_zts_private_ec_k0.pem", "1001", "ES256", false);
    }

    public void testLoadDBJWSInvalidKeyVersion(final String privateKeyPath, final String keyVersion,
                                               final String algorithm, boolean p1363Format) throws IOException {

        setupInvalidJWSPolicyDataInvalidVersion(privateKeyPath, keyVersion, algorithm, p1363Format);

        java.nio.file.Path polFile = java.nio.file.Paths.get(TEST_POL_DIR, TEST_POL_FILE);
        java.nio.file.Files.deleteIfExists(polFile);

        java.nio.file.Path invalidKeyVersionFile = java.nio.file.Paths.get(TEST_JWS_POL_GOOD_FILE);
        java.nio.file.Files.copy(invalidKeyVersionFile, polFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        java.io.File [] files = { polFile.toFile() };

        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        loader.loadDb(files);

        java.util.Map<String, ZpeUpdPolLoader.ZpeFileStatus> fsmap = loader.getFileStatusMap();
        ZpeUpdPolLoader.ZpeFileStatus fstat = fsmap.get(polFile.toFile().getName());
        assertFalse(fstat.validPolFile);
    }

    @Test
    public void testLoadDBJsonInvalidRSAKeyVersion() throws IOException {
        testLoadDBJsonInvalidKeyVersion("./src/test/resources/unit_test_zts_private_k0.pem", "1001",
                "./src/test/resources/unit_test_zms_private_k0.pem", "0");
        testLoadDBJsonInvalidKeyVersion("./src/test/resources/unit_test_zts_private_k0.pem", "0",
                "./src/test/resources/unit_test_zms_private_k0.pem", "1001");
    }

    @Test
    public void testLoadDBJsonInvalidECKeyVersion() throws IOException {
        testLoadDBJsonInvalidKeyVersion("./src/test/resources/unit_test_zts_private_ec_k0.pem", "1001",
                "./src/test/resources/unit_test_zms_private_ec_k0.pem", "0");
        testLoadDBJsonInvalidKeyVersion("./src/test/resources/unit_test_zts_private_ec_k0.pem", "0",
                "./src/test/resources/unit_test_zms_private_ec_k0.pem", "1001");
    }

    public void testLoadDBJsonInvalidKeyVersion(final String ztsPrivateKeyFile, final String ztsKeyVersion,
            final String zmsPrivateKeyFile, final String zmsKeyVersion) throws IOException {

        setupInvalidJsonPolicyDataInvalidVersion(ztsPrivateKeyFile, ztsKeyVersion, zmsPrivateKeyFile, zmsKeyVersion);

        java.nio.file.Path polFile = java.nio.file.Paths.get(TEST_POL_DIR, TEST_POL_FILE);
        java.nio.file.Files.deleteIfExists(polFile);

        java.nio.file.Path invalidKeyVersionFile = java.nio.file.Paths.get(TEST_SIGNED_POL_GOOD_FILE);
        java.nio.file.Files.copy(invalidKeyVersionFile, polFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        java.io.File [] files = { polFile.toFile() };

        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        loader.loadDb(files);

        java.util.Map<String, ZpeUpdPolLoader.ZpeFileStatus> fsmap = loader.getFileStatusMap();
        ZpeUpdPolLoader.ZpeFileStatus fstat = fsmap.get(polFile.toFile().getName());
        assertFalse(fstat.validPolFile);
    }

    @Test
    public void testLoadDBJWSInvalidData() throws IOException {

        setupInvalidJWSPolicyDataInvalidData();

        java.nio.file.Path polFile = java.nio.file.Paths.get(TEST_POL_DIR, TEST_POL_FILE);
        java.nio.file.Files.deleteIfExists(polFile);

        java.nio.file.Path invalidKeyVersionFile = java.nio.file.Paths.get(TEST_JWS_POL_GOOD_FILE);
        java.nio.file.Files.copy(invalidKeyVersionFile, polFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        java.io.File [] files = { polFile.toFile() };

        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        loader.loadDb(files);

        java.util.Map<String, ZpeUpdPolLoader.ZpeFileStatus> fsmap = loader.getFileStatusMap();
        ZpeUpdPolLoader.ZpeFileStatus fstat = fsmap.get(polFile.toFile().getName());
        assertFalse(fstat.validPolFile);
    }

    @Test
    public void testLoadDBJWSInvalidRSASignature() throws IOException {
        testLoadDBJWSInvalidSignature("RS256");
    }

    @Test
    public void testLoadDBJWSInvalidECSignature() throws IOException {
        testLoadDBJWSInvalidSignature("ES256");
    }

    void testLoadDBJWSInvalidSignature(final String algorithm) throws IOException {

        setupInvalidJWSPolicyDataInvalidSignature(algorithm);

        java.nio.file.Path polFile = java.nio.file.Paths.get(TEST_POL_DIR, TEST_POL_FILE);
        java.nio.file.Files.deleteIfExists(polFile);

        java.nio.file.Path invalidSignatureFile = java.nio.file.Paths.get(TEST_JWS_POL_GOOD_FILE);
        java.nio.file.Files.copy(invalidSignatureFile, polFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        java.io.File [] files = { polFile.toFile() };

        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        loader.loadDb(files);

        java.util.Map<String, ZpeUpdPolLoader.ZpeFileStatus> fsmap = loader.getFileStatusMap();
        ZpeUpdPolLoader.ZpeFileStatus fstat = fsmap.get(polFile.toFile().getName());
        assertFalse(fstat.validPolFile);
    }

    @Test
    public void testIsESAlgorithm() {

        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        boolean skipPolicyDirCheck = ZpeUpdPolLoader.skipPolicyDirCheck;
        ZpeUpdPolLoader.skipPolicyDirCheck = true;
        loader.loadDb();

        assertTrue(loader.isESAlgorithm("ES256"));
        assertTrue(loader.isESAlgorithm("ES384"));
        assertTrue(loader.isESAlgorithm("ES512"));
        assertFalse(loader.isESAlgorithm("RS256"));
        assertFalse(loader.isESAlgorithm(""));
        assertFalse(loader.isESAlgorithm(null));

        loader.close();
        ZpeUpdPolLoader.skipPolicyDirCheck = skipPolicyDirCheck;
    }

    @Test
    public void testLoadDBNull() {
        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        loader.loadDb(null);
        
        loader.close();
    }
    
    @Test
    public void testLoadDBNotExist() {
        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        File fileMock = Mockito.mock(File.class);
        java.io.File [] files = { fileMock };
        
        // delete file
        Mockito.when(fileMock.exists()).thenReturn(false);
        
        try {
            loader.loadDb(files);
        } catch(Exception ex) {
            loader.close();
        }
        
        loader.close();
    }
    
    @Test(expectedExceptions = {java.lang.Exception.class})
    public void testStartNullDir() throws Exception {
        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(null);
        loader.start();
        loader.close();
    }
    
    @Test
    public void testLoadFileStatusNull() {
        ZpeUpdPolLoader loader = new ZpeUpdPolLoader("./noexist");
        ZpeUpdMonitor monitor = new ZpeUpdMonitor(loader);
        File[] files = monitor.loadFileStatus();
        assertNull(files);
        loader.close();
    }
    
    @Test
    public void testUpdLoaderInvalid() {
        ZpeUpdPolLoader loaderMock = Mockito.mock(ZpeUpdPolLoader.class);
        Mockito.when(loaderMock.getDirName()).thenReturn(null);
        ZpeUpdMonitor monitor = new ZpeUpdMonitor(loaderMock);
                
        monitor.run();
        monitor.cancel();
        monitor.run();
    }

    @Test
    public void testGetDERSignatureInvalidHeader() {
        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        assertNull(loader.getDERSignature("invalid-header", "signature"));
        loader.close();
    }
}
