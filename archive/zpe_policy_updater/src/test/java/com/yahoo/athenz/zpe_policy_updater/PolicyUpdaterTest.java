/**
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
package com.yahoo.athenz.zpe_policy_updater;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.DomainSignedPolicyData;
import com.yahoo.athenz.zts.ZTSClient;
import com.yahoo.rdl.JSON;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.AfterClass;
import org.mockito.Mockito;

public class PolicyUpdaterTest {

    private final String pathToAthenzConfigFile = "./src/test/resources/athenz.conf";
    private final String pathToZPUConfigFile = "./src/test/resources/zpu.conf";
    private final String pathToZPUTestConfigFile = "./src/test/resources/zpu_test.conf";
    private final String pathToZPUEmptyConfigFile = "./src/test/resources/zpu_empty.conf";
    private final String EXPECTED_ROOT_DIR = "/home/athenz";
    private final String TEST_ROOT_DIR = "/home/myroot";
    
    private final String EXPECTED_ZTS_PUBLIC_KEY_K0 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TDNza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbXZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private final String EXPECTED_ZTS_PUBLIC_KEY_K1 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBUFpyWkMxelBhNXBQZloxaXFtcjdnWW9YaHVIbGlSUApVbnlLelliWWhRZXpUSlJlSDBsdWhvVVdQdTZxeWRHSm54RVUyTldNQ1hZLzhuL1VGSUZvakYwQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";

    private final String EXPECTED_POLICY_FILE_TMP_DIR_SUFFIX = "/tmp/zpe";
    private final String TEST_POLICY_DIR = "/pol_dir";
    private final String TEST_POLICY_TEMP_DIR = "/tmp";
    
    private final int TEST_STARTUP_DELAY = 1339; 

    private PolicyUpdaterConfiguration pupConfig = null;

    @BeforeClass
    public void beforeClass() throws Exception {
        System.setProperty("athenz.zpe_policy_updater.dir", "src/test/resources");
        System.setProperty("athenz.zpe_policy_updater.test_root_path", "src/test/resources");
        System.setProperty("athenz.zpe_policy_updater.metric_factory_class", "com.yahoo.athenz.common.metrics.impl.NoOpMetricFactory");

        pupConfig = new PolicyUpdaterConfiguration();
        pupConfig.init(pathToAthenzConfigFile, pathToZPUConfigFile);
        pupConfig.setPolicyFileTmpDir(pupConfig.getRootDir() + TEST_POLICY_TEMP_DIR);
        pupConfig.setPolicyFileDir(pupConfig.getRootDir() + TEST_POLICY_DIR);
    }

    @AfterClass
    public void afterClass() {
    }
    
    // main has exit, so temporary exclude..
    @Test(enabled=false, expectedExceptions = {Exception.class})
    public void TestMainConfigInitializeFail() throws IOException, InterruptedException {
        PolicyUpdater.main(null);
        Assert.fail();
    }
    
    @Test
    public void TestPolicyUpdaterConfiguration() throws Exception {
        
        String rootPath = System.clearProperty(PolicyUpdaterConfiguration.ZPU_PROP_TEST_ROOT_PATH);
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);
        Assert.assertEquals(configuration.getRootDir(), EXPECTED_ROOT_DIR);
        Assert.assertEquals(configuration.getPolicyFileDir(), "src/test/resources"); //set in pom.xml
        Assert.assertEquals(configuration.getPolicyFileTmpDir(), EXPECTED_ROOT_DIR + EXPECTED_POLICY_FILE_TMP_DIR_SUFFIX);
        Assert.assertEquals(configuration.getZtsPublicKey(null, "0"), Crypto.loadPublicKey(Crypto.ybase64DecodeString(EXPECTED_ZTS_PUBLIC_KEY_K0)));
        Assert.assertEquals(configuration.getZtsPublicKey(null, "1"), Crypto.loadPublicKey(Crypto.ybase64DecodeString(EXPECTED_ZTS_PUBLIC_KEY_K1)));
        
        List<String> domainList = configuration.getDomainList();
        Assert.assertNotNull(domainList);
        Assert.assertEquals(domainList.size(), 2);
        Assert.assertTrue(domainList.contains("athenz.ci"));
        Assert.assertTrue(domainList.contains("coretech.hosted"));
        
        // Set the ROOT env variable to /home/myroot
        Map<String, String> newenv = new HashMap<String, String>();
        newenv.put("ROOT", TEST_ROOT_DIR);
        setEnvironmentVar(newenv);
        configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);
        Assert.assertEquals(configuration.getRootDir(), TEST_ROOT_DIR);
        Assert.assertEquals(configuration.getPolicyFileDir(), "src/test/resources");
        Assert.assertEquals(configuration.getPolicyFileTmpDir(), TEST_ROOT_DIR + EXPECTED_POLICY_FILE_TMP_DIR_SUFFIX);

        // use the test root
        //
        System.setProperty(PolicyUpdaterConfiguration.ZPU_PROP_TEST_ROOT_PATH, rootPath);

        configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);
        Assert.assertEquals(configuration.getRootDir(), "src/test/resources");
        Assert.assertEquals(configuration.getPolicyFileDir(), "src/test/resources"); //set in pom.xml
        Assert.assertEquals(configuration.getPolicyFileTmpDir(), "src/test/resources" + EXPECTED_POLICY_FILE_TMP_DIR_SUFFIX);
        Assert.assertEquals(configuration.getZpuDirOwner(), "root");
    }
    
    @Test
    public void TestVerifySignature() throws Exception {
        
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);
        
        SignPoliciesUtility.signPolicies("./src/test/resources/unit_test_zts_private_k0.pem",
                "./src/test/resources/unit_test_zms_private_k0.pem", "./src/test/resources/sys.auth.pol",
                "./src/test/resources/sys.auth.new.pol");
        
        Path path = Paths.get("./src/test/resources/sys.auth.new.pol");
        DomainSignedPolicyData domainPolicySignedData = JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        Assert.assertTrue(PolicyUpdater.validateSignedPolicies(null, configuration, domainPolicySignedData, "sys.auth.new"));
        
        // negative test with tampered publickey - zts pubkey failure
        PolicyUpdaterConfiguration confMock = Mockito.mock(PolicyUpdaterConfiguration.class);
        Mockito.when(confMock.getZtsPublicKey(Mockito.any(ZTSClient.class), Mockito.<String>any())).thenReturn(null);
        Assert.assertFalse(PolicyUpdater.validateSignedPolicies(null, confMock, domainPolicySignedData, "sys.auth.new"));
        
        // negative test with tampered publickey - zms pubkey failure
        confMock = Mockito.mock(PolicyUpdaterConfiguration.class);
        PublicKey pKey = Crypto.loadPublicKey(Crypto.ybase64DecodeString("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0"
                + "RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTHpmU09UUUpmRW0xZW00TD"
                + "Nza3lOVlEvYngwTU9UcQphK1J3T0gzWmNNS3lvR3hPSm85QXllUmE2RlhNbX"
                + "ZKSkdZczVQMzRZc3pGcG5qMnVBYmkyNG5FQ0F3RUFBUT09Ci0tLS0tRU5EIF"
                + "BVQkxJQyBLRVktLS0tLQo-"));
        Mockito.when(confMock.getZtsPublicKey(Mockito.any(ZTSClient.class), Mockito.<String>any())).thenReturn(pKey);
        Mockito.when(confMock.getZmsPublicKey(Mockito.any(ZTSClient.class), Mockito.<String>any())).thenReturn(null);
        Assert.assertFalse(PolicyUpdater.validateSignedPolicies(null, confMock, domainPolicySignedData, "sys.auth.new"));
        
        // negative test with tampered expiration - zts signature failure
        path = Paths.get("./src/test/resources/sys.auth.pol.tampered.zts");
        domainPolicySignedData = JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        Assert.assertFalse(PolicyUpdater.validateSignedPolicies(null, configuration, domainPolicySignedData, "sys.auth.new"));
        
        // negative test with tampered actions - zms signature failure
        path = Paths.get("./src/test/resources/sys.auth.pol.tampered.zms");
        domainPolicySignedData = JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        Assert.assertFalse(PolicyUpdater.validateSignedPolicies(null, configuration, domainPolicySignedData, "sys.auth.new"));
        
        // Test error handling for illegal arguments
        boolean exceptionCaught = false;
        try {
            PolicyUpdater.validateSignedPolicies(null, configuration, null, "sys.auth.new");
        } catch (IllegalArgumentException ex) {
            exceptionCaught = true;
        }
        Assert.assertTrue(exceptionCaught);
        
        exceptionCaught = false;
        try {
            PolicyUpdater.validateSignedPolicies(null, configuration, domainPolicySignedData, null);
        } catch (IllegalArgumentException ex) {
            exceptionCaught = true;
        }
        Assert.assertTrue(exceptionCaught);
    }

    @Test
    public void TestValidateExpiredPolicies() throws Exception {
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);

        ZTSMock zts = new ZTSMock();
        zts.setPublicKeyId("0");
        DomainSignedPolicyData domainPolicySignedData = zts.getDomainSignedPolicyData("expiredDomain", null, null);
        Assert.assertFalse(PolicyUpdater.validateSignedPolicies(null, configuration, domainPolicySignedData, "expiredDomain"));
    }
    
    @Test
    public void TestValidateExpiredPolicies_defaultConfDir() throws Exception {
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        try {
            configuration.init(null, null);
            Assert.fail();
        } catch (Exception e) {
        }
    }
    
    @Test
    public void TestWritePolicies() throws Exception {
        Path path = Paths.get("./src/test/resources/sys.auth.pol");
        DomainSignedPolicyData domainPolicySignedDataInput = JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        PolicyUpdater.writePolicies(pupConfig, "sys.auth", domainPolicySignedDataInput);
        
        path = Paths.get(pupConfig.getRootDir() + TEST_POLICY_DIR + "/sys.auth.pol");
        JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        
        // test handling of missing tmp dir
        //
        Path sysauthPath = Paths.get(pupConfig.getRootDir() + TEST_POLICY_TEMP_DIR + "/tmp/sys.auth");
        Files.deleteIfExists(sysauthPath);
        sysauthPath = Paths.get(pupConfig.getRootDir() + TEST_POLICY_TEMP_DIR + "/tmp");
        Files.deleteIfExists(sysauthPath);
        java.io.File polFile = path.toFile();
        long flen = polFile.length();
        long fmod = polFile.lastModified();
        Thread.sleep(1000);
        
        PolicyUpdaterConfiguration config = new PolicyUpdaterConfiguration();
        config.init(pathToAthenzConfigFile, pathToZPUConfigFile);
        config.setPolicyFileTmpDir(pupConfig.getRootDir() + TEST_POLICY_TEMP_DIR + "/tmp");
        config.setPolicyFileDir(pupConfig.getRootDir() + TEST_POLICY_DIR);
        PolicyUpdater.writePolicies(config, "sys.auth", domainPolicySignedDataInput);
        long flen2 = polFile.length();
        long fmod2 = polFile.lastModified();
        Assert.assertTrue(flen == flen2);
        Assert.assertTrue(fmod < fmod2);
        
        // Test error handling for illegal arguments
        boolean exceptionCaught = false;
        try {
            PolicyUpdater.writePolicies(null,  "sys.auth", domainPolicySignedDataInput);
        } catch (IllegalArgumentException ex) {
            exceptionCaught = true;
        }
        Assert.assertTrue(exceptionCaught);
        
        exceptionCaught = false;
        try {
            config.setPolicyFileTmpDir(null);
            PolicyUpdater.writePolicies(config,  "sys.auth", domainPolicySignedDataInput);
        } catch (IllegalArgumentException ex) {
            exceptionCaught = true;
        }
        Assert.assertTrue(exceptionCaught);
        
        exceptionCaught = false;
        try {
            config.setPolicyFileTmpDir(TEST_POLICY_TEMP_DIR);
            config.setPolicyFileDir(null);
            PolicyUpdater.writePolicies(config, "sys.auth", domainPolicySignedDataInput);
        } catch (IllegalArgumentException ex) {
            exceptionCaught = true;
        }
        Assert.assertTrue(exceptionCaught);
        
        try {
            config.setPolicyFileDir(TEST_POLICY_DIR);
            PolicyUpdater.writePolicies(config, null, domainPolicySignedDataInput);
        } catch (IllegalArgumentException ex) {
            exceptionCaught = true;
        }
        Assert.assertTrue(exceptionCaught);
        
        try {
            PolicyUpdater.writePolicies(config, "sys.auth", null);
        } catch (IllegalArgumentException ex) {
            exceptionCaught = true;
        }
        Assert.assertTrue(exceptionCaught);
        
        Files.delete(path);
    }

    @Test
    public void TestGetEtagForExistingPolicy() throws Exception, IOException {
        String expectedEtag = SignPoliciesUtility.signPolicies("./src/test/resources/unit_test_zts_private_k0.pem",
                    "./src/test/resources/unit_test_zms_private_k0.pem", "./src/test/resources/sys.auth.pol",
                    "./src/test/resources/sys.auth.new.pol");

        Map<String, String> newenv = new HashMap<String, String>();
        newenv.put("STARTUP_DELAY", Integer.toString(TEST_STARTUP_DELAY));
        setEnvironmentVar(newenv);
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);

        String matchingTag = PolicyUpdater.getEtagForExistingPolicy(null, configuration, "sys.auth.new");
        Assert.assertEquals(matchingTag, expectedEtag);
        
        matchingTag = PolicyUpdater.getEtagForExistingPolicy(null, configuration, "sys.auth.new");
        Assert.assertEquals(matchingTag, expectedEtag);
    }

    @Test
    public void TestGetEtagForExistingPolicy_ExpirationLessThanStartUpDelay() throws Exception, IOException {

        Map<String, String> newenv = new HashMap<String, String>();
        newenv.put("STARTUP_DELAY", Integer.toString(TEST_STARTUP_DELAY));
        setEnvironmentVar(newenv);
        
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);

        String matchingTag = PolicyUpdater.getEtagForExistingPolicy(null, configuration, "sys.auth");
        Assert.assertNull(matchingTag);

        matchingTag = PolicyUpdater.getEtagForExistingPolicy(null, configuration, "sys.auth");
        Assert.assertNull(matchingTag);
    }
    
    @Test
    public void TestGetEtagForExistingPolicy_NoPolicyFile() throws Exception {
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);
        
        // Negative test, getEtagForExistingPolicy should return null when no policy file is found
        String matchingTag = PolicyUpdater.getEtagForExistingPolicy(null, configuration, "testDomain");
        Assert.assertNull(matchingTag);
    }

    @Test
    public void TestGetEtagForExistingPolicy_IllegalArgs() throws Exception {
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);

        // Test error handling for illegal arguments
        boolean exceptionCaught = false;
        
        try {
            PolicyUpdater.getEtagForExistingPolicy(null, configuration, null);
        } catch (IllegalArgumentException ex) {
            exceptionCaught = true;
        }
        Assert.assertTrue(exceptionCaught);
    }
    
    @Test
    public void TestGetEtagForExistingPolicy_BadPolicyFileDir_IllegalArgs() throws Exception {
        
        PolicyUpdaterConfiguration configMock = Mockito.mock(PolicyUpdaterConfiguration.class);
        Mockito.when(configMock.getPolicyFileDir()).thenReturn(null);
        
        // Test error handling for illegal arguments
        boolean exceptionCaught = false;
        
        try {
            PolicyUpdater.getEtagForExistingPolicy(null, configMock, "testDomain");
        } catch (IllegalArgumentException ex) {
            exceptionCaught = true;
        }
        Assert.assertTrue(exceptionCaught);
    }

    @Test
    public void TestPolicyUpdater() throws Exception {
        
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUTestConfigFile);
        configuration.setPolicyFileDir(configuration.getRootDir() + TEST_POLICY_DIR);
        configuration.setPolicyFileTmpDir(configuration.getRootDir() + TEST_POLICY_TEMP_DIR);

        DebugZTSClientFactory ztsFactory = new DebugZTSClientFactory();
        ztsFactory.setPublicKeyId("0");
        PolicyUpdater.policyUpdater(configuration, ztsFactory);
        
        Path path = Paths.get(configuration.getRootDir() + TEST_POLICY_DIR
                + File.separator + "sports.pol");
        DomainSignedPolicyData domainPolicySignedData =
                JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        
        // Validate that the SignedPolicy written to target/classes is correct,
        // return value is true when policies are correctly validated
        Assert.assertTrue(PolicyUpdater.validateSignedPolicies(null, configuration,
                domainPolicySignedData, "sports"));
         
        Files.delete(path);
        
        path = Paths.get(configuration.getRootDir() + TEST_POLICY_DIR + File.separator + "sys.auth.pol");
        domainPolicySignedData = JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        
        // Validate that the SignedPolicy written to target/classes is correct,
        // return value is true when policies are correctly validated
        Assert.assertTrue(PolicyUpdater.validateSignedPolicies(null, configuration,
                domainPolicySignedData, "sys.auth.pol"));
        
        Files.delete(path);
    }
    
    @Test
    public void TestPolicyUpdaterEmptyDomainList() throws Exception {
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUEmptyConfigFile);
        configuration.setPolicyFileDir("./target/classes");
        
        try {
            PolicyUpdater.policyUpdater(configuration, new DebugZTSClientFactory());
            Assert.fail();
        } catch (Exception ex) {
            Assert.assertTrue(ex.getMessage().contains("no configured domains"));
        }
    }
    
    @Test
    public void TestPolicyUpdaterZTSException() throws Exception {
        
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);
        configuration.setPolicyFileDir(configuration.getRootDir() + TEST_POLICY_DIR);
        configuration.setPolicyFileTmpDir(configuration.getRootDir() + TEST_POLICY_TEMP_DIR);

        DebugZTSClientFactory ztsFactory = new DebugZTSClientFactory();
        ztsFactory.setPublicKeyId("4"); // not exist id
        PolicyUpdater.policyUpdater(configuration, ztsFactory);
    }
    
    @Test
    public void TestPolicyUpdaterConfigurationZTSKeyRetrieval() throws Exception {
        
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.init(pathToAthenzConfigFile, pathToZPUConfigFile);
        Assert.assertNotNull(configuration.getZtsPublicKey(null, "0"));
        Assert.assertNotNull(configuration.getZtsPublicKey(null, "1"));
        Assert.assertNull(configuration.getZtsPublicKey(null, "2"));
    }
    
    // URI null is not allow
    @Test(expectedExceptions={java.lang.NullPointerException.class})
    public void TestZTSClientFactoryImpl() {
        ZTSClientFactoryImpl factory = new ZTSClientFactoryImpl();
        factory.create();
    }
    
    @Test
    public void TestPolicyUpdaterConfigGetSet() {
        PolicyUpdaterConfiguration configuration = new PolicyUpdaterConfiguration();
        configuration.setRootDir("/home/root");
        configuration.setDebugMode(true);
        configuration.setStartupDelayInterval(2);
        
        Assert.assertEquals(configuration.getRootDir(), "/home/root");
        Assert.assertEquals(configuration.isDebugMode(), true);
        Assert.assertEquals(configuration.getStartupDelayIntervalInSecs(), 2*60);
        
    }
    
    @Test
    public void TestverifyTmpDirSetupUserNull() throws Exception {
        
        PolicyUpdaterConfiguration config = Mockito.mock(PolicyUpdaterConfiguration.class);
        Mockito.when(config.getPolicyFileTmpDir()).thenReturn(pupConfig.getRootDir() + TEST_POLICY_TEMP_DIR + "/tmpnon");
        Mockito.when(config.getZpuDirOwner()).thenReturn(null);
        
        boolean expectedCaught = true;
        try {
            PolicyUpdater.verifyTmpDirSetup(config);
        } catch (Exception e) {
        }
        Assert.assertTrue(expectedCaught);
    }
    
    private void setEnvironmentVar(Map<String, String> newenv) throws Exception {
        @SuppressWarnings("rawtypes")
        Class[] classes = Collections.class.getDeclaredClasses();
        Map<String, String> env = System.getenv();
        for (@SuppressWarnings("rawtypes") Class cl : classes) {
            if ("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
                Field field = cl.getDeclaredField("m");
                field.setAccessible(true);
                Object obj = field.get(env);
                @SuppressWarnings("unchecked")
                Map<String, String> map = (Map<String, String>) obj;
                map.clear();
                map.putAll(newenv);
           }
        }
     }
}
