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
package com.yahoo.athenz.zms_aws_json_domain_syncer;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zms.ZMSClient;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;

public class ZmsSyncerTest {
    private static final Logger LOGGER   = LoggerFactory.getLogger(ZmsSyncerTest.class);
    final static String TESTROOT             = "src/test/resources";
    final static Timestamp CUR_TIME = Timestamp.fromMillis(Timestamp.fromCurrentTime().millis());
    final static Timestamp OLD_TIME = Timestamp.fromString("2016-04-19T12:04:32.044Z");
    final static String[] domainUploadNames = { "coretech", "clouds", "moon", "pluto" };
    final static String[] domainDontUploadNames = { "coriander" };
    final static String   domainIgnoreNames = "moon, pluto";

    ZMSClient mockZMSClt = null;

    public static class MockCloudSyncer implements CloudSyncer {
        public void uploadDomain(String domainName, String domJson) throws Exception {
        }
        public void deleteDomain(String domainName) throws Exception {
        }
    }

    @SuppressWarnings("unchecked")
    public static class MockZmsSyncerFactory implements ZmsClientFactory {
        ZMSClient mockZMSClient = Mockito.mock(com.yahoo.athenz.zms.ZMSClient.class);
        public ZMSClient createClient(String url, String svcKeyFile, String svcCert, String trustStorePath, String trustStorePassword) throws Exception {

            final SignedDomains sdoms = new SignedDomains();
            List<SignedDomain> sdList = setupDomList(domainUploadNames, domainDontUploadNames);
            sdoms.setDomains(sdList);

            final List<SignedDomain> sdList2 = setupSignedDomList(domainUploadNames, domainDontUploadNames);

            // public SignedDomains getSignedDomains(String domainName, String metaOnly, String metaAttr,
            //      boolean masterCopy, String matchingTag, Map<String, List<String>> responseHeaders) {
            Mockito.doAnswer(new Answer<Object>() {
                @SuppressWarnings("rawtypes")
                public Object answer(InvocationOnMock invocation) {
                    Object[] args = invocation.getArguments();
                    if (args[5] != null) {
                        List<String> tagData = new ArrayList<>();
                        tagData.add(Timestamp.fromCurrentTime().toString());
                        ((HashMap)args[5]).put("tag", tagData);
                    }
                    if (args[0] != null) {
                        String domName = (String) args[0];
                        List<SignedDomain> sdList = new ArrayList<>();
                        for (int cnt = 0; cnt < sdList2.size(); ++cnt) {
                            SignedDomain sd = sdList2.get(cnt);
                            String name = sd.getDomain().getName();
                            if (name.equals(domName)) {
                                sdList.add(sd);
                                break;
                            }
                        }
                        return new SignedDomains().setDomains(sdList);
                    } else {
                        return sdoms;
                    }
                }
            }).when(mockZMSClient).getSignedDomains(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.any(), Mockito.any());
            return mockZMSClient;
        }
    }

    //
    @BeforeClass
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        mockZMSClt = new MockZmsSyncerFactory().createClient(null, null, null, null, null);
    }

    static List<SignedDomain> setupDomList(String[] domNames, String[] noUploadDoms) {
        List<SignedDomain> sdList = new ArrayList<>();
        for (String domName: domNames) {
            SignedDomain signedDomain = new SignedDomain();
            DomainData domainData = new DomainData().setName(domName);
            signedDomain.setDomain(domainData);
            domainData.setModified(CUR_TIME);
            sdList.add(signedDomain);
        }

        for (String domName: noUploadDoms) {
            SignedDomain signedDomain = new SignedDomain();
            DomainData domainData = new DomainData().setName(domName);
            signedDomain.setDomain(domainData);
            domainData.setModified(OLD_TIME);
            sdList.add(signedDomain);
        }

        return sdList;
    }

    static List<SignedDomain> setupSignedDomList(String[] domNames, String[] noUploadDoms) {
        List<SignedDomain> sdList = new ArrayList<>();
        for (String domName: domNames) {
            SignedDomain signedDomain = new SignedDomain();
            DomainData domainData = new DomainData().setName(domName);
            signedDomain.setDomain(domainData);
            domainData.setModified(CUR_TIME);

            File privKeyFile = new File("src/test/resources/zms_private.pem");
            String privKey = Crypto.encodedFile(privKeyFile);
            java.security.PrivateKey privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
            String keyId = "1";
            signedDomain.setKeyId(keyId);
            String signature = Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain()), privateKey);
            signedDomain.setSignature(signature);

            sdList.add(signedDomain);
        }

        for (String domName: noUploadDoms) {
            SignedDomain signedDomain = new SignedDomain();
            DomainData domainData = new DomainData().setName(domName);
            signedDomain.setDomain(domainData);
            domainData.setModified(OLD_TIME);

            File privKeyFile = new File("src/test/resources/zms_private.pem");
            String privKey = Crypto.encodedFile(privKeyFile);
            java.security.PrivateKey privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
            String keyId = "1";
            signedDomain.setKeyId(keyId);
            String signature = Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain()), privateKey);
            signedDomain.setSignature(signature);

            sdList.add(signedDomain);
        }

        return sdList;
    }

    @BeforeMethod
    void setupStateFile() throws Exception {
        // Reset singleton
        Field instance = Config.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);

        // set server property so that Config will get the path to our test file
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOTPATH, TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG, "true");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATEPATH, ".");
        System.setProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL, "https://zms.athenz.io:4443/");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_CLOUDCLASS, "com.yahoo.athenz.zms_aws_json_domain_syncer.AwsSyncer");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_IGNDOMS, domainIgnoreNames);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSREGION,"us-west-2");
        Config.getInstance().loadConfigParams();

        // cp the test json statefile to name to be processed by ZmsReader
        Path sourceFile = Paths.get(TESTROOT + "/domain_state_test.json");
        Path destinationFile = Paths.get(TESTROOT + "/domain_state.json");
        Files.copy(sourceFile, destinationFile, StandardCopyOption.REPLACE_EXISTING);
    }

    @Test
    public void testLoadStateFail() throws Exception {
        System.out.println("testLoadStateFail");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATEPATH, "no_such_state_file");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID,"keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY, "accessKey");
        Config.getInstance().loadConfigParams();
        ZmsSyncer zmsSyncer = new ZmsSyncer();
        assertEquals(new HashMap<>(), zmsSyncer.loadState());
        assertFalse(zmsSyncer.getLoadState());
        assertFalse(zmsSyncer.saveDomainsState());
    }

    @Test
    public void testDeleteDomainFail() throws Exception {
        System.out.println("testDeleteDomainFail");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID,"keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY, "accessKey");
        Config.getInstance().loadConfigParams();
        ZmsSyncer zmsSyncer = new ZmsSyncer();
        DomainState stateObj = zmsSyncer.deleteDomain("no_such_domain");
        assertNotNull(stateObj);
        assertEquals(stateObj.getModified(), "0");
        assertEquals(zmsSyncer.getNumDomainsDeleted(), 0);
        assertEquals(zmsSyncer.getNumDomainsDeletedFailed(), 1);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID);
    }

    @Test
    public void testDeleteDomain() throws Exception {
        System.out.println("testDeleteDomain");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_CLOUDCLASS, "com.yahoo.athenz.zms_aws_json_domain_syncer.ZmsSyncerTest$MockCloudSyncer");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID,"keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY, "accessKey");
        Config.getInstance().loadConfigParams();
        ZmsSyncer zmsSyncer = new ZmsSyncer();
        DomainState stateObj = zmsSyncer.deleteDomain("no_such_domain");
        assertNull(stateObj);
        assertEquals(zmsSyncer.getNumDomainsDeleted(), 1);
        assertEquals(zmsSyncer.getNumDomainsDeletedFailed(), 0);
    }

    @Test
    public void testUploadDomain() throws Exception {
        System.out.println("testUploadDomain");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_CLOUDCLASS, "com.yahoo.athenz.zms_aws_json_domain_syncer.ZmsSyncerTest$MockCloudSyncer");
        Config.getInstance().loadConfigParams();

        ZmsSyncer zmsSyncer = new ZmsSyncer();
        ZmsReader zmsRdr    = new ZmsReader(mockZMSClt);
        DomainState stateObj     = zmsSyncer.uploadDomain("clouds", zmsRdr);
        assertNotNull(stateObj);
        assertNotEquals(stateObj.getModified(), "0");
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 1);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 0);
    }

    @Test
    public void testUploadDomainFail() throws Exception {
        System.out.println("testUploadDomainFail");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID,"keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY, "accessKey");
        Config.getInstance().loadConfigParams();

        ZmsSyncer zmsSyncer = new ZmsSyncer();
        ZmsReader zmsRdr    = new ZmsReader(mockZMSClt);
        DomainState stateObj     = zmsSyncer.uploadDomain("no_such_domain", zmsRdr);
        assertNotNull(stateObj);
        assertEquals(stateObj.getModified(), "0");
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 0);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 1);

        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATEPATH) + ZmsSyncer.RUN_STATE_FILE;

        zmsSyncer.saveRunState(null);
        Struct rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        int runStatus = rState.getInt(ZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 1);
        String runMsg = rState.getString(ZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, ZmsSyncer.RUNS_STATUS_FAIL_MSG);
        int val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);

        // test an init state
        zmsSyncer = new ZmsSyncer();
        zmsSyncer.saveRunState(null);
        rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        runStatus = rState.getInt(ZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 0);
        runMsg = rState.getString(ZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, ZmsSyncer.RUNS_STATUS_SUCCESS_MSG);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);

        // test the init state but specify an exception
        zmsSyncer.saveRunState(new Exception("init-state-but-fail"));
        rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        runStatus = rState.getInt(ZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 1);
        runMsg = rState.getString(ZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, "init-state-but-fail");
        val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);
    }

    @Test(dependsOnMethods = { "testUploadDomainFail" })
    public void testProcessDomains() throws Exception {
        System.out.println("testProcessDomains");
        // set state file that will cause some domains to be deleted
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_CLOUDCLASS, "com.yahoo.athenz.zms_aws_json_domain_syncer.ZmsSyncerTest$MockCloudSyncer");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ZMSCLTFACT, "com.yahoo.athenz.zms_aws_json_domain_syncer.ZmsSyncerTest$MockZmsSyncerFactory");
        Config.getInstance().loadConfigParams();

        ZmsSyncer zmsSyncer = new ZmsSyncer();
        Map<String, DomainState> stateMap = zmsSyncer.loadState();
        assertNotNull(stateMap);
        assertTrue(zmsSyncer.syncDomains(stateMap));
        assertTrue(zmsSyncer.saveDomainsState());
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 2);
        assertEquals(zmsSyncer.getNumDomainsNotUploaded(), 3);  // 2 ignored, 1 was up to date
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 0);
        assertEquals(zmsSyncer.getNumDomainsDeleted(), 1);      // delete paas
        assertEquals(zmsSyncer.getNumDomainsDeletedFailed(), 0);

        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATEPATH) + ZmsSyncer.RUN_STATE_FILE;

        zmsSyncer.saveRunState(null);
        Struct rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        int runStatus = rState.getInt(ZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 0);
        String runMsg = rState.getString(ZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, ZmsSyncer.RUNS_STATUS_SUCCESS_MSG);
        int val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 2);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 3);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);

        zmsSyncer.saveRunState(new Exception("test-load-state-fail"));
        rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        runStatus = rState.getInt(ZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 1);
        runMsg = rState.getString(ZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, "test-load-state-fail");
        val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 2);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 3);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);
    }

    @Test
    public void testGetDomainList() {
        System.out.println("testGetDomainList");
        ZmsReader zmsRdr = new ZmsReader(mockZMSClt);
        List<SignedDomain> sdList = zmsRdr.getDomainList();
        assertNotNull(sdList);
        System.out.println(sdList.size());
        assertEquals(sdList.size(), 5);
        for (SignedDomain sDom : sdList) {
            DomainData domData = sDom.getDomain();
            assertNotNull(domData.getModified());
        }
    }

    @Test
    public void testGetZmsDomain() {
        System.out.println("testGetZmsDomain");
        ZmsReader zmsRdr = new ZmsReader(mockZMSClt);
        SignedDomain sDom = zmsRdr.getDomain("clouds");
        assertNotNull(sDom);
        DomainData domData = sDom.getDomain();
        assertEquals(domData.getName(), "clouds");
    }

    @Test
    public void testCloudInitBadRegion() {
        System.out.println("testCloudInitBadRegion");
        ZmsReader zmsRdr = new ZmsReader(mockZMSClt);
        SignedDomain sDom = zmsRdr.getDomain("clouds");
        LOGGER.debug("sDom: " + sDom);
        assertNotNull(sDom);

        // set props for bucket, clear aws secrets
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSREGION, TestConsts.TEST_AWSREGION);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID, TestConsts.TEST_AWSKEYID);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY, TestConsts.TEST_AWSACCKEY);
        Config.getInstance().loadConfigParams();
        try {
            @SuppressWarnings("unused")
            CloudSyncer syncer = new AwsSyncer();
        } catch (Exception exc) {
            System.out.println("testCloudInitBadRegion: AwsSyncer throws=" + exc);
            assertTrue(exc.getMessage().contains("MARS"));
        }
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSREGION);
    }

    @Test(dependsOnMethods = { "testCloudInitBadRegion" })
    public void testCloudInitBadBucket() {
        System.out.println("testCloudInitBadBucket");

        ZmsReader zmsRdr = new ZmsReader(mockZMSClt);
        SignedDomain sDom = zmsRdr.getDomain("clouds");
        LOGGER.debug("sDom: " + sDom);
        assertNotNull(sDom);

        // set propery for bucket and for aws secrets
        String bucket = "no_such_bucket";
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG, "true");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSBUCK, bucket);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID, "abcd");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY, "xyz");
        Config.getInstance().loadConfigParams();

        try {
            @SuppressWarnings("unused")
            CloudSyncer syncer = new AwsSyncer();
        } catch (Exception exc) {
            assertTrue(exc.getMessage().contains("bucket=" + bucket + " does NOT exist in S3"));
        }
    }
}