/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms_aws_domain_syncer;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Struct;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.*;
import static org.testng.Assert.*;

public class ZmsSyncerTest {

    ZMSClient mockZMSClt = null;

    @BeforeClass
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @BeforeMethod
    void setupStateFile() throws Exception {

        mockZMSClt = new MockZmsClient().createClient();

        // set server property so that Config will get the path to our test file
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG, "true");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, ".");
        System.setProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL, "https://athenz.com:4443/");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION,"us-west-2");
        Config.getInstance().loadConfigParams();

        // cp the test json statefile to name to be processed by ZmsReader
        Path sourceFile = Paths.get(TestUtils.TESTROOT + "/domain_state_test.json");
        Path destinationFile = Paths.get(TestUtils.TESTROOT + "/domain_state.json");
        Files.copy(sourceFile, destinationFile, StandardCopyOption.REPLACE_EXISTING);
    }

    @Test
    public void testLoadStateFail() {
        System.out.println("testLoadStateFail");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, "no_such_state_file");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID,"keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "accessKey");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = new DomainValidator();
        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        AmazonS3 s3Client = Mockito.mock(AmazonS3.class);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3Client, validator);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        assertEquals(new HashMap<>(), zmsSyncer.loadState());
        assertFalse(zmsSyncer.getLoadState());
        assertFalse(zmsSyncer.saveDomainsState());
    }

    @Test
    public void testDeleteDomainFail() throws Exception {
        System.out.println("testDeleteDomainFail");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID,"keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "accessKey");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = new DomainValidator();
        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        doThrow(new AmazonS3Exception("failure")).when(awsSyncer).deleteDomain(any());
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        AmazonS3 s3Client = Mockito.mock(AmazonS3.class);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3Client, validator);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        DomainState stateObj = zmsSyncer.deleteDomain("no_such_domain");
        assertNotNull(stateObj);
        assertEquals(stateObj.getModified(), "0");
        assertEquals(zmsSyncer.getNumDomainsDeleted(), 0);
        assertEquals(zmsSyncer.getNumDomainsDeletedFailed(), 1);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
    }

    @Test
    public void testDeleteDomain() {
        System.out.println("testDeleteDomain");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID,"keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "accessKey");
        Config.getInstance().loadConfigParams();

        DomainValidator domainValidator = new DomainValidator();
        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, domainValidator);
        AmazonS3 s3Client = Mockito.mock(AmazonS3.class);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3Client, domainValidator);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        DomainState stateObj = zmsSyncer.deleteDomain("no_such_domain");
        assertNull(stateObj);
        assertEquals(zmsSyncer.getNumDomainsDeleted(), 1);
        assertEquals(zmsSyncer.getNumDomainsDeletedFailed(), 0);
    }

    @Test
    public void testUploadDomain() {
        System.out.println("testUploadDomain");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        AmazonS3 s3Client = Mockito.mock(AmazonS3.class);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3Client, domainValidator);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        DomainState stateObj = zmsSyncer.uploadDomain("clouds");
        assertNotNull(stateObj);
        assertNotEquals(stateObj.getModified(), "0");
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 1);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 0);
    }

    @Test
    public void testUploadDomainFail() throws Exception {
        System.out.println("testUploadDomainFail");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, "keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "accessKey");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        when(validator.getDomainData(any())).thenReturn(new DomainData());

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        doThrow(new AmazonS3Exception("failure")).when(awsSyncer).uploadDomain(any(), any());
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        AmazonS3 s3Client = Mockito.mock(AmazonS3.class);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3Client, validator);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        DomainState stateObj = zmsSyncer.uploadDomain("no_such_domain");
        assertNotNull(stateObj);
        assertEquals(stateObj.getModified(), "0");
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 0);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 1);

        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH) + ZmsSyncer.RUN_STATE_FILE;

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
        zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
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

    @Test
    public void testUploadDomainAwsFailure() throws Exception {
        System.out.println("testUploadDomain");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        doThrow(new AmazonS3Exception("failure")).when(awsSyncer).uploadDomain(any(), any());
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        AmazonS3 s3Client = Mockito.mock(AmazonS3.class);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3Client, domainValidator);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        DomainState stateObj = zmsSyncer.uploadDomain("clouds");
        assertNotNull(stateObj);
        assertEquals(stateObj.getModified(), "0");
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 0);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 1);
    }

    @Test
    public void testProcessDomains() throws Exception {
        System.out.println("testProcessDomains");
        // set state file that will cause some domains to be deleted
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, TestConsts.TEST_AWS_KEY_ID);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, TestConsts.TEST_AWS_ACCESS_KEY);
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        StateFileBuilder stateFileBuilder = new StateFileBuilder();

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        assertTrue(zmsSyncer.processDomains());
        assertTrue(zmsSyncer.saveDomainsState());
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 4);
        // 1 was up-to-date
        assertEquals(zmsSyncer.getNumDomainsNotUploaded(), 1);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 0);
        // delete paas
        assertEquals(zmsSyncer.getNumDomainsDeleted(), 1);
        assertEquals(zmsSyncer.getNumDomainsDeletedFailed(), 0);
    }

    @Test
    public void testSyncDomains() throws Exception {
        System.out.println("testSyncDomains");
        // set state file that will cause some domains to be deleted
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        StateFileBuilder stateFileBuilder = new StateFileBuilder();

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);

        Map<String, DomainState> stateMap = zmsSyncer.loadState();
        assertNotNull(stateMap);
        assertTrue(zmsSyncer.syncDomains(stateMap));
        assertTrue(zmsSyncer.saveDomainsState());
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 4);
        // 1 was up-to-date
        assertEquals(zmsSyncer.getNumDomainsNotUploaded(), 1);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 0);
        // delete paas
        assertEquals(zmsSyncer.getNumDomainsDeleted(), 1);
        assertEquals(zmsSyncer.getNumDomainsDeletedFailed(), 0);

        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH) + ZmsSyncer.RUN_STATE_FILE;

        zmsSyncer.saveRunState(null);
        Struct rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        int runStatus = rState.getInt(ZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 0);
        String runMsg = rState.getString(ZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, ZmsSyncer.RUNS_STATUS_SUCCESS_MSG);
        int val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 4);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 1);
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
        assertEquals(val, 4);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(ZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);
    }

    @Test
    public void testSyncDomainsNoList() {
        System.out.println("testSyncDomainsNoList");

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        when(validator.getDomainData(any())).thenReturn(new DomainData());

        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        when(zmsReader.getDomainList()).thenReturn(null);

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        try {
            zmsSyncer.syncDomains(null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("no zms domain list"));
        }
    }

    @Test
    public void testSyncDomainsException() {
        System.out.println("testSyncDomainsException");

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        when(validator.getDomainData(any())).thenReturn(new DomainData());

        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        when(zmsReader.getDomainList()).thenThrow(new ZMSClientException(400, "invalid-request"));

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        try {
            zmsSyncer.syncDomains(null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("invalid-request"));
        }
    }

    @Test
    public void testGetDomainList() {
        System.out.println("testGetDomainList");

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        when(validator.getDomainData(any())).thenReturn(new DomainData());

        ZmsReader zmsRdr = new ZmsReader(mockZMSClt, validator);
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
    public void testProcessDomainsBadConfig() {

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        Config.getInstance().loadConfigParams();

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        try {
            zmsSyncer.processDomains();
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("bad configuration"));
        }
    }

    @Test
    public void testProcessDomainsInvalidStatePath() throws Exception {
        System.out.println("testProcessDomains");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, "invalid-path");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        AmazonS3 s3Client = Mockito.mock(AmazonS3.class);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3Client, validator);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        assertFalse(zmsSyncer.processDomains());
    }

    @Test
    public void testLoadStateException() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, "bad-data");
        Config.getInstance().loadConfigParams();

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        assertTrue(zmsSyncer.loadState().isEmpty());
    }

    @Test
    public void testShouldRefreshDomain() {

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);
        assertFalse(zmsSyncer.shouldRefreshDomain(null, 10000, 10, 3600));

        // test refresh limit reached

        zmsSyncer.setNumDomainsRefreshed(10);
        DomainState state = new DomainState();
        state.setFetchTime(1000);

        assertFalse(zmsSyncer.shouldRefreshDomain(state, 10000, 10, 9500));

        zmsSyncer.setNumDomainsRefreshed(11);
        assertFalse(zmsSyncer.shouldRefreshDomain(state, 10000, 10, 9500));

        // with limit lower we should get success

        zmsSyncer.setNumDomainsRefreshed(9);
        assertTrue(zmsSyncer.shouldRefreshDomain(state, 10000, 10, 8500));

        // if the value is 0 then it's false

        state.setFetchTime(0);
        assertFalse(zmsSyncer.shouldRefreshDomain(state, 10000, 10, 9500));

        // test where refresh is not necessary

        state.setFetchTime(600);
        assertFalse(zmsSyncer.shouldRefreshDomain(state, 10000, 10, 9500));

        state.setFetchTime(400);
        assertTrue(zmsSyncer.shouldRefreshDomain(state, 10000, 10, 9500));
    }

    @Test
    public void testSyncDomainsWithFailures() throws Exception {
        System.out.println("testSyncDomains");
        // set state file that will cause some domains to be deleted
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        AwsSyncer awsSyncer = Mockito.mock(AwsSyncer.class);
        doThrow(new AmazonS3Exception("bad-request")).when(awsSyncer).deleteDomain("paas");
        when(mockZMSClt.getJWSDomain(eq("clouds"), eq(null), anyMap()))
                .thenThrow(new ZMSClientException(400, "bad-domain"));
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        AmazonS3 s3Client = Mockito.mock(AmazonS3.class);
        StateFileBuilder stateFileBuilder = new StateFileBuilder(s3Client, validator);

        ZmsSyncer zmsSyncer = new ZmsSyncer(awsSyncer, zmsReader, stateFileBuilder);

        Map<String, DomainState> stateMap = zmsSyncer.loadState();
        assertNotNull(stateMap);
        assertFalse(zmsSyncer.syncDomains(stateMap));
        assertTrue(zmsSyncer.saveDomainsState());
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 3);
        assertEquals(zmsSyncer.getNumDomainsNotUploaded(), 1);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 1);
        // delete paas
        assertEquals(zmsSyncer.getNumDomainsDeleted(), 0);
        assertEquals(zmsSyncer.getNumDomainsDeletedFailed(), 1);
    }

    @Test
    public void testZmsSyncer() {
        // calling main zms syncer without any proper zms
        // and s3 config will result in failure
        try {
            new ZmsSyncer();
            fail();
        } catch (Exception ignored) {
        }
    }
}
