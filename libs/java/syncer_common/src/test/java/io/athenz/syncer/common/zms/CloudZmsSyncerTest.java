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

package io.athenz.syncer.common.zms;

import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Struct;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.s3.S3Client;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class CloudZmsSyncerTest {
    private final ClassLoader classLoader = this.getClass().getClassLoader();

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

    @AfterClass
    public void tearDown() {
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION);

    }

    @Test
    public void testCloudZmsSyncerDefaultConstructor() throws Exception {
        System.setProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS, "io.athenz.syncer.common.zms.impl.CloudDomainStoreNoOpFactory");
        System.setProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS, "io.athenz.syncer.common.zms.impl.StateFileBuilderNoOpFactory");

        final String certFile = Objects.requireNonNull(classLoader.getResource("unit_test_x509.pem")).getFile();
        final String keyFile = Objects.requireNonNull(classLoader.getResource("unit_test_private.pem")).getFile();
        final String caFile = Objects.requireNonNull(classLoader.getResource("unit_test_truststore.jks")).getFile();

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE, keyFile);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT, certFile);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PATH, caFile);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD, "secret");
        System.setProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL, "https://athenz.io");
        Config.getInstance().loadConfigParams();

        CloudZmsSyncer cloudZmsSyncer = new CloudZmsSyncer();
        assertNotNull(cloudZmsSyncer);

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD);
        System.clearProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL);
    }

    @Test
    public void testCreateCloudStoreInvalidFactory() {
        // Test with invalid factory class
        try {
            System.setProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS, "nonexistent.FactoryClass");

            CloudZmsSyncer syncer = new CloudZmsSyncer(null, null, null);
            Method method = CloudZmsSyncer.class.getDeclaredMethod("createCloudStore");
            method.setAccessible(true);
            method.invoke(syncer);
            fail("Expected exception when using invalid factory class");
        } catch (InvocationTargetException ex) {
            assertTrue(ex.getCause() instanceof RuntimeException);
            assertTrue(ex.getCause().getMessage().contains("unable to load cloud domain store factory class"));
        } catch (Exception ex) {
            fail("Unexpected exception: " + ex.getMessage());
        } finally {
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS);
        }
    }

    @Test
    public void testCreateStateFileBuilderInvalidFactory() {
        // Test with invalid factory class
        try {
            System.setProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS, "nonexistent.FactoryClass");

            CloudZmsSyncer syncer = new CloudZmsSyncer(null, null, null);
            Method method = CloudZmsSyncer.class.getDeclaredMethod("createStateFileBuilder");
            method.setAccessible(true);
            method.invoke(syncer);
            fail("Expected exception when using invalid factory class");
        } catch (InvocationTargetException ex) {
            assertTrue(ex.getCause() instanceof RuntimeException);
            assertTrue(ex.getCause().getMessage().contains("unable to load state file builder factory class"));
        } catch (Exception ex) {
            fail("Unexpected exception: " + ex.getMessage());
        } finally {
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS);
        }
    }

    @Test
    public void testLoadStateFail() {
        System.out.println("testLoadStateFail");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, "no_such_state_file");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID,"keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "accessKey");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = new DomainValidator();
        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
        assertEquals(zmsSyncer.loadState(), new HashMap<>());
        assertFalse(zmsSyncer.getLoadState());
        assertFalse(zmsSyncer.saveDomainsState());

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
    }

    @Test
    public void testLoadStateExceptionHandling() {
        System.out.println("testLoadStateExceptionHandling");

        // Set an invalid path that will cause an exception
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, "");
        Config.getInstance().loadConfigParams();

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);

        // Call loadState() which should hit the exception handling code
        Map<String, DomainState> result = zmsSyncer.loadState();

        // Verify that an empty HashMap is returned when an exception occurs
        assertNotNull(result);
        assertTrue(result.isEmpty());

        // Clean up
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH);
    }

    @Test
    public void testDeleteDomainFail() {
        System.out.println("testDeleteDomainFail");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID,"keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "accessKey");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = new DomainValidator();
        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        doThrow(AwsServiceException.builder().build()).when(cloudDomainStore).deleteDomain(any());
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
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
        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, domainValidator);
        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
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

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
        DomainState stateObj = zmsSyncer.uploadDomain("clouds");
        assertNotNull(stateObj);
        assertNotEquals(stateObj.getModified(), "0");
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 1);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 0);
    }

    @Test
    public void testUploadDomainFail() {
        System.out.println("testUploadDomainFail");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, "keyId");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "accessKey");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        when(validator.getDomainData(any())).thenReturn(new DomainData());

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        doThrow(AwsServiceException.builder().build()).when(cloudDomainStore).uploadDomain(any(), any());

        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
        DomainState stateObj = zmsSyncer.uploadDomain("no_such_domain");
        assertNotNull(stateObj);
        assertEquals(stateObj.getModified(), "0");
        assertEquals(zmsSyncer.getNumDomainsUploaded(), 0);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 1);

        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH) + CloudZmsSyncer.RUN_STATE_FILE;

        zmsSyncer.saveRunState(null);
        Struct rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        int runStatus = rState.getInt(CloudZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 1);
        String runMsg = rState.getString(CloudZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, CloudZmsSyncer.RUNS_STATUS_FAIL_MSG);
        int val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);

        // test an init state
        zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
        zmsSyncer.saveRunState(null);
        rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        runStatus = rState.getInt(CloudZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 0);
        runMsg = rState.getString(CloudZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, CloudZmsSyncer.RUNS_STATUS_SUCCESS_MSG);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);

        // test the init state but specify an exception
        zmsSyncer.saveRunState(new Exception("init-state-but-fail"));
        rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        runStatus = rState.getInt(CloudZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 1);
        runMsg = rState.getString(CloudZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, "init-state-but-fail");
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);
    }

    @Test
    public void testUploadDomainAwsFailure() {
        System.out.println("testUploadDomain");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        doThrow(AwsServiceException.builder().build()).when(cloudDomainStore).uploadDomain(any(), any());
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
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

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);

        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
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

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);

        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);

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

        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH) + CloudZmsSyncer.RUN_STATE_FILE;

        zmsSyncer.saveRunState(null);
        Struct rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        int runStatus = rState.getInt(CloudZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 0);
        String runMsg = rState.getString(CloudZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, CloudZmsSyncer.RUNS_STATUS_SUCCESS_MSG);
        int val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 4);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);

        zmsSyncer.saveRunState(new Exception("test-load-state-fail"));
        rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        runStatus = rState.getInt(CloudZmsSyncer.RUN_STATUS_FIELD);
        assertEquals(runStatus, 1);
        runMsg = rState.getString(CloudZmsSyncer.RUN_MESSAGE_FIELD);
        assertEquals(runMsg, "test-load-state-fail");
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOADED_FIELD);
        assertEquals(val, 4);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_NOT_UPLOADED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_UPLOAD_FAILED_FIELD);
        assertEquals(val, 0);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETED_FIELD);
        assertEquals(val, 1);
        val = rState.getInt(CloudZmsSyncer.NUM_DOMS_DELETE_FAILED_FIELD);
        assertEquals(val, 0);
    }

    @Test
    public void testSyncDomainsParallel() throws Exception {
        System.out.println("testSyncDomainsParallel");
        // set state file that will cause some domains to be deleted
        Config.getInstance().loadConfigParams();
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_UPDATE_FETCH_THREADS, "4");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_FETCH_THREADS, "4");
        Config.getInstance().loadConfigParams();

        try {
            DomainValidator validator = Mockito.mock(DomainValidator.class);
            when(validator.validateJWSDomain(any())).thenReturn(true);
            DomainValidator domainValidator = new DomainValidator();
            when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
                Object[] arguments = invocationOnMock.getArguments();
                return domainValidator.getDomainData((JWSDomain) arguments[0]);
            });

            CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
            ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);

            S3Client s3Client = Mockito.mock(S3Client.class);
            StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

            CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);

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
        } finally {
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_UPDATE_FETCH_THREADS);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_FETCH_THREADS);
            Config.getInstance().loadConfigParams();
        }
    }

    @Test
    public void testSyncDomainsNoList() {
        System.out.println("testSyncDomainsNoList");

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        when(validator.getDomainData(any())).thenReturn(new DomainData());

        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        when(zmsReader.getDomainList()).thenReturn(null);

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
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

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
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

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
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

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
        assertFalse(zmsSyncer.processDomains());
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH);
    }

    @Test
    public void testLoadStateException() {
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, "bad-data");

        Config.getInstance().loadConfigParams();

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
        assertTrue(zmsSyncer.loadState().isEmpty());
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH);
    }

    @Test
    public void testShouldRefreshDomain() {
        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
        assertFalse(zmsSyncer.shouldRefreshDomain(null, 10000, 3600));

        DomainState state = new DomainState();
        state.setFetchTime(1000);

        // with time matching we should get success

        assertTrue(zmsSyncer.shouldRefreshDomain(state, 10000, 8500));

        // if the value is 0 then it's false

        state.setFetchTime(0);
        assertFalse(zmsSyncer.shouldRefreshDomain(state, 10000, 9500));

        // test where refresh is not necessary

        state.setFetchTime(600);
        assertFalse(zmsSyncer.shouldRefreshDomain(state, 10000, 9500));

        state.setFetchTime(400);
        assertTrue(zmsSyncer.shouldRefreshDomain(state, 10000, 9500));
    }

    @Test
    public void testDomainRefreshIncrement() {
        System.out.println("testDomainRefreshIncrement");
        Config.getInstance().loadConfigParams();

        // Set up a short refresh timeout to ensure domains need refreshing
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_TIMEOUT, "300");
        // Set the limit lower than the number of domains that need refresh
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_COUNT, "2");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_UPDATE_FETCH_THREADS, "4");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_FETCH_THREADS, "4");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);

        // Create a state map with domains that need refreshing
        Map<String, DomainState> stateMap = new HashMap<>();

        // Use domains that are part of the mock ZMS response in MockZmsClient
        // coretech, clouds, moon, pluto, coriander

        try {
            // First we need to get the exact modification times from the mock to prevent "uploadDom = true"
            List<SignedDomain> mockDomainList = zmsReader.getDomainList();
            for (SignedDomain sDom : mockDomainList) {
                String domName = sDom.getDomain().getName();
                DomainState staleState = new DomainState();
                staleState.setDomain(domName);
                // Modified time matching exactly what ZMS returns will force refresh logic (not upload)
                staleState.setModified(sDom.getDomain().getModified().toString());
                staleState.setFetchTime(System.currentTimeMillis()/1000 - 600); // 10 minutes ago
                stateMap.put(domName, staleState);
            }

            // Before syncing, the count should be 0
            assertEquals(zmsSyncer.getNumDomainsRefreshed(), 0);

            // Perform sync
            zmsSyncer.syncDomains(stateMap);

            // After syncing, verify that numDomainsRefreshed was incremented,
            // but exactly up to the limit (2)
            assertEquals(zmsSyncer.getNumDomainsRefreshed(), 2);

        } catch (Exception e) {
            fail("Test failed with exception: " + e.getMessage());
        } finally {
            // Clean up
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_TIMEOUT);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_COUNT);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_UPDATE_FETCH_THREADS);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_FETCH_THREADS);
        }
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

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        doThrow(AwsServiceException.builder().build()).when(cloudDomainStore).deleteDomain("paas");
        when(mockZMSClt.getJWSDomain(eq("clouds"), eq(null), anyMap()))
                .thenThrow(new ZMSClientException(400, "bad-domain"));
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        S3Client s3Client = Mockito.mock(S3Client.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);

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
    public void testSyncDomainsThreadConfigNormalization() throws Exception {
        System.out.println("testSyncDomainsThreadConfigNormalization");
        Config.getInstance().loadConfigParams();
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_UPDATE_FETCH_THREADS, "0");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_FETCH_THREADS, "0");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_COUNT, "-1");
        Config.getInstance().loadConfigParams();

        try {
            DomainValidator validator = Mockito.mock(DomainValidator.class);
            when(validator.validateJWSDomain(any())).thenReturn(true);
            DomainValidator domainValidator = new DomainValidator();
            when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
                Object[] arguments = invocationOnMock.getArguments();
                return domainValidator.getDomainData((JWSDomain) arguments[0]);
            });

            CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
            ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
            StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

            CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);
            Map<String, DomainState> stateMap = zmsSyncer.loadState();
            assertNotNull(stateMap);
            assertTrue(zmsSyncer.syncDomains(stateMap));
        } finally {
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_UPDATE_FETCH_THREADS);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_FETCH_THREADS);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DOMAIN_REFRESH_COUNT);
            Config.getInstance().loadConfigParams();
        }
    }

    @Test
    public void testSyncDomainsExecutionExceptionPath() throws Exception {
        System.out.println("testSyncDomainsExecutionExceptionPath");
        Config.getInstance().loadConfigParams();

        DomainValidator validator = Mockito.mock(DomainValidator.class);
        when(validator.validateJWSDomain(any())).thenReturn(true);
        DomainValidator domainValidator = new DomainValidator();
        when(validator.getDomainData(any())).thenAnswer(invocationOnMock -> {
            Object[] arguments = invocationOnMock.getArguments();
            return domainValidator.getDomainData((JWSDomain) arguments[0]);
        });

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = new ZmsReader(mockZMSClt, validator);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);

        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder) {
            @Override
            DomainState uploadDomain(final String domainName) {
                throw new RuntimeException("injected upload failure");
            }
        };

        assertFalse(zmsSyncer.syncDomains(new HashMap<>()));
        assertTrue(zmsSyncer.getNumDomainsUploadFailed() > 0);
        assertTrue(zmsSyncer.saveRunState(null));

        String stateFileName = Config.getInstance().getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH) + CloudZmsSyncer.RUN_STATE_FILE;
        Struct rState = Config.getInstance().parseJsonConfigFile(stateFileName);
        assertEquals(rState.getInt(CloudZmsSyncer.RUN_STATUS_FIELD), 1);
    }

    @Test
    public void testAddFailedDomainStateIncrementsUploadFailed() throws Exception {
        System.out.println("testAddFailedDomainStateIncrementsUploadFailed");

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);
        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);

        java.lang.reflect.Field field = CloudZmsSyncer.class.getDeclaredField("processedDomains");
        field.setAccessible(true);
        field.set(zmsSyncer, new ArrayList<DomainState>());

        Method addFailedMethod = CloudZmsSyncer.class.getDeclaredMethod("addFailedDomainState", String.class);
        addFailedMethod.setAccessible(true);
        addFailedMethod.invoke(zmsSyncer, "domain.one");

        @SuppressWarnings("unchecked")
        List<DomainState> processed = (List<DomainState>) field.get(zmsSyncer);
        assertEquals(processed.size(), 1);
        assertEquals(processed.get(0).getDomain(), "domain.one");
        assertEquals(processed.get(0).getModified(), CloudZmsSyncer.LAST_MOD_NO_DATE);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 1);
    }

    @Test
    public void testCollectProcessedDomainsInterruptedPath() throws Exception {
        System.out.println("testCollectProcessedDomainsInterruptedPath");

        CloudDomainStore cloudDomainStore = Mockito.mock(CloudDomainStore.class);
        ZmsReader zmsReader = Mockito.mock(ZmsReader.class);
        StateFileBuilder stateFileBuilder = Mockito.mock(StateFileBuilder.class);
        CloudZmsSyncer zmsSyncer = new CloudZmsSyncer(cloudDomainStore, zmsReader, stateFileBuilder);

        // initialize processedDomains so collectProcessedDomains can store fallback states
        Method method = CloudZmsSyncer.class.getDeclaredMethod("collectProcessedDomains", List.class);
        method.setAccessible(true);

        java.lang.reflect.Field field = CloudZmsSyncer.class.getDeclaredField("processedDomains");
        field.setAccessible(true);
        field.set(zmsSyncer, new ArrayList<DomainState>());

        class InterruptFuture implements Future<DomainState> {
            boolean cancelled = false;

            @Override
            public boolean cancel(boolean mayInterruptIfRunning) {
                cancelled = true;
                return true;
            }

            @Override
            public boolean isCancelled() {
                return cancelled;
            }

            @Override
            public boolean isDone() {
                return false;
            }

            @Override
            public DomainState get() throws InterruptedException, ExecutionException {
                throw new InterruptedException("interrupted");
            }

            @Override
            public DomainState get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException {
                throw new InterruptedException("interrupted");
            }
        }

        InterruptFuture firstFuture = new InterruptFuture();
        InterruptFuture secondFuture = new InterruptFuture();

        List<CloudZmsSyncer.DomainUploadTask> tasks = new ArrayList<>();
        tasks.add(new CloudZmsSyncer.DomainUploadTask("domain.one", firstFuture));
        tasks.add(new CloudZmsSyncer.DomainUploadTask("domain.two", secondFuture));

        try {
            boolean result = (boolean) method.invoke(zmsSyncer, tasks);
            assertFalse(result);
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            // clear interrupt flag so other tests are not affected
            Thread.interrupted();
        }

        @SuppressWarnings("unchecked")
        List<DomainState> processed = (List<DomainState>) field.get(zmsSyncer);
        assertEquals(processed.size(), 2);
        assertEquals(processed.get(0).getDomain(), "domain.one");
        assertEquals(processed.get(0).getModified(), CloudZmsSyncer.LAST_MOD_NO_DATE);
        assertEquals(processed.get(1).getDomain(), "domain.two");
        assertEquals(processed.get(1).getModified(), CloudZmsSyncer.LAST_MOD_NO_DATE);
        assertEquals(zmsSyncer.getNumDomainsUploadFailed(), 2);
        assertTrue(firstFuture.cancelled);
        assertTrue(secondFuture.cancelled);
    }

    @Test
    public void testCloudZmsSyncer() {
        // calling main zms syncer without any proper zms
        // and s3 config will result in failure
        try {
            new CloudZmsSyncer();
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testLaunchSyncerSuccess() throws Exception {
        System.setProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS, "io.athenz.syncer.common.zms.impl.CloudDomainStoreNoOpFactory");
        System.setProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS, "io.athenz.syncer.common.zms.impl.StateFileBuilderNoOpFactory");

        CloudZmsSyncer mockSyncer = Mockito.mock(CloudZmsSyncer.class);
        when(mockSyncer.processDomains()).thenReturn(true);

        try {
            boolean result = CloudZmsSyncer.launchSyncer(mockSyncer);
            assertTrue(result);
        } finally {
            // Clean up
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS);
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS);
        }
    }

    @Test
    public void testLaunchSyncerFailure() throws Exception {
        System.setProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS, "io.athenz.syncer.common.zms.impl.CloudDomainStoreNoOpFactory");
        System.setProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS, "io.athenz.syncer.common.zms.impl.StateFileBuilderNoOpFactory");

        CloudZmsSyncer mockSyncer = Mockito.mock(CloudZmsSyncer.class);
        when(mockSyncer.processDomains()).thenThrow(new RuntimeException("processDomains failed"));
        when(mockSyncer.saveRunState(any())).thenReturn(true);

        try {
            boolean result = CloudZmsSyncer.launchSyncer(mockSyncer);

            assertFalse(result);
        } finally {
            // Clean up
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS);
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS);
        }
    }
}
