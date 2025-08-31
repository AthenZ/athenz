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
package io.athenz.syncer.gcp.common.impl;

import com.google.api.gax.paging.Page;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import io.athenz.syncer.common.zms.Config;
import io.athenz.syncer.common.zms.DomainState;
import io.athenz.syncer.common.zms.DomainValidator;
import io.athenz.syncer.common.zms.JWSDomainData;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutorService;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class GcsStateFileBuilderTest {

    private static final String TEST_PROJECT_ID = "test-project";
    private static final String TEST_BUCKET_NAME = "test-bucket";
    private static final String TEST_DOMAIN = "test-domain";
    private static final String TEST_DOMAIN_CONTENT = "{\"domain\":{\"name\":\"test-domain\"}}";
    private static final String TEST_THREAD_COUNT = "2";
    private static final String TEST_TIMEOUT = "30";

    @Mock
    private Storage mockStorage;

    @Mock
    private StorageOptions mockOptions;

    @Mock
    private StorageOptions.Builder mockBuilder;

    @Mock
    private Page<Blob> mockPage;

    @Mock
    private Blob mockBlob;

    @Mock
    private DomainValidator mockDomainValidator;

    private AutoCloseable closeable;
    private MockedStatic<Config> mockedConfig;
    private MockedStatic<StorageOptions> mockedStorageOptions;
    private GcsStateFileBuilder stateFileBuilder;

    @BeforeMethod
    public void setUp() {
        closeable = MockitoAnnotations.openMocks(this);

        // Mock Config
        mockedConfig = mockStatic(Config.class);
        Config mockConfigInstance = mock(Config.class);
        mockedConfig.when(Config::getInstance).thenReturn(mockConfigInstance);
        when(mockConfigInstance.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_PROJECT_ID)).thenReturn(TEST_PROJECT_ID);
        when(mockConfigInstance.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_BUCKET_NAME)).thenReturn(TEST_BUCKET_NAME);
        when(mockConfigInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS)).thenReturn(TEST_THREAD_COUNT);
        when(mockConfigInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT)).thenReturn(TEST_TIMEOUT);

        // Mock StorageOptions
        mockedStorageOptions = mockStatic(StorageOptions.class);
        mockedStorageOptions.when(StorageOptions::newBuilder).thenReturn(mockBuilder);
        mockedStorageOptions.when(StorageOptions::getDefaultInstance).thenReturn(mockOptions);
        when(mockBuilder.setProjectId(anyString())).thenReturn(mockBuilder);
        when(mockBuilder.build()).thenReturn(mockOptions);
        when(mockOptions.getService()).thenReturn(mockStorage);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (mockedConfig != null) {
            mockedConfig.close();
        }
        if (mockedStorageOptions != null) {
            mockedStorageOptions.close();
        }
        if (closeable != null) {
            closeable.close();
        }
    }

    @Test
    public void testConstructor() {
        stateFileBuilder = new GcsStateFileBuilder(TEST_PROJECT_ID, TEST_BUCKET_NAME, mockDomainValidator);
        assertNotNull(stateFileBuilder);
    }

    @Test
    public void testListObjects() {
        // mock hidden file
        Blob hiddenBlob = mock(Blob.class);
        when(hiddenBlob.getName()).thenReturn(".hidden-file");

        // Setup mock Page and Blob for list operation
        Iterable<Blob> mockIterable = List.of(mockBlob, hiddenBlob);
        when(mockStorage.list(TEST_BUCKET_NAME)).thenReturn(mockPage);
        when(mockPage.iterateAll()).thenReturn(mockIterable);
        when(mockBlob.getName()).thenReturn(TEST_DOMAIN).thenReturn(".hidden-file");

        stateFileBuilder = new GcsStateFileBuilder(TEST_PROJECT_ID, TEST_BUCKET_NAME, mockDomainValidator);
        List<String> domains = stateFileBuilder.listObjects();

        assertNotNull(domains);
        assertEquals(domains.size(), 1);
        assertEquals(domains.get(0), TEST_DOMAIN);
        verify(mockStorage).list(TEST_BUCKET_NAME);
    }

    @Test
    public void testBuildStateMap() throws IOException, NoSuchFieldException, IllegalAccessException {
        Timestamp modifiedTime = Timestamp.fromMillis(System.currentTimeMillis() - 2000);
        // Setup domain validation
        JWSDomain mockJwsDomain = mock(JWSDomain.class);
        DomainData mockDomainData = new DomainData();
        mockDomainData.setName(TEST_DOMAIN);
        mockDomainData.setModified(modifiedTime);

        when(mockDomainValidator.validateJWSDomain(mockJwsDomain)).thenReturn(true);
        when(mockDomainValidator.getDomainData(mockJwsDomain)).thenReturn(mockDomainData);

        // Setup storage and blob mocks
        Iterable<Blob> mockIterable = Collections.singletonList(mockBlob);
        when(mockStorage.list(TEST_BUCKET_NAME)).thenReturn(mockPage);
        when(mockPage.iterateAll()).thenReturn(mockIterable);
        when(mockBlob.getName()).thenReturn(TEST_DOMAIN);
        when(mockStorage.get(TEST_BUCKET_NAME, TEST_DOMAIN)).thenReturn(mockBlob);
        when(mockBlob.getContent()).thenReturn(TEST_DOMAIN_CONTENT.getBytes());
        when(mockBlob.getUpdateTimeOffsetDateTime()).thenReturn(OffsetDateTime.now());

        // Setup mapper to return our mock domain
        stateFileBuilder = new GcsStateFileBuilder(TEST_PROJECT_ID, TEST_BUCKET_NAME, mockDomainValidator) {
            @Override
            List<String> listObjects() {
                return Collections.singletonList(TEST_DOMAIN);
            }
        };

        // We need to set this field in our test
        java.lang.reflect.Field field = GcsStateFileBuilder.class.getDeclaredField("tempJWSDomainMap");
        field.setAccessible(true);
        field.set(stateFileBuilder, Collections.singletonMap(TEST_DOMAIN,
                new JWSDomainData(mockJwsDomain, System.currentTimeMillis())));

        Map<String, DomainState> stateMap = stateFileBuilder.buildStateMap();

        assertNotNull(stateMap);
        assertEquals(stateMap.size(), 1);
        assertTrue(stateMap.containsKey(TEST_DOMAIN));
        Assert.assertEquals(stateMap.get(TEST_DOMAIN).getDomain(), TEST_DOMAIN);
    }

    @Test
    public void testBuildStateMapWithInvalidDomain() {
        // Setup domain validation to return false
        JWSDomain mockJwsDomain = mock(JWSDomain.class);
        when(mockDomainValidator.validateJWSDomain(mockJwsDomain)).thenReturn(false);

        // Setup storage for list operation
        Iterable<Blob> mockIterable = Collections.singletonList(mockBlob);
        when(mockStorage.list(TEST_BUCKET_NAME)).thenReturn(mockPage);
        when(mockPage.iterateAll()).thenReturn(mockIterable);
        when(mockBlob.getName()).thenReturn(TEST_DOMAIN);

        stateFileBuilder = new GcsStateFileBuilder(TEST_PROJECT_ID, TEST_BUCKET_NAME, mockDomainValidator) {
            @Override
            List<String> listObjects() {
                return Collections.singletonList(TEST_DOMAIN);
            }
        };

        // We need to set this field in our test
        try {
            java.lang.reflect.Field field = GcsStateFileBuilder.class.getDeclaredField("tempJWSDomainMap");
            field.setAccessible(true);
            field.set(stateFileBuilder, Collections.singletonMap(TEST_DOMAIN,
                    new JWSDomainData(mockJwsDomain, System.currentTimeMillis())));

            Map<String, DomainState> stateMap = stateFileBuilder.buildStateMap();

            assertNotNull(stateMap);
            assertEquals(stateMap.size(), 0);
        } catch (Exception e) {
            fail("Failed to set field: " + e.getMessage());
        }
    }

    @Test
    public void testBuildStateMapInterruptedException() throws Exception {
        // Create a mock executor service that will throw InterruptedException
        ExecutorService mockExecutorService = mock(ExecutorService.class);
        when(mockExecutorService.awaitTermination(anyLong(), any(TimeUnit.class)))
                .thenThrow(new InterruptedException("Test interruption"));

        // Create the GcsStateFileBuilder with mocked dependencies
        stateFileBuilder = new GcsStateFileBuilder(TEST_PROJECT_ID, TEST_BUCKET_NAME, mockDomainValidator) {
            @Override
            List<String> listObjects() {
                // Return a small list of domains
                return Arrays.asList(TEST_DOMAIN);
            }
        };

        // Replace the executor service with our mock
        java.lang.reflect.Field executorField = GcsStateFileBuilder.class.getDeclaredField("executorService");
        executorField.setAccessible(true);
        ExecutorService originalExecutor = (ExecutorService) executorField.get(stateFileBuilder);
        executorField.set(stateFileBuilder, mockExecutorService);

        // Add test data to the map
        stateFileBuilder.tempJWSDomainMap.put(TEST_DOMAIN, mock(JWSDomainData.class));

        try {
            // This should trigger our mocked InterruptedException
            stateFileBuilder.buildStateMap();

            // Verify tempJWSDomainMap was cleared
            assertTrue(stateFileBuilder.tempJWSDomainMap.isEmpty(),
                    "Map should be cleared after InterruptedException");

            // Verify shutdownNow was called
            verify(mockExecutorService).shutdownNow();

        } finally {
            // Restore original executor and shut it down
            executorField.set(stateFileBuilder, originalExecutor);
            originalExecutor.shutdownNow();
        }
    }

    @Test
    public void testBucketObjectThread() throws Exception {
        // Setup domain and blob
        JWSDomain mockJwsDomain = mock(JWSDomain.class);
        when(mockStorage.get(TEST_BUCKET_NAME, TEST_DOMAIN)).thenReturn(mockBlob);
        when(mockBlob.getContent()).thenReturn(TEST_DOMAIN_CONTENT.getBytes());
        when(mockBlob.getUpdateTimeOffsetDateTime()).thenReturn(OffsetDateTime.now());

        stateFileBuilder = new GcsStateFileBuilder(TEST_PROJECT_ID, TEST_BUCKET_NAME, mockDomainValidator);

        Map<String, JWSDomainData> jwsDomainMap = new HashMap<String, JWSDomainData>();

        // Create an instance of BucketObjectThread using reflection
        Object bucketThread = stateFileBuilder.new BucketObjectThread(mockStorage, TEST_BUCKET_NAME, TEST_DOMAIN, jwsDomainMap);

        // Call run method
        java.lang.reflect.Method runMethod = bucketThread.getClass().getDeclaredMethod("run");
        runMethod.setAccessible(true);
        runMethod.invoke(bucketThread);

        // Verify storage was accessed
        verify(mockStorage).get(TEST_BUCKET_NAME, TEST_DOMAIN);
        verify(mockBlob).getContent();
    }

    @Test
    public void testBucketObjectThreadInvalidContent() throws Exception {
        // Setup domain and blob
        JWSDomain mockJwsDomain = mock(JWSDomain.class);
        when(mockStorage.get(TEST_BUCKET_NAME, TEST_DOMAIN)).thenReturn(mockBlob);
        when(mockBlob.getContent()).thenReturn("{invalid json}".getBytes());
        when(mockBlob.getUpdateTimeOffsetDateTime()).thenReturn(OffsetDateTime.now());

        stateFileBuilder = new GcsStateFileBuilder(TEST_PROJECT_ID, TEST_BUCKET_NAME, mockDomainValidator);

        Map<String, JWSDomainData> jwsDomainMap = new HashMap<String, JWSDomainData>();

        // Create an instance of BucketObjectThread using reflection
        Object bucketThread = stateFileBuilder.new BucketObjectThread(mockStorage, TEST_BUCKET_NAME, TEST_DOMAIN, jwsDomainMap);

        // Call run method
        java.lang.reflect.Method runMethod = bucketThread.getClass().getDeclaredMethod("run");
        runMethod.setAccessible(true);
        runMethod.invoke(bucketThread);

        assertEquals(jwsDomainMap.size(), 0);

        // Verify storage was accessed
        verify(mockStorage).get(TEST_BUCKET_NAME, TEST_DOMAIN);
        verify(mockBlob).getContent();
    }

    @Test
    public void testBucketObjectThreadBlobNotFound() throws Exception {
        // Setup null blob (not found case)
        when(mockStorage.get(TEST_BUCKET_NAME, TEST_DOMAIN)).thenReturn(null);

        stateFileBuilder = new GcsStateFileBuilder(TEST_PROJECT_ID, TEST_BUCKET_NAME, mockDomainValidator);

        // Create an instance of BucketObjectThread using reflection
        Object bucketThread = stateFileBuilder.new BucketObjectThread(mockStorage, TEST_BUCKET_NAME, TEST_DOMAIN,
                Collections.synchronizedMap(Collections.emptyMap()));

        // Call run method
        java.lang.reflect.Method runMethod = bucketThread.getClass().getDeclaredMethod("run");
        runMethod.setAccessible(true);
        runMethod.invoke(bucketThread);

        // Verify storage was accessed
        verify(mockStorage).get(TEST_BUCKET_NAME, TEST_DOMAIN);
    }
}