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

import com.google.cloud.storage.*;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class GcsDomainStoreTest {

    @Mock
    private Storage mockStorage;

    @Mock
    private StorageOptions.Builder mockBuilder;

    @Mock
    private StorageOptions mockOptions;

    @Mock
    private Blob mockBlob;

    private GcsDomainStore domainStore;
    private static final String TEST_PROJECT = "test-project";
    private static final String TEST_BUCKET = "test-bucket";
    private static final String TEST_DOMAIN = "domain1";
    private static final String TEST_JSON = "{\"domain\":\"test\"}";
    private AutoCloseable closeable;
    private MockedStatic<StorageOptions> mockedStorageOptions;

    @BeforeMethod
    public void setUp() {
        closeable = MockitoAnnotations.openMocks(this);

        // Set up the mock StorageOptions chain
        mockedStorageOptions = Mockito.mockStatic(StorageOptions.class);
        mockedStorageOptions.when(StorageOptions::newBuilder).thenReturn(mockBuilder);
        when(mockBuilder.setProjectId(TEST_PROJECT)).thenReturn(mockBuilder);
        when(mockBuilder.build()).thenReturn(mockOptions);
        when(mockOptions.getService()).thenReturn(mockStorage);

        // Create the domain store with our test values
        domainStore = new GcsDomainStore(TEST_PROJECT, TEST_BUCKET);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (mockedStorageOptions != null) {
            mockedStorageOptions.close();
        }
        if (closeable != null) {
            closeable.close();
        }
    }

    @Test
    public void testConstructor_NullProjectId() {
        try {
            new GcsDomainStore(null, TEST_BUCKET);
            fail("Expected NullPointerException");
        } catch (NullPointerException e) {
            // Expected
        }
    }

    @Test
    public void testConstructor_NullBucketName() {
        try {
            new GcsDomainStore(TEST_PROJECT, null);
            fail("Expected NullPointerException");
        } catch (NullPointerException e) {
            // Expected
        }
    }

    @Test
    public void testUploadDomain() {
        // Arrange
        byte[] content = TEST_JSON.getBytes(StandardCharsets.UTF_8);

        // Act
        domainStore.uploadDomain(TEST_DOMAIN, TEST_JSON);

        // Assert
        verify(mockStorage).create(argThat(info ->
                        info.getBlobId().getBucket().equals(TEST_BUCKET) &&
                                info.getBlobId().getName().equals(TEST_DOMAIN)),
                eq(content));
    }

    @Test
    public void testDeleteDomain_Success() {
        // Arrange
        BlobId blobId = BlobId.of(TEST_BUCKET, TEST_DOMAIN);
        when(mockStorage.get(TEST_BUCKET, TEST_DOMAIN)).thenReturn(mockBlob);
        when(mockBlob.getBlobId()).thenReturn(blobId);

        // Act
        domainStore.deleteDomain(TEST_DOMAIN);

        // Assert
        verify(mockStorage).get(TEST_BUCKET, TEST_DOMAIN);
        verify(mockStorage).delete(blobId);
    }

    @Test
    public void testDeleteDomain_NotFound() {
        // Arrange
        when(mockStorage.get(TEST_BUCKET, TEST_DOMAIN)).thenReturn(null);

        // Act
        domainStore.deleteDomain(TEST_DOMAIN);

        // Assert
        verify(mockStorage).get(TEST_BUCKET, TEST_DOMAIN);
        verify(mockStorage, never()).delete(any(BlobId.class));
    }
}