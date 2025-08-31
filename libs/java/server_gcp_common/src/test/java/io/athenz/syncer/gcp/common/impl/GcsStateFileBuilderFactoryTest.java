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

import com.google.cloud.storage.StorageOptions;
import io.athenz.syncer.common.zms.Config;
import io.athenz.syncer.common.zms.StateFileBuilder;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class GcsStateFileBuilderFactoryTest {

    private static final String TEST_PROJECT_ID = "test-project-id";
    private static final String TEST_BUCKET_NAME = "test-bucket-name";

    private MockedStatic<Config> mockedConfig;
    private Config mockConfigInstance;
    private GcsStateFileBuilderFactory factory;

    @BeforeMethod
    public void setUp() {
        // Mock Config singleton
        mockedConfig = Mockito.mockStatic(Config.class);
        mockConfigInstance = mock(Config.class);
        mockedConfig.when(Config::getInstance).thenReturn(mockConfigInstance);

        when(mockConfigInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS)).thenReturn("10");
        when(mockConfigInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT)).thenReturn("1800");

        // Create factory instance
        factory = new GcsStateFileBuilderFactory();
    }

    @AfterMethod
    public void tearDown() {
        if (mockedConfig != null) {
            mockedConfig.close();
        }
    }

    @Test
    public void testCreateSuccess() {
        // Arrange
        when(mockConfigInstance.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_PROJECT_ID))
                .thenReturn(TEST_PROJECT_ID);
        when(mockConfigInstance.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_BUCKET_NAME))
                .thenReturn(TEST_BUCKET_NAME);

        // Act
        StateFileBuilder builder = factory.create();

        // Assert
        assertNotNull(builder, "Builder should not be null");
        assertTrue(builder instanceof GcsStateFileBuilder, "Builder should be instance of GcsStateFileBuilder");

        // Verify Config was called with correct parameters
        verify(mockConfigInstance).getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_PROJECT_ID);
        verify(mockConfigInstance).getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_BUCKET_NAME);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testCreateFailure() {
        // Arrange
        when(mockConfigInstance.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_PROJECT_ID))
                .thenThrow(new RuntimeException("Config error"));

        // Act & Assert - should throw RuntimeException
        factory.create();
    }

    @Test
    public void testCreateWithMissingProjectId() {
        // Arrange
        when(mockConfigInstance.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_PROJECT_ID))
                .thenReturn(null).thenReturn("");
        when(mockConfigInstance.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_BUCKET_NAME))
                .thenReturn(TEST_BUCKET_NAME);

        // 1. null project id
        try {
            factory.create();
            fail();
        } catch (RuntimeException e) {
            // expected
        }

        // 2. "" project id
        try {
            factory.create();
            fail();
        } catch (Exception e) {
            // expected
        }

    }

    @Test
    public void testCreateWithMissingBucketName() {
        // Arrange
        when(mockConfigInstance.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_PROJECT_ID))
                .thenReturn(TEST_PROJECT_ID);
        when(mockConfigInstance.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_BUCKET_NAME))
                .thenReturn(null).thenReturn("");

        // 1. null bucket name
        try {
            factory.create();
            fail();
        } catch (RuntimeException e) {
            // expected
        }

        // 2. "" bucket name
        try {
            factory.create();
            fail();
        } catch (Exception e) {
            // expected
        }
    }

    @Test
    public void testStorageOptions() {
        StorageOptions.newBuilder().setProjectId(null).build().getService();
    }
}