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

import io.athenz.syncer.common.zms.CloudDomainStore;
import io.athenz.syncer.common.zms.Config;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class GcsDomainStoreFactoryTest {

    private static final String TEST_PROJECT_ID = "test-project";
    private static final String TEST_BUCKET_NAME = "test-bucket";

    @Test
    public void testCreate_Success() {
        try (MockedStatic<Config> mockedConfig = mockStatic(Config.class)) {
            // Mock Config
            Config mockConfig = mock(Config.class);
            mockedConfig.when(Config::getInstance).thenReturn(mockConfig);
            when(mockConfig.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_PROJECT_ID)).thenReturn(TEST_PROJECT_ID);
            when(mockConfig.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_BUCKET_NAME)).thenReturn(TEST_BUCKET_NAME);

            // Create the factory
            GcsDomainStoreFactory factory = new GcsDomainStoreFactory();

            // Call create()
            CloudDomainStore store = factory.create();

            // Verify the returned object is a GcsDomainStore
            assertNotNull(store);
            assertTrue(store instanceof GcsDomainStore);
        }
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testCreate_Exception() {
        try (MockedStatic<Config> mockedConfig = mockStatic(Config.class);
             MockedConstruction<GcsDomainStore> mockedConstruction = mockConstruction(
                     GcsDomainStore.class, (mock, context) -> {
                         throw new IllegalStateException("Test exception");
                     })) {

            // Mock Config
            Config mockConfig = mock(Config.class);
            mockedConfig.when(Config::getInstance).thenReturn(mockConfig);
            when(mockConfig.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_PROJECT_ID)).thenReturn(TEST_PROJECT_ID);
            when(mockConfig.getConfigParam(GcsConsts.SYNC_CFG_PARAM_GCP_BUCKET_NAME)).thenReturn(TEST_BUCKET_NAME);

            // Create the factory
            GcsDomainStoreFactory factory = new GcsDomainStoreFactory();

            // Call create() - should throw RuntimeException
            factory.create();
        }
    }
}