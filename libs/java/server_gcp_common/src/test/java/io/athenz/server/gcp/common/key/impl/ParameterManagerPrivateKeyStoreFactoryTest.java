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
package io.athenz.server.gcp.common.key.impl;

import com.google.cloud.parametermanager.v1.ParameterManagerClient;
import com.google.cloud.parametermanager.v1.ParameterManagerSettings;
import com.yahoo.athenz.auth.PrivateKeyStore;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.*;

public class ParameterManagerPrivateKeyStoreFactoryTest {
    @Test
    public void testCreate_Success() {
        ParameterManagerPrivateKeyStoreFactory factory = new ParameterManagerPrivateKeyStoreFactory();
        try (MockedStatic<ParameterManagerClient> mocked = mockStatic(ParameterManagerClient.class)) {
            ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
            mocked.when(ParameterManagerClient::create).thenReturn(mockClient);

            PrivateKeyStore store = factory.create();
            assertNotNull(store);
            assertTrue(store instanceof ParameterManagerPrivateKeyStore);
        }
    }

    @Test
    public void testCreate_NonGlobalLocation() {
        System.setProperty("athenz.gcp.location", "us-central1");
        ParameterManagerPrivateKeyStoreFactory factory = new ParameterManagerPrivateKeyStoreFactory();
        try (MockedStatic<ParameterManagerClient> mocked = mockStatic(ParameterManagerClient.class)) {
            ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
            mocked.when(() -> ParameterManagerClient.create(any(ParameterManagerSettings.class))).thenReturn(mockClient);

            PrivateKeyStore store = factory.create();
            assertNotNull(store);
            assertTrue(store instanceof ParameterManagerPrivateKeyStore);
        } finally {
            System.clearProperty("athenz.gcp.location");
        }
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testCreate_Failure() throws IOException {
        ParameterManagerPrivateKeyStoreFactory factory = new ParameterManagerPrivateKeyStoreFactory();
        try (MockedStatic<ParameterManagerClient> mocked = mockStatic(ParameterManagerClient.class)) {
            mocked.when(ParameterManagerClient::create).thenThrow(new IOException("fail"));
            factory.create();
        }
    }
}