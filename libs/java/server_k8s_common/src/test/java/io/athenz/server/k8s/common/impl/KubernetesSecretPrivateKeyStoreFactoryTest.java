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
package io.athenz.server.k8s.common.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import io.kubernetes.client.util.Config;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class KubernetesSecretPrivateKeyStoreFactoryTest {
    @Test
    public void createKubernetesSecretPrivateKeyStore() {
        PrivateKeyStore privateKeyStore = new KubernetesSecretPrivateKeyStoreFactory().create();
        assertTrue(privateKeyStore instanceof KubernetesSecretPrivateKeyStore);
    }

    @Test
    public void createKubernetesSecretPrivateKeyStoreException() {
        try (MockedStatic<Config> configMockedStatic = Mockito.mockStatic(Config.class)) {
            configMockedStatic.when(Config::defaultClient).thenThrow(new RuntimeException("mocked exception"));
            try {
                new KubernetesSecretPrivateKeyStoreFactory().create();
                fail();
            } catch (RuntimeException ex) {
                assertTrue(ex.getMessage().contains("Unable to create KubernetesSecretPrivateKeyStore"));
            }
        }
    }
}
