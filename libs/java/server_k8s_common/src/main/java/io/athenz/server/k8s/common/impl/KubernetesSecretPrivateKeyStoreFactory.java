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
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import io.kubernetes.client.util.Config;

public class KubernetesSecretPrivateKeyStoreFactory implements PrivateKeyStoreFactory {
    @Override
    public PrivateKeyStore create() {
        try {
            return new KubernetesSecretPrivateKeyStore(Config.defaultClient());
        } catch (Exception ex) {
            throw new RuntimeException("Unable to create KubernetesSecretPrivateKeyStore", ex);
        }
    }
}
