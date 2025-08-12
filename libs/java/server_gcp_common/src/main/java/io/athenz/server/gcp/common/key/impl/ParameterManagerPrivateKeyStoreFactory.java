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

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;

import java.io.IOException;

import static io.athenz.server.gcp.common.Consts.*;
import static io.athenz.server.gcp.common.utils.ParameterManagerClientHelper.createParameterManagerClient;

public class ParameterManagerPrivateKeyStoreFactory implements PrivateKeyStoreFactory {
    @Override
    public PrivateKeyStore create() {
        String projectId = System.getProperty(ATHENZ_PROP_GCP_PROJECT_ID, "default-project-id");
        String location = System.getProperty(ATHENZ_PROP_GCP_LOCATION, GLOBAL_LOCATION);
        try {
            return new ParameterManagerPrivateKeyStore(createParameterManagerClient(location), projectId, location);
        } catch (IOException ex) {
            throw new RuntimeException("Failed to create ParameterManagerClient in ParameterManagerPrivateKeyStore", ex);
        }
    }
}
