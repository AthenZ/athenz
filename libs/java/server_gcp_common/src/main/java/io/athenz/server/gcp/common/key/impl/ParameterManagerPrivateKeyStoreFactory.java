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
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;

import java.io.IOException;

public class ParameterManagerPrivateKeyStoreFactory implements PrivateKeyStoreFactory {
    public static final String ATHENZ_PROP_GCP_PROJECT_ID = "athenz.gcp.project_id";
    public static final String ATHENZ_PROP_GCP_LOCATION = "athenz.gcp.location";
    public static final String GLOBAL_LOCATION = "global";

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

    public static ParameterManagerClient createParameterManagerClient(String location) throws IOException {
        if (isGlobalLocation(location)) {
            return ParameterManagerClient.create();
        }

        String apiEndpoint = String.format("parametermanager.%s.rep.googleapis.com:443", location);

        ParameterManagerSettings parameterManagerSettings =
                ParameterManagerSettings.newBuilder().setEndpoint(apiEndpoint).build();

        return ParameterManagerClient.create(parameterManagerSettings);
    }

    public static boolean isGlobalLocation(String location) {
        return GLOBAL_LOCATION.equalsIgnoreCase(location);
    }
}
