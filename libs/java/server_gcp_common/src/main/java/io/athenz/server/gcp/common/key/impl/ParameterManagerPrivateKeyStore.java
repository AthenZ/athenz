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

import com.google.cloud.parametermanager.v1.*;
import com.google.protobuf.Timestamp;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.util.PrivateKeyStoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.Comparator;
import java.util.stream.StreamSupport;

public class ParameterManagerPrivateKeyStore implements PrivateKeyStore {
    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static String CLOUD_NAME = "gcp";

    private final ParameterManagerClient client;
    private final String projectId;
    private final String location;

    private static final Comparator<Timestamp> TIMESTAMP_COMPARATOR = Comparator
            .comparingLong(Timestamp::getSeconds)
            .thenComparingInt(Timestamp::getNanos);

    ParameterManagerPrivateKeyStore(final ParameterManagerClient parameterManagerClient, String projectId, String location) {
        this.client = parameterManagerClient;
        this.projectId = projectId;
        this.location = location;
    }

    @Override
    public char[] getSecret(String appName, String keygroupName, String keyName) {
        return getParameter(keyName).toCharArray();
    }

    @Override
    public ServerPrivateKey getPrivateKey(String service, String serverHostName, String serverRegion, String algorithm) {
        return PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(CLOUD_NAME, service, serverRegion, algorithm, this::getParameter);
    }

    /**
     * Retrieve the parameter value for the given parameter name.
     * If the parameter does not exist, an empty string is returned.
     *
     * Implementation note: "latest" is a keyword in Parameter Manager for versions, and currently, we are not able to
     * fetch the latest version using "latest" alias. Therefore, we retrieve the latest version of the parameter by
     * listing all versions and selecting the one with the most recent createTime.
     *
     * @param parameter The name of the parameter to retrieve.
     * @return The value of the parameter as a String, or an empty string if not found.
     */
    public String getParameter(String parameter) {
        LOG.info("getParameter: {}", parameter);
        ParameterVersion latestParameterVersion = getLatestParameterVersion(parameter);

        if (latestParameterVersion == null) {
            LOG.error("Latest version for Parameter '{}' not found in project '{}', location '{}'", parameter, projectId, location);
            return "";
        }

        return client.getParameterVersion(latestParameterVersion.getName()).getPayload().getData().toStringUtf8();
    }

    public ParameterVersion getLatestParameterVersion(String parameter) {
        LOG.info("getLatestParameterVersion: {}", parameter);

        // Build the parameter name from the project and parameter ID.
        ParameterName parameterName = ParameterName.of(projectId, location, parameter);

        // Build the request to list parameter versions.
        ListParameterVersionsRequest listParameterVersionsRequest =
                ListParameterVersionsRequest
                        .newBuilder()
                        .setParent(parameterName.toString())
                        .build();

        // Send the request and get the response.
        ParameterManagerClient.ListParameterVersionsPagedResponse listParameterVersionsPagedResponse = client.listParameterVersions(listParameterVersionsRequest);

        // Iterate through all versions and find the latest one based on createTime.
        return StreamSupport
                .stream(listParameterVersionsPagedResponse.iterateAll().spliterator(), false)
                .max(Comparator.comparing(ParameterVersion::getCreateTime, TIMESTAMP_COMPARATOR))
                .orElse(null);
    }
}
