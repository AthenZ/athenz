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
package io.athenz.server.gcp.common.utils;

import com.google.cloud.parametermanager.v1.*;
import com.google.protobuf.Timestamp;

import java.io.IOException;
import java.util.Comparator;
import java.util.stream.StreamSupport;

import static io.athenz.server.gcp.common.Consts.GLOBAL_LOCATION;

public class ParameterManagerClientHelper {
    private static final Comparator<Timestamp> TIMESTAMP_COMPARATOR = Comparator
            .comparingLong(Timestamp::getSeconds)
            .thenComparingInt(Timestamp::getNanos);


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

    public static ParameterVersion getLatestParameterVersion(ParameterManagerClient client, ParameterName parameterName) {
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

    public static ParameterVersion getLatestParameterVersion(ParameterManagerClient client, String projectId, String location, String parameter) {
        return getLatestParameterVersion(client, ParameterName.of(projectId, location, parameter));
    }
}
