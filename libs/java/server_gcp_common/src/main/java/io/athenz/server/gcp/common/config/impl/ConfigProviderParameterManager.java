/*
 * Copyright The Athenz Authors.
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
package io.athenz.server.gcp.common.config.impl;

import com.google.cloud.parametermanager.v1.*;
import com.yahoo.athenz.common.server.util.config.ConfigEntry;
import com.yahoo.athenz.common.server.util.config.providers.ConfigProvider;
import io.athenz.server.gcp.common.utils.ParameterManagerClientHelper;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static io.athenz.server.gcp.common.Consts.*;

/**
 * A configuration provider implementation that retrieves configuration parameters from Google Cloud's Parameter Manager.
 * <p>
 * This provider connects to the GCP Parameter Manager service to fetch configuration values stored as parameters.
 * It uses a specific URI format "gcp-param-manager://" followed by a path to identify parameter sources.
 * <p>
 * The provider relies on the following system properties for configuration:
 * <ul>
 *   <li>{@code athenz.gcp.location} - The GCP location (defaults to "global")</li>
 *   <li>{@code athenz.gcp.project_id} - The GCP project ID (defaults to a predefined value)</li>
 * </ul>
 * <p>
 * Parameters retrieved from GCP Parameter Manager are transformed into {@link ConfigEntry} objects
 * with keys derived from their parameter names, using appropriate prefix trimming logic.
 */
public class ConfigProviderParameterManager extends ConfigProvider {

    public static final String PROVIDER_DESCRIPTION_PREFIX = "gcp-param-manager://";

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Override
    public @Nullable ConfigSourceParameterManager tryToBuildConfigSource(String sourceDescription) {
        if (!sourceDescription.startsWith(PROVIDER_DESCRIPTION_PREFIX)) {
            return null;
        }
        String location = System.getProperty(ATHENZ_PROP_GCP_LOCATION, GLOBAL_LOCATION);
        String projectId = System.getProperty(ATHENZ_PROP_GCP_PROJECT_ID);
        if (projectId == null) {
            throw new IllegalArgumentException("GCP project ID must be set via system property: " + ATHENZ_PROP_GCP_PROJECT_ID);
        }
        return new ConfigSourceParameterManager(
                sourceDescription,
                sourceDescription.substring(PROVIDER_DESCRIPTION_PREFIX.length()),
                projectId,
                location,
                buildClient(location));
    }

    protected ParameterManagerClient buildClient(String location) {
        try {
            return ParameterManagerClientHelper.createParameterManagerClient(location);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create ParameterManagerClient in ConfigProviderParameterManager", e);
        }
    }

    public static class ConfigSourceParameterManager extends ConfigSource {
        private final ParameterManagerClient client;
        private final String projectId;
        private final LocationName locationName;
        private final String parameterFullPrefix;

        public ConfigSourceParameterManager(String sourceDescription, String redundantPrefix, String projectId, String location, ParameterManagerClient client) {
            super(sourceDescription);
            this.projectId = projectId;
            this.locationName = LocationName.of(this.projectId, location);
            this.client = client;

            if (!redundantPrefix.endsWith("--")) {
                // Ensure the redundantPrefix ends with "--" to match the expected format.
                // Expected format: "location--system--key"
                redundantPrefix += "--";
            }

            this.parameterFullPrefix = String.format("%s/parameters/%s", locationName.toString(), redundantPrefix);

            LOG.info("Building ConfigSourceParameterManager, sourceDescription: {}, redundantPrefix: {}, projectId: {}, location: {}",
                    sourceDescription, redundantPrefix, projectId, location);
        }

        /** Get all configuration entries of the source */
        @Override
        public Collection<ConfigEntry> getConfigEntries() {
            LOG.debug("getConfigEntries, location: {}", locationName.toString());

            // Get all parameters.
            ParameterManagerClient.ListParametersPagedResponse response = client.listParameters(locationName.toString());

            // Fetch parameters that start with the parameterFullPrefix.
            List<Parameter> parameters = StreamSupport.stream(response.iterateAll().spliterator(), false)
                    .filter(parameter -> parameter.getName().startsWith(parameterFullPrefix))
                    .collect(Collectors.toList());

            // Return a list of ConfigEntry objects created from the latest versions of the matched parameters.
            return parameters.stream()
                    .map(this::makeConfigEntry)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
        }

        ConfigEntry makeConfigEntry(Parameter parameter) {
            try {
                ParameterVersion latestParameterVersion = ParameterManagerClientHelper.getLatestParameterVersion(
                        client,
                        ParameterName.parse(parameter.getName())
                );

                if (latestParameterVersion == null) {
                    LOG.error("Latest version for Parameter '{}' not found in project '{}', location '{}'", parameter.getName(), projectId, locationName.getLocation());
                    return null;
                }

                return new ConfigEntry(
                        trimPrefixAndReplaceHyphen(parameter.getName(), parameterFullPrefix),
                        client.getParameterVersion(latestParameterVersion.getName()).getPayload().getData().toStringUtf8(),
                        this,
                        ""
                );

            } catch (Exception e) {
                LOG.error("Failed to get parameter version for: {}", parameter.getName(), e);
                return null;
            }
        }

        @Override
        public String toString() {
            return "GCP-Parameters-Manager projectId: " + projectId + ", location: " + locationName.getLocation() + ", parameterFullPrefix: " + parameterFullPrefix;
        }

        public ParameterManagerClient getClient() {
            return client;
        }

        public String getProjectId() {
            return projectId;
        }

        public LocationName getLocationName() {
            return locationName;
        }

        public String getParameterFullPrefix() {
            return parameterFullPrefix;
        }
    }

    // Sample format: "{location}--{system}--{keyWithHyphens}"
    // ex: "us-west1--zts--athenz-zts-read_only" to model "athenz.zts.read_only" property for "us-west1" region for "zts" system.
    public static String trimPrefixAndReplaceHyphen(String name, String prefix) {
        return name.substring(prefix.length()).replace('-', '.');
    }
}
