/*
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.common.server.util.config.providers;

import com.amazonaws.util.EC2MetadataUtils;
import com.yahoo.athenz.common.server.util.Utils;
import com.yahoo.athenz.common.server.util.config.ConfigEntry;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.lang.invoke.MethodHandles;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * A provider for configurations from AWS Parameters-Store. <br>
 * <b>NOTE:</b> AWS stores parameters PER REGION ! <br>
 * The simplest provider-description is "aws-param-store://" - which gets all parameters. <br>
 * To get parameters under the path "/my/project" - use provider-description is "aws-param-store:///my/project"
 *  (the config-names will not include the "/my/project/" prefix).
 */
public class ConfigProviderAwsParametersStore extends ConfigProvider {

    public static final String PROVIDER_DESCRIPTION_PREFIX = "aws-param-store://";

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    @Override
    public @Nullable ConfigSourceAwsParametersStore tryToBuildConfigSource(String sourceDescription) {
        // Check if the provider-description matches "aws-param-store://...path..."
        if (!sourceDescription.startsWith(PROVIDER_DESCRIPTION_PREFIX)) {
            return null;
        }
        return new ConfigSourceAwsParametersStore(sourceDescription, sourceDescription.substring(PROVIDER_DESCRIPTION_PREFIX.length()));
    }

    public static class ConfigSourceAwsParametersStore extends ConfigSource {

        public final String path;
        public final String parameterNamesRedundantPrefix;
        private final SsmClient ssmClient;

        public ConfigSourceAwsParametersStore(String sourceDescription, String path) {
            super(sourceDescription);

            // Path must start with "/" - add it if not.
            if (!path.startsWith("/")) {
                path = "/" + path;
            }
            this.path = path;

            // Queried parameter-names starts with the path, then "/", then the relevant part.
            if (!path.endsWith("/")) {
                path += "/";
            }
            parameterNamesRedundantPrefix = path;

            ssmClient = SsmClient.builder()
                    .region(Region.of(EC2MetadataUtils.getInstanceInfo().getRegion()))
                    .build();
        }

        /** Get all configuration entries of the source */
        @Override
        public Collection<ConfigEntry> getConfigEntries() {

            List<ConfigEntry> configEntries = new LinkedList<>();
            LOG.debug("Reading configurations page 1 from {}", this);
            GetParametersByPathResponse result = ssmClient.getParametersByPath(GetParametersByPathRequest.builder().path(path).recursive(true).build());
            for (int page = 2; ; page++) {
                for (Parameter parameter : result.parameters()) {

                    // Remove the path from the parameter-name
                    String parameterName = parameter.name();
                    if (parameterName.startsWith(parameterNamesRedundantPrefix)) {
                        parameterName = parameterName.substring(parameterNamesRedundantPrefix.length());
                    }

                    configEntries.add(new ConfigEntry(
                            parameterName,
                            parameter.value(),
                            this,
                            null));
                }

                // Proceed to next page?
                if (result.nextToken() == null) {
                    break;
                } else {
                    LOG.debug("Reading configurations page {} from {}", page, this);
                    result = ssmClient.getParametersByPath(GetParametersByPathRequest.builder().path(path).nextToken(result.nextToken()).build());
                }
            }

            return configEntries;
        }

        @Override
        public String toString() {
            return "AWS-Parameters-Store path " + Utils.jsonSerializeForLog(path);
        }
    }
}
