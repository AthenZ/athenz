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

package com.yahoo.athenz.common.server.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;

public class Utils {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigProperties.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /** Convert a value to JSON - or return a human-readable error if failed */
    public static String jsonSerializeForLog(Object value) {
        try {
            return OBJECT_MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            return "=== Can't JSON-ize a " + value.getClass().getName() + " ===";
        }
    }

    public static Region getAwsRegion(Region defaultRegion) {
        try {
            DefaultAwsRegionProviderChain regionProvider = DefaultAwsRegionProviderChain.builder().build();
            return regionProvider.getRegion();
        } catch (Exception ex) {
            LOGGER.error("Unable to determine AWS region", ex);
        }
        return defaultRegion;
    }
}
