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
package com.yahoo.athenz.container.config;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;

import java.util.Collections;
import java.util.List;

/**
 * Root configuration object for port-uri mappings.
 * Represents the structure of port-uri.json configuration file.
 * The ports list is never null - it's either populated or an empty list.
 * Supports both empty JSON "{}" and explicit empty array {"ports": []}.
 */
public class PortUriConfiguration {

    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private List<PortConfig> ports = Collections.emptyList();

    public List<PortConfig> getPorts() {
        return ports;
    }

    public void setPorts(List<PortConfig> ports) {
        this.ports = (ports != null) ? ports : Collections.emptyList();
    }

    /**
     * Get port configuration for a specific port number
     *
     * @param port the port number to look up
     * @return PortConfig for the port, or null if not found
     */
    public PortConfig getPortConfig(int port) {
        return ports.stream()
                .filter(p -> p.getPort() == port)
                .findFirst()
                .orElse(null);
    }

    /**
     * Check if a port allows all endpoints (unrestricted)
     *
     * @param port the port number to check
     * @return true if port is unrestricted (empty allowed_endpoints array)
     */
    public boolean isPortUnrestricted(int port) {
        PortConfig config = getPortConfig(port);
        return config != null &&
                (config.getAllowedEndpoints() == null ||
                config.getAllowedEndpoints().isEmpty());
    }
}
