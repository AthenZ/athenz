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

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Configuration for a specific port including mTLS requirements and allowed endpoints.
 */
public class PortConfig {

    private int port;
    @JsonProperty("mtls_required")
    private boolean mtlsRequired;
    private String description;
    @JsonProperty("allowed_endpoints")
    private List<EndpointConfig> allowedEndpoints;

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public boolean isMtlsRequired() {
        return mtlsRequired;
    }

    public void setMtlsRequired(boolean mtlsRequired) {
        this.mtlsRequired = mtlsRequired;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<EndpointConfig> getAllowedEndpoints() {
        return allowedEndpoints;
    }

    public void setAllowedEndpoints(List<EndpointConfig> allowedEndpoints) {
        this.allowedEndpoints = allowedEndpoints;
    }
}
