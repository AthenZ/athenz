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
    private String description;

    @JsonProperty("mtls_required")
    private boolean mtlsRequired;

    @JsonProperty("sni_required")
    private boolean sniRequired;

    @JsonProperty("sni_host_check")
    private boolean sniHostCheck;

    @JsonProperty("allowed_endpoints")
    private List<EndpointConfig> allowedEndpoints;

    /**
     * Optional per-port PROXY protocol setting. When null (not specified in
     * port-uri.json) the port inherits the global athenz.proxy_protocol value.
     * Set it to true only on a listener that is reachable exclusively through a
     * trusted L4 proxy (e.g. a Cloudflare Spectrum origin port): any peer that can
     * reach a PROXY-enabled port can forge the client address in the header.
     */
    @JsonProperty("proxy_protocol")
    private Boolean proxyProtocol;

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

    public boolean isSniRequired() {
        return sniRequired;
    }

    public void setSniRequired(boolean sniRequired) {
        this.sniRequired = sniRequired;
    }

    public boolean isSniHostCheck() {
        return sniHostCheck;
    }

    public void setSniHostCheck(boolean sniHostCheck) {
        this.sniHostCheck = sniHostCheck;
    }

    public Boolean getProxyProtocol() {
        return proxyProtocol;
    }

    public void setProxyProtocol(Boolean proxyProtocol) {
        this.proxyProtocol = proxyProtocol;
    }

    /**
     * @param defaultValue the global athenz.proxy_protocol setting
     * @return the per-port value if specified, otherwise the global default
     */
    public boolean isProxyProtocolEnabled(boolean defaultValue) {
        return proxyProtocol != null ? proxyProtocol : defaultValue;
    }
}
