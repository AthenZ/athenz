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
package com.yahoo.athenz.instance.provider;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Map;
import com.yahoo.rdl.*;

public class InstanceConfirmation {
    private String provider;
    private String domain;
    private String service;
    private String attestationData;
    @RdlOptional
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Map<String, String> attributes;

    public InstanceConfirmation setProvider(String provider) {
        this.provider = provider;
        return this;
    }
    public String getProvider() {
        return provider;
    }
    public InstanceConfirmation setDomain(String domain) {
        this.domain = domain;
        return this;
    }
    public String getDomain() {
        return domain;
    }
    public InstanceConfirmation setService(String service) {
        this.service = service;
        return this;
    }
    public String getService() {
        return service;
    }
    public InstanceConfirmation setAttestationData(String attestationData) {
        this.attestationData = attestationData;
        return this;
    }
    public String getAttestationData() {
        return attestationData;
    }
    public InstanceConfirmation setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
        return this;
    }
    public Map<String, String> getAttributes() {
        return attributes;
    }

    @Override
    public boolean equals(Object another) {
        if (this != another) {
            if (another == null || another.getClass() != InstanceConfirmation.class) {
                return false;
            }
            InstanceConfirmation a = (InstanceConfirmation) another;
            if (provider == null ? a.provider != null : !provider.equals(a.provider)) {
                return false;
            }
            if (domain == null ? a.domain != null : !domain.equals(a.domain)) {
                return false;
            }
            if (service == null ? a.service != null : !service.equals(a.service)) {
                return false;
            }
            if (attestationData == null ? a.attestationData != null : !attestationData.equals(a.attestationData)) {
                return false;
            }
            return attributes == null ? a.attributes == null : attributes.equals(a.attributes);
        }
        return true;
    }
}
