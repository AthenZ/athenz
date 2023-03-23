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
package com.yahoo.athenz.zts.utils;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.ALWAYS)
public class IPPrefix {

    @JsonProperty("ip_prefix")
    @JsonAlias("ipv4Prefix")
    private String ipv4Prefix;

    @JsonProperty("ipv6_prefix")
    @JsonAlias("ipv6Prefix")
    private String ipv6Prefix;

    @JsonProperty("region")
    @JsonAlias("scope")
    private String region;

    private String service;

    public String getIpv4Prefix() {
        return ipv4Prefix;
    }

    public void setIpv4Prefix(String ipv4Prefix) {
        this.ipv4Prefix = ipv4Prefix;
    }

    public String getIpv6Prefix() {
        return ipv6Prefix;
    }

    public void setIpv6Prefix(String ipv6Prefix) {
        this.ipv6Prefix = ipv6Prefix;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }
}
