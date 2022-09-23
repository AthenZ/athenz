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
package com.yahoo.athenz.instance.provider.impl;

public class AzureVmDetails {

    private String name;
    private String location;
    private AzureVmTags tags;
    private AzureVmIdentity identity;
    private AzureVmProperties properties;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public AzureVmIdentity getIdentity() {
        return identity;
    }

    public void setIdentity(AzureVmIdentity identity) {
        this.identity = identity;
    }

    public AzureVmProperties getProperties() {
        return properties;
    }

    public void setProperties(AzureVmProperties properties) {
        this.properties = properties;
    }

    public AzureVmTags getTags() {
        return tags;
    }

    public void setTags(AzureVmTags tags) {
        this.tags = tags;
    }
}
