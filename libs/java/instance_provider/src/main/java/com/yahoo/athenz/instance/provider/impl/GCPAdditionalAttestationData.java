/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.instance.provider.impl;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;

import java.math.BigDecimal;

/**
 * GCPAdditionalAttestationData - additional information a booting
 * instance should provide to ZTS to authenticate.
 */

public class GCPAdditionalAttestationData {

    @Expose
    private BigDecimal instanceCreationTimestamp;

    @Expose
    private String instanceId;

    @Expose
    private String instanceName;

    @Expose
    private String projectId;

    @Expose
    private String projectNumber;

    @Expose
    private String zone;

    public BigDecimal getInstanceCreationTimestamp() {
        return instanceCreationTimestamp;
    }

    @JsonProperty("instance_creation_timestamp")
    public void setInstanceCreationTimestamp(BigDecimal instanceCreationTimestamp) {
        this.instanceCreationTimestamp = instanceCreationTimestamp;
    }

    public String getInstanceId() {
        return instanceId;
    }

    @JsonProperty("instance_id")
    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    public String getInstanceName() {
        return instanceName;
    }

    @JsonProperty("instance_name")
    public void setInstanceName(String instanceName) {
        this.instanceName = instanceName;
    }

    public String getProjectId() {
        return projectId;
    }

    @JsonProperty("project_id")
    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

    public String getProjectNumber() {
        return projectNumber;
    }

    @JsonProperty("project_number")
    public void setProjectNumber(String projectNumber) {
        this.projectNumber = projectNumber;
    }

    public String getZone() {
        return zone;
    }

    public void setZone(String zone) {
        this.zone = zone;
    }
}
