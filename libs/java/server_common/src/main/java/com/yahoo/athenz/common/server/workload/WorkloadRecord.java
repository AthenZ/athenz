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
package com.yahoo.athenz.common.server.workload;

import java.util.Date;

public class WorkloadRecord {
    private String service;
    private String provider;
    private String instanceId;
    private String ip;
    private Date creationTime;
    private Date updateTime;
    private String hostname;

    public Date getCertExpiryTime() {
        return certExpiryTime;
    }

    public void setCertExpiryTime(Date certExpiryTime) {
        this.certExpiryTime = certExpiryTime;
    }

    private Date certExpiryTime;
    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }
    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getInstanceId() {
        return instanceId;
    }

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public Date getCreationTime() {
        return creationTime;
    }

    public void setCreationTime(Date creationTime) {
        this.creationTime = creationTime;
    }

    public Date getUpdateTime() {
        return updateTime;
    }

    public void setUpdateTime(Date updateTime) {
        this.updateTime = updateTime;
    }

    @Override
    public String toString() {
        return "WorkloadRecord{" +
                "service='" + service + '\'' +
                ", provider='" + provider + '\'' +
                ", instanceId='" + instanceId + '\'' +
                ", ip='" + ip + '\'' +
                ", creationTime=" + creationTime +
                ", updateTime=" + updateTime +
                ", hostname='" + hostname + '\'' +
                ", certExpiryTime=" + certExpiryTime +
                '}';
    }
}
