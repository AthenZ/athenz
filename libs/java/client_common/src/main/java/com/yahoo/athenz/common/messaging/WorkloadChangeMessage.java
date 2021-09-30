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

package com.yahoo.athenz.common.messaging;

import java.util.Objects;

public class WorkloadChangeMessage {

    // Represent the changed object type
    public enum ObjectType {
        IP,       // Signals an IP change in one of the workloads for the service
        UUID,     // Signals a UUID addition/deletion to the workloads for the service
        HOSTNAME  // Signals a hostname change on one of the workloads for the service
    }

    // domain name
    private String domainName;

    // service name
    private String serviceName;

    // Workload change message id
    private String messageId;

    // milliseconds since the epoch
    private long published;

    private ObjectType objectType;

    public String getDomainName() {
        return domainName;
    }

    public WorkloadChangeMessage setDomainName(String domainName) {
        this.domainName = domainName;
        return this;
    }

    public String getServiceName() {
        return serviceName;
    }

    public WorkloadChangeMessage setServiceName(String serviceName) {
        this.serviceName = serviceName;
        return this;
    }

    public String getMessageId() {
        return messageId;
    }

    public WorkloadChangeMessage setMessageId(String messageId) {
        this.messageId = messageId;
        return this;
    }

    public long getPublished() {
        return published;
    }

    public WorkloadChangeMessage setPublished(long published) {
        this.published = published;
        return this;
    }

    public ObjectType getObjectType() {
        return objectType;
    }

    public WorkloadChangeMessage setObjectType(ObjectType objectType) {
        this.objectType = objectType;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        WorkloadChangeMessage that = (WorkloadChangeMessage) o;
        return messageId.equals(that.messageId) &&
                domainName.equals(that.domainName) &&
                serviceName.equals(that.serviceName) &&
                published == that.published &&
                objectType == that.objectType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(domainName, serviceName, messageId, published, objectType);
    }
}
