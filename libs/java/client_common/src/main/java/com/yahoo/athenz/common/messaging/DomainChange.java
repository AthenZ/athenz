/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.messaging;

import java.util.Objects;

public class DomainChange {
    
    private String domainName;
    
     // Domain change message id     
    private String uuid;
   
    // The number of milliseconds since the epoch 
    private long published;
    
    // Change in domain meta
    private boolean metaChange;

    // Change in domain roles
    private boolean roleChange;

    // Change in domain policies
    private boolean policyChange;

    // Change in domain services
    private boolean serviceChange;

    // Change in domain groups
    private boolean groupChange;

    // Change in domain itself
    private boolean entityChange;

    public String getDomainName() {
        return domainName;
    }

    public DomainChange setDomainName(String domainName) {
        this.domainName = domainName;
        return this;
    }

    public String getUuid() {
        return uuid;
    }

    public DomainChange setUuid(String uuid) {
        this.uuid = uuid;
        return this;
    }

    public long getPublished() {
        return published;
    }

    public DomainChange setPublished(long published) {
        this.published = published;
        return this;
    }

    public boolean isMetaChange() {
        return metaChange;
    }

    public DomainChange setMetaChange(boolean metaChange) {
        this.metaChange = metaChange;
        return this;
    }

    public boolean isRoleChange() {
        return roleChange;
    }

    public DomainChange setRoleChange(boolean roleChange) {
        this.roleChange = roleChange;
        return this;
    }

    public boolean isPolicyChange() {
        return policyChange;
    }

    public DomainChange setPolicyChange(boolean policyChange) {
        this.policyChange = policyChange;
        return this;
    }

    public boolean isServiceChange() {
        return serviceChange;
    }

    public DomainChange setServiceChange(boolean serviceChange) {
        this.serviceChange = serviceChange;
        return this;
    }

    public boolean isGroupChange() {
        return groupChange;
    }

    public DomainChange setGroupChange(boolean groupChange) {
        this.groupChange = groupChange;
        return this;
    }

    public boolean isEntityChange() {
        return entityChange;
    }

    public DomainChange setEntityChange(boolean entityChange) {
        this.entityChange = entityChange;
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
        DomainChange that = (DomainChange) o;
        return published == that.published &&
            metaChange == that.metaChange &&
            roleChange == that.roleChange &&
            policyChange == that.policyChange &&
            serviceChange == that.serviceChange &&
            groupChange == that.groupChange &&
            entityChange == that.entityChange &&
            domainName.equals(that.domainName) &&
            uuid.equals(that.uuid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(domainName, uuid, published, metaChange, roleChange, policyChange, serviceChange, groupChange, entityChange);
    }
}
