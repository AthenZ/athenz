/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zms.store;

import java.util.ArrayList;
import java.util.List;

import com.yahoo.athenz.zms.Domain;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.ServiceIdentity;

public class AthenzDomain {

    String name;
    List<Role> roles;
    List<Policy> policies;
    List<ServiceIdentity> services;
    Domain domain = null;
    
    public AthenzDomain(String name) {
        this.name = name;
        roles = new ArrayList<>();
        policies = new ArrayList<>();
        services = new ArrayList<>();
    }
    
    public void setName(String name) {
        this.name = name;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }

    public void setServices(List<ServiceIdentity> services) {
        this.services = services;
    }

    public void setPolicies(List<Policy> policies) {
        this.policies = policies;
    }
    
    public void setDomain(Domain domain) {
        this.domain = domain;
    }
    
    public String getName() {
        return name;
    }
    
    public List<Role> getRoles() {
        return roles;
    }
    
    public List<Policy> getPolicies() {
        return policies;
    }

    public List<ServiceIdentity> getServices() {
        return services;
    }

    public Domain getDomain() {
        return domain;
    }
}
