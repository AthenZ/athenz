/*
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

import com.yahoo.athenz.zms.*;

public class AthenzDomain {

    private String name;
    private List<Role> roles;
    private List<Group> groups;
    private List<Policy> policies;
    private List<ServiceIdentity> services;
    private Domain domain = null;
    
    public AthenzDomain(String name) {
        this.name = name;
        roles = new ArrayList<>();
        groups = new ArrayList<>();
        policies = new ArrayList<>();
        services = new ArrayList<>();
    }
    
    public void setName(String name) {
        this.name = name;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }

    public void setGroups(List<Group> groups) {
        this.groups = groups;
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

    public List<Group> getGroups() {
        return groups;
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
