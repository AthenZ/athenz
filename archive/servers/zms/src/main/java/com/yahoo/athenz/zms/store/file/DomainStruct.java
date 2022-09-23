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
package com.yahoo.athenz.zms.store.file;

import java.util.ArrayList;
import java.util.HashMap;

import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;

public class DomainStruct {
    
    private String name;
    private DomainMeta meta;
    private UUID id;
    private Timestamp modified;
    private HashMap<String, Role> roles;
    private HashMap<String, Policy> policies;
    private HashMap<String, ServiceIdentity> services;
    private HashMap<String, Entity> entities;
    private ArrayList<String> templates;
    private ArrayList<TemplateMetaData> templateMeta;

    public ArrayList<TemplateMetaData> getTemplateMeta() {
        return templateMeta;
    }
    public void setTemplateMeta(ArrayList<TemplateMetaData> templateMeta) {
        this.templateMeta = templateMeta;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public DomainMeta getMeta() {
        return meta;
    }
    public void setMeta(DomainMeta meta) {
        this.meta = meta;
    }
    public UUID getId() {
        return id;
    }
    public void setId(UUID id) {
        this.id = id;
    }
    public Timestamp getModified() {
        return modified;
    }
    public void setModified(Timestamp modified) {
        this.modified = modified;
    }
    public HashMap<String, Role> getRoles() {
        return roles;
    }
    public void setRoles(HashMap<String, Role> roles) {
        this.roles = roles;
    }
    public HashMap<String, Policy> getPolicies() {
        return policies;
    }
    public void setPolicies(HashMap<String, Policy> policies) {
        this.policies = policies;
    }
    public HashMap<String, ServiceIdentity> getServices() {
        return services;
    }
    public void setServices(HashMap<String, ServiceIdentity> services) {
        this.services = services;
    }
    public HashMap<String, Entity> getEntities() {
        return entities;
    }
    public void setEntities(HashMap<String, Entity> entities) {
        this.entities = entities;
    }
    public ArrayList<String> getTemplates() {
        return templates;
    }
    public void setTemplates(ArrayList<String> templates) {
        this.templates = templates;
    }
    
}
