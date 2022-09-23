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

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * AWSAttestationData - the information a booting
 * EC2 instance must provide to ZTS to authenticate.
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public class AWSAttestationData {
    private String document;
    private String signature;
    private String role;
    private String access;
    private String secret;
    private String token;
    private String taskid;

    public void setDocument(String document) {
        this.document = document;
    }
    public String getDocument() {
        return document;
    }
    public void setSignature(String signature) {
        this.signature = signature;
    }
    public String getSignature() {
        return signature;
    }
    public void setRole(String role) {
        this.role = role;
    }
    public String getRole() {
        return role;
    }
    public void setAccess(String access) {
        this.access = access;
    }
    public String getAccess() {
        return access;
    }
    public void setSecret(String secret) {
        this.secret = secret;
    }
    public String getSecret() {
        return secret;
    }
    public void setToken(String token) {
        this.token = token;
    }
    public String getToken() {
        return token;
    }
    public void setTaskid(String taskid) {
        this.taskid = taskid;
    }
    public String getTaskid() {
        return taskid;
    }
}
