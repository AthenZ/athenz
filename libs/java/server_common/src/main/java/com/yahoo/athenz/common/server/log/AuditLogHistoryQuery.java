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
package com.yahoo.athenz.common.server.log;

import com.yahoo.rdl.Timestamp;

/**
 * Query arguments for retrieving the audit log history of a domain.
 * The domain name, start/end times and limit are always set by the
 * server while the api, entity and principal filters are optional
 * and will be null if not specified by the caller. The domain, entity
 * and principal values are converted to lower case by the server while
 * the api value is passed as specified by the caller since the audit
 * records store the api name with its camel-case spelling (e.g. putRole).
 */
public class AuditLogHistoryQuery {

    private String domainName;
    private String api;
    private String entity;
    private String principal;
    private Timestamp startTime;
    private Timestamp endTime;
    private int limit;

    public String getDomainName() {
        return domainName;
    }

    public AuditLogHistoryQuery setDomainName(String domainName) {
        this.domainName = domainName;
        return this;
    }

    public String getApi() {
        return api;
    }

    public AuditLogHistoryQuery setApi(String api) {
        this.api = api;
        return this;
    }

    public String getEntity() {
        return entity;
    }

    public AuditLogHistoryQuery setEntity(String entity) {
        this.entity = entity;
        return this;
    }

    public String getPrincipal() {
        return principal;
    }

    public AuditLogHistoryQuery setPrincipal(String principal) {
        this.principal = principal;
        return this;
    }

    public Timestamp getStartTime() {
        return startTime;
    }

    public AuditLogHistoryQuery setStartTime(Timestamp startTime) {
        this.startTime = startTime;
        return this;
    }

    public Timestamp getEndTime() {
        return endTime;
    }

    public AuditLogHistoryQuery setEndTime(Timestamp endTime) {
        this.endTime = endTime;
        return this;
    }

    public int getLimit() {
        return limit;
    }

    public AuditLogHistoryQuery setLimit(int limit) {
        this.limit = limit;
        return this;
    }
}
