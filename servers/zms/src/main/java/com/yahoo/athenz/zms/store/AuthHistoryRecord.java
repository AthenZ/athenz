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

package com.yahoo.athenz.zms.store;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

import java.util.Objects;

@DynamoDbBean
public class AuthHistoryRecord {
    private String domain;
    private String principal;
    private String endpoint;
    private String timestamp;
    private long ttl;

    public AuthHistoryRecord() {

    }

    public AuthHistoryRecord(String domain, String principal, String endpoint, String timestamp, long ttl) {
        this.domain = domain;
        this.principal = principal;
        this.endpoint = endpoint;
        this.timestamp = timestamp;
        this.ttl = ttl;
    }

    @DynamoDbPartitionKey
    public String getDomain() {
        return domain;
    }

    @DynamoDbSortKey
    public String getPrincipal() {
        return principal;
    }
    public String getEndpoint() {
        return endpoint;
    }
    public String getTimestamp() {
        return timestamp;
    }
    public long getTtl() {
        return ttl;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }
    public void setPrincipal(String principal) {
        this.principal = principal;
    }
    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }
    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }
    public void setTtl(long ttl) {
        this.ttl = ttl;
    }

    // We only want to keep a single entry per domain and principal so
    // two records will be considered equal even if timestamp or endpoint are different
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AuthHistoryRecord record = (AuthHistoryRecord) o;
        return getDomain().equals(record.getDomain()) && getPrincipal().equals(record.getPrincipal());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getDomain(), getPrincipal());
    }

    @Override
    public String toString() {
        return "AuthHistoryRecord{" +
                "domain='" + domain + '\'' +
                ", principal='" + principal + '\'' +
                ", endpoint='" + endpoint + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", ttl='" + ttl + '\'' +
                '}';
    }
}
