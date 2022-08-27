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

package com.yahoo.athenz.zms.store.impl.dynamodb;

import com.yahoo.athenz.zms.ZMSConsts;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;

import java.util.Objects;

@DynamoDbBean
public class AuthHistoryDynamoDBRecord {
    private String primaryKey;
    private String uriDomain;
    private String principalDomain;
    private String principalName;
    private String endpoint;
    private String timestamp;
    private long ttl;

    public AuthHistoryDynamoDBRecord() {
    }

    @DynamoDbPartitionKey
    public String getPrimaryKey() {
        return primaryKey;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = {ZMSConsts.ZMS_DYNAMODB_URI_DOMAIN_INDEX_NAME})
    public String getUriDomain() {
        return uriDomain;
    }

    public long getTtl() {
        return ttl;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = {ZMSConsts.ZMS_DYNAMODB_PRINCIPAL_DOMAIN_INDEX_NAME})
    public String getPrincipalDomain() {
        return principalDomain;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getTimestamp() {
        return timestamp;
    }

    // Set methods must exist for @DynamoDbBean successful marshalling
    public void setPrimaryKey(String primaryKey) {
        this.primaryKey = primaryKey;
    }
    public void setUriDomain(String uriDomain) {
        this.uriDomain = uriDomain;
    }
    public void setPrincipalDomain(String principalDomain) {
        this.principalDomain = principalDomain;
    }
    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        AuthHistoryDynamoDBRecord record = (AuthHistoryDynamoDBRecord) o;
        return getPrimaryKey() == null ? record.getPrimaryKey() == null : getPrimaryKey().equals(record.getPrimaryKey());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getPrimaryKey());
    }

    @Override
    public String toString() {
        return "AuthHistoryDynamoDBRecord{" +
                "primaryKey='" + primaryKey + '\'' +
                ", uriDomain='" + uriDomain + '\'' +
                ", principalDomain='" + principalDomain + '\'' +
                ", principalName='" + principalName + '\'' +
                ", endpoint='" + endpoint + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", ttl=" + ttl +
                '}';
    }
}
