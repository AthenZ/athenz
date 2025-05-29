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
package io.athenz.server.aws.common.notification.impl;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

import java.util.Objects;

@DynamoDbBean
public class DynamoDBNotificationObjectStoreRecord {

    public static final String DYNAMODB_OBJECT_ARN_INDEX_NAME = "objectArn-index";

    private String principalName;
    private String objectArn;
    private long ttl;

    public DynamoDBNotificationObjectStoreRecord() {
    }

    @DynamoDbPartitionKey
    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    @DynamoDbSortKey
    @DynamoDbSecondaryPartitionKey(indexNames = {DYNAMODB_OBJECT_ARN_INDEX_NAME})
    public String getObjectArn() {
        return objectArn;
    }

    public void setObjectArn(String objectArn) {
        this.objectArn = objectArn;
    }

    public long getTtl() {
        return ttl;
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

        DynamoDBNotificationObjectStoreRecord record = (DynamoDBNotificationObjectStoreRecord) o;
        return Objects.equals(principalName, record.principalName) && Objects.equals(objectArn, record.objectArn);
    }

    @Override
    public int hashCode() {
        return Objects.hash(principalName, objectArn);
    }

    @Override
    public String toString() {
        return "DynamoDBNotificationObjectStoreRecord{" +
                "principalName='" + principalName + '\'' +
                ", objectArn='" + objectArn + '\'' +
                ", ttl=" + ttl +
                '}';
    }
}
