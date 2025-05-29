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

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.notification.NotificationObjectStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class DynamoDBNotificationObjectStore implements NotificationObjectStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBNotificationObjectStore.class);
    private final DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable;

    DynamoDBNotificationObjectStore(DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable) {
        this.recordTable = recordTable;
    }

    @Override
    public void registerReviewObjects(String principalName, List<String> reviewObjects) throws ServerResourceException {
        for (String objectArn : reviewObjects) {
            registerReviewObject(principalName, objectArn);
        }
    }

    void registerReviewObject(String principalName, String objectArn) throws ServerResourceException {
        DynamoDBNotificationObjectStoreRecord record = new DynamoDBNotificationObjectStoreRecord();
        record.setPrincipalName(principalName);
        record.setObjectArn(objectArn);
        record.setTtl(System.currentTimeMillis() / 1000 + TimeUnit.DAYS.toMillis(30));
        try {
            recordTable.putItem(record);
        } catch (Exception ex) {
            LOGGER.error("Error inserting record for principal {} and object {}: {}", principalName, objectArn, ex.getMessage());
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR,
                    "Error inserting record: " + ex.getMessage());
        }
    }

    @Override
    public List<String> getReviewObjects(String principalName) throws ServerResourceException {
        QueryConditional queryConditional = QueryConditional
                .keyEqualTo(Key.builder().partitionValue(principalName).build());

        // Perform the query on the main table using its partition key
        try {
            Iterator<DynamoDBNotificationObjectStoreRecord> results = recordTable.query
                    (r -> r.queryConditional(queryConditional)).items().iterator();

            List<String> objectArns = new ArrayList<>();
            while (results.hasNext()) {
                objectArns.add(results.next().getObjectArn());
            }
            return objectArns;
        } catch (Exception ex) {
            LOGGER.error("Error retrieving review objects for principal {}: {}", principalName, ex.getMessage());
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR,
                    "Error retrieving review objects for: " + principalName + " error: " + ex.getMessage());
        }
    }

    @Override
    public void removePrincipal(String principalName) throws ServerResourceException {

        try {
            QueryConditional queryConditional = QueryConditional
                    .keyEqualTo(Key.builder().partitionValue(principalName).build());

            // Perform the query on the main table using its partition key
            Iterator<DynamoDBNotificationObjectStoreRecord> results =
                    recordTable.query(r -> r.queryConditional(queryConditional)).items().iterator();

            List<DynamoDBNotificationObjectStoreRecord> records = new ArrayList<>();
            while (results.hasNext()) {
                records.add(results.next());
            }

            for (DynamoDBNotificationObjectStoreRecord record : records) {
                deleteSpecifiedRecord(record.getPrincipalName(), record.getObjectArn());
            }

        } catch (Exception ex) {
            LOGGER.error("Error removing principal {}: {}", principalName, ex.getMessage());
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR,
                    "Error removing principal: " + principalName + " error: " + ex.getMessage());
        }
    }

    @Override
    public void deregisterReviewObject(String objectArn) throws ServerResourceException {


        try {
            QueryConditional queryConditional = QueryConditional
                    .keyEqualTo(Key.builder().partitionValue(objectArn).build());

            List<String> principals = recordTable.index(DynamoDBNotificationObjectStoreRecord.DYNAMODB_OBJECT_ARN_INDEX_NAME)
                    .query(r -> r.queryConditional(queryConditional))
                    .stream()
                    .map(Page::items)
                    .flatMap(List::stream)
                    .map(DynamoDBNotificationObjectStoreRecord::getPrincipalName)
                    .collect(Collectors.toList());

            for (String principal : principals) {
                deleteSpecifiedRecord(principal, objectArn);
            }
        } catch (Exception ex) {
            LOGGER.error("Error deregistering review object {}: {}", objectArn, ex.getMessage());
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR,
                    "Error deregistering review object: " + objectArn + " error: " + ex.getMessage());
        }
    }

    void deleteSpecifiedRecord(String principalName, String objectArn) {
        Key primaryKey = Key.builder()
                .partitionValue(principalName)
                .sortValue(objectArn)
                .build();
        recordTable.deleteItem(primaryKey);
    }
}
