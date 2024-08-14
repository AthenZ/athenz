/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.zts.utils.RetryDynamoDBCommand;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ReturnValue;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

public class DynamoDBNotificationsHelper {

    public boolean isMostUpdatedRecordBasedOnAttribute(Map<String, AttributeValue> recordToCheck,
            List<Map<String, AttributeValue>> allRecordsWithHost, String dateKey, String primaryKey) {
        Map<String, AttributeValue> mostUpdatedHostRecord = allRecordsWithHost.stream()
                .reduce((record1, record2) -> {
                    if (record1.get(dateKey) == null) {
                        return record2;
                    }
                    if (record2.get(dateKey) == null) {
                        return record1;
                    }
                    return Long.parseLong(record1.get(dateKey).n()) > Long.parseLong(record2.get(dateKey).n()) ? record1 : record2;
                }).get();

        return recordToCheck.get(primaryKey).equals(mostUpdatedHostRecord.get(primaryKey));
    }

    public Map<String, AttributeValue> updateLastNotifiedItem(final String lastNotifiedServer, long lastNotifiedTime,
            long yesterday, Map<String, AttributeValue> item, final String primaryKey, final String tableName,
            DynamoDbClient dbClient) throws InterruptedException, TimeoutException {

        RetryDynamoDBCommand<Map<String, AttributeValue>> retryDynamoDBCommand = new RetryDynamoDBCommand<>();
        return retryDynamoDBCommand.run(() -> {

            HashMap<String, AttributeValue> itemKey = new HashMap<>();
            itemKey.put(primaryKey, item.get(primaryKey));

            HashMap<String, AttributeValue> attrValues = new HashMap<>();
            attrValues.put(":lastNotifiedTimeVal", AttributeValue.fromN(String.valueOf(lastNotifiedTime)));
            attrValues.put(":v_yesterday", AttributeValue.fromN(String.valueOf(yesterday)));
            attrValues.put(":lastNotifiedServerVal", AttributeValue.fromS(lastNotifiedServer));

            // For each item, update lastNotifiedTime and lastNotifiedServer (unless they were already updated)
            UpdateItemRequest request =  UpdateItemRequest.builder()
                    .tableName(tableName)
                    .key(itemKey)
                    .returnValues(ReturnValue.ALL_NEW)
                    .updateExpression("set lastNotifiedTime = :lastNotifiedTimeVal, lastNotifiedServer = :lastNotifiedServerVal")
                    .conditionExpression("attribute_not_exists(lastNotifiedTime) OR lastNotifiedTime < :v_yesterday")
                    .expressionAttributeValues(attrValues)
                    .build();

            return dbClient.updateItem(request).attributes();
        });
    }
}
