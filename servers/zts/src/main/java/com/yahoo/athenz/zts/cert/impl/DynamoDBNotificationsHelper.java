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

import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.amazonaws.services.dynamodbv2.model.ReturnValue;
import com.yahoo.athenz.zts.utils.RetryDynamoDBCommand;

import java.util.List;
import java.util.concurrent.TimeoutException;

public class DynamoDBNotificationsHelper {

    public boolean isMostUpdatedRecordBasedOnAttribute(Item recordToCheck, List<Item> allRecordsWithHost, String dateKey, String primaryKey) {
        Item mostUpdatedHostRecord = allRecordsWithHost.stream()
                .reduce((record1, record2) -> {
                    if (record1.isNull(dateKey) || record1.get(dateKey) == null) {
                        return record2;
                    }
                    if (record2.isNull(dateKey) || record2.get(dateKey) == null) {
                        return record1;
                    }
                    return record1.getLong(dateKey) > record2.getLong(dateKey) ? record1 : record2;
                }).get();

        return recordToCheck.get(primaryKey).equals(mostUpdatedHostRecord.get(primaryKey));
    }

    public Item updateLastNotifiedItem(String lastNotifiedServer, long lastNotifiedTime, long yesterday, Item item, String primaryKey, Table table) throws InterruptedException, TimeoutException {
        RetryDynamoDBCommand<Item> retryDynamoDBCommand = new RetryDynamoDBCommand<>();
        return retryDynamoDBCommand.run(() -> {
            // For each item, update lastNotifiedTime and lastNotifiedServer (unless they were already updated)
            UpdateItemSpec updateItemSpec = new UpdateItemSpec().withPrimaryKey(primaryKey, item.getString(primaryKey))
                    .withReturnValues(ReturnValue.ALL_NEW)
                    .withUpdateExpression("set lastNotifiedTime = :lastNotifiedTimeVal, lastNotifiedServer = :lastNotifiedServerVal")
                    .withConditionExpression("attribute_not_exists(lastNotifiedTime) OR lastNotifiedTime < :v_yesterday")
                    .withValueMap(new ValueMap()
                            .with(":lastNotifiedTimeVal", lastNotifiedTime)
                            .withNumber(":v_yesterday", yesterday)
                            .withString(":lastNotifiedServerVal", lastNotifiedServer));

            return table.updateItem(updateItemSpec).getItem();
        });
    }
}
