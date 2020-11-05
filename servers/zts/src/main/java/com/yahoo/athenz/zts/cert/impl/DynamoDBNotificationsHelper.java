/*
 *  Copyright 2020 Verizon Media
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

import java.util.List;

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
}
