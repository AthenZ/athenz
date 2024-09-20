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

package io.athenz.server.aws.common.utils;

import software.amazon.awssdk.services.dynamodb.model.AttributeAction;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.AttributeValueUpdate;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class DynamoDBUtils {

    public static String getIso8601FromDate(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        return sdf.format(date);
    }

    public static List<String> getISODatesByRange(long epochBegin, long epochEnd) {
        List<String> datesArray = new ArrayList<>();
        while (epochBegin <= epochEnd) {
            String date = getIso8601FromDate(new Date(epochBegin));
            datesArray.add(date);
            // Advance to next day
            epochBegin += TimeUnit.DAYS.toMillis(1);
        }

        return datesArray;
    }

    public static Date getDateFromItem(Map<String, AttributeValue> item, final String key) {
        AttributeValue value = item.get(key);
        if (value == null) {
            return null;
        }
        return new Date(Long.parseLong(value.n()));
    }

    public static String getNumberFromDate(Date date) {
        if (date == null) {
            return "0";
        }

        return String.valueOf(date.getTime());
    }

    public static String getString(Map<String, AttributeValue> item, final String key) {
        AttributeValue value = item.get(key);
        if (value == null) {
            return null;
        }
        return value.s();
    }

    public static boolean getBoolean(Map<String, AttributeValue> item, final String key) {
        AttributeValue value = item.get(key);
        if (value == null || value.bool() == null) {
            return false;
        }
        return value.bool();
    }

    public static long getLong(Map<String, AttributeValue> item, final String key) {
        AttributeValue value = item.get(key);
        if (value == null) {
            return 0;
        }
        return Long.parseLong(value.n());
    }

    public static void updateItemStringValue(HashMap<String, AttributeValueUpdate> updatedValues,
            final String key, final String value) {
        updatedValues.put(key, AttributeValueUpdate.builder()
                .value(AttributeValue.fromS(value))
                .action(AttributeAction.PUT)
                .build());
    }

    public static void updateItemBoolValue(HashMap<String, AttributeValueUpdate> updatedValues,
            final String key, final Boolean value) {
        updatedValues.put(key, AttributeValueUpdate.builder()
                .value(AttributeValue.fromBool(value))
                .action(AttributeAction.PUT)
                .build());
    }

    public static void updateItemLongValue(HashMap<String, AttributeValueUpdate> updatedValues,
            final String key, final Long value) {
        updatedValues.put(key, AttributeValueUpdate.builder()
                .value(AttributeValue.fromN(String.valueOf(value)))
                .action(AttributeAction.PUT)
                .build());
    }

    public static void updateItemLongValue(HashMap<String, AttributeValueUpdate> updatedValues,
            final String key, final Date value) {
        AttributeValue attributeValue;
        if (value == null) {
            attributeValue = AttributeValue.builder().nul(true).build();
        } else {
            attributeValue = AttributeValue.fromN(String.valueOf(value.getTime()));
        }
        updatedValues.put(key, AttributeValueUpdate.builder()
                .value(attributeValue)
                .action(AttributeAction.PUT)
                .build());
    }
}
