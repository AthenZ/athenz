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

package com.yahoo.athenz.zts.utils;

import com.amazonaws.services.dynamodbv2.document.Item;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
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

    public static Date getDateFromItem(Item item, String key) {
        if (item.isNull(key) || item.get(key) == null) {
            return null;
        }
        return new Date(item.getLong(key));
    }

    public static Object getLongFromDate(Date date) {
        if (date == null) {
            return null;
        }

        return date.getTime();
    }
}
