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

package com.yahoo.athenz.common.server.notification;

import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

public class NotificationToMetricConverterCommon {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationToMetricConverterCommon.class);

    public String getNumberOfDaysBetweenTimestamps(String timeStampStr1, String timeStampStr2) {
        Timestamp timestamp1 = Timestamp.fromString(timeStampStr1);
        if (timestamp1 == null) {
            LOGGER.error("Failed to parse days from timestamp: {}", timeStampStr1);
            return "";
        }
        Timestamp timestamp2 = Timestamp.fromString(timeStampStr2);
        if (timestamp2 == null) {
            LOGGER.error("Failed to parse days from timestamp: {}", timeStampStr2);
            return "";
        }

        long diffInMS = timestamp2.millis() - timestamp1.millis();
        long days = TimeUnit.DAYS.convert(diffInMS, TimeUnit.MILLISECONDS);
        return Long.toString(days);
    }
}
