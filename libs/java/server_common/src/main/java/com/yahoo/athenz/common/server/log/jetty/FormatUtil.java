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

package com.yahoo.athenz.common.server.log.jetty;

import com.fasterxml.jackson.core.JsonGenerator;
import java.io.IOException;

class FormatUtil {

    private FormatUtil() { }

    static void writeSecondsField(JsonGenerator generator, String fieldName, double seconds) throws IOException {
        writeSecondsField(generator, fieldName, (long) (seconds * 1000));
    }

    static void writeSecondsField(JsonGenerator generator, String fieldName, long milliseconds) throws IOException {
        generator.writeFieldName(fieldName);
        generator.writeRawValue(toSecondsString(milliseconds));
    }

    /** @return a string with number of seconds with 3 decimals */
    static String toSecondsString(long milliseconds) {
        StringBuilder builder = new StringBuilder().append(milliseconds / 1000L).append('.');
        long decimals = milliseconds % 1000;
        if (decimals < 100) {
            builder.append('0');
            if (decimals < 10) {
                builder.append('0');
            }
        }
        return builder.append(decimals).toString();
    }
}

