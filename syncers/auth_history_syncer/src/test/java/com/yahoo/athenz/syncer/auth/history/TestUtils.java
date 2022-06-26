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

package com.yahoo.athenz.syncer.auth.history;

import static org.junit.Assert.assertEquals;

public class TestUtils {
    public static void assertRecordMatch(AuthHistoryDynamoDBRecord recordFromLogEvent, String message) {
        assertEquals("home.testuser:user:testprincipal", recordFromLogEvent.getPrimaryKey());
        assertEquals("home.testuser", recordFromLogEvent.getUriDomain());
        assertEquals("user", recordFromLogEvent.getPrincipalDomain());
        assertEquals("testprincipal", recordFromLogEvent.getPrincipalName());
        assertEquals("19/Apr/2022:08:00:45", recordFromLogEvent.getTimestamp());
    }
}
