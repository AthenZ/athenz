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

package com.yahoo.athenz.syncer.auth.history.impl;

import com.yahoo.athenz.syncer.auth.history.AuthHistoryDynamoDBRecord;
import com.yahoo.athenz.syncer.auth.history.AuthHistoryFetcher;

import java.util.HashSet;
import java.util.Set;

public class MockAuthHistoryFetcher implements AuthHistoryFetcher {
    @Override
    public Set<AuthHistoryDynamoDBRecord> getLogs(Long startTime, Long endTime, boolean useFilterPattern) {
        Long mockStartTime = 1650185529000L; // 17/Apr/2022:08:52:09
        Long mockEndTime = 1650271929000L; // 18/Apr/2022:08:52:09
        if (startTime < mockStartTime || endTime > mockEndTime) {
            return new HashSet<>();
        }
        Set<AuthHistoryDynamoDBRecord> records = new HashSet<>();
        AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord = new AuthHistoryDynamoDBRecord("primaryKeyTest",
                "uriDomainTest", "principalDomainTest", "principalNameTest", "endpointTest",
                "timestampTest", "access-check", 0L);
        records.add(authHistoryDynamoDBRecord);
        return records;
    }
}
