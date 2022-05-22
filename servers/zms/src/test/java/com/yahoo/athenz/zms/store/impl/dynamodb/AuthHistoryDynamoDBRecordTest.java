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

package com.yahoo.athenz.zms.store.impl.dynamodb;

import org.testng.annotations.Test;

import static org.testng.Assert.assertNotEquals;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

public class AuthHistoryDynamoDBRecordTest {

    @Test
    public void testAuthHistoryDynamoDBRecord() {
        AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord = new AuthHistoryDynamoDBRecord();
        assertNotNull(authHistoryDynamoDBRecord);

        AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord2 = new AuthHistoryDynamoDBRecord();
        assertEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);

        authHistoryDynamoDBRecord.setDomain("domain");
        assertNotEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);
        authHistoryDynamoDBRecord2.setDomain("domain2");
        assertNotEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);
        authHistoryDynamoDBRecord2.setDomain("domain");
        assertEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);

        authHistoryDynamoDBRecord.setPrincipal("principal");
        assertNotEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);
        authHistoryDynamoDBRecord2.setPrincipal("principal2");
        assertNotEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);
        authHistoryDynamoDBRecord2.setPrincipal("principal");
        assertEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);

        authHistoryDynamoDBRecord.setTimestamp("timestamp");
        authHistoryDynamoDBRecord.setEndpoint("endpoint");
        authHistoryDynamoDBRecord.setTtl(1L);
        assertEquals(authHistoryDynamoDBRecord.getTimestamp(), "timestamp");
        assertEquals(authHistoryDynamoDBRecord.getEndpoint(), "endpoint");
        assertEquals(authHistoryDynamoDBRecord.getTtl(), 1L);

        // Both records will still be equals as we only differentiate records by domain and principal
        assertEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);
    }
}
