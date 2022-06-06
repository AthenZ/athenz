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

        authHistoryDynamoDBRecord.setUriDomain("domain");
        authHistoryDynamoDBRecord.setPrincipalDomain("principal.domain");
        authHistoryDynamoDBRecord.setPrincipalName("principal");
        authHistoryDynamoDBRecord.setTimestamp("timestamp");
        authHistoryDynamoDBRecord.setEndpoint("endpoint");
        authHistoryDynamoDBRecord.setTtl(1L);
        authHistoryDynamoDBRecord.setPrimaryKey("domain:principal.domain:principal");
        assertEquals(authHistoryDynamoDBRecord.getUriDomain(), "domain");
        assertEquals(authHistoryDynamoDBRecord.getPrincipalDomain(), "principal.domain");
        assertEquals(authHistoryDynamoDBRecord.getPrincipalName(), "principal");
        assertEquals(authHistoryDynamoDBRecord.getTimestamp(), "timestamp");
        assertEquals(authHistoryDynamoDBRecord.getEndpoint(), "endpoint");
        assertEquals(authHistoryDynamoDBRecord.getTtl(), 1L);
        assertEquals(authHistoryDynamoDBRecord.getPrimaryKey(), "domain:principal.domain:principal");

        AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord2 = new AuthHistoryDynamoDBRecord();
        assertNotEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);
        authHistoryDynamoDBRecord2.setUriDomain("domain");
        authHistoryDynamoDBRecord2.setUriDomain("principal.domain");
        authHistoryDynamoDBRecord2.setPrincipalName("principal");
        authHistoryDynamoDBRecord2.setTimestamp("timestamp");
        authHistoryDynamoDBRecord2.setEndpoint("endpoint");
        authHistoryDynamoDBRecord2.setTtl(1L);
        assertNotEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);
        authHistoryDynamoDBRecord2.setPrimaryKey("domain:principal.domain:principal");
        assertEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);


    }
}
