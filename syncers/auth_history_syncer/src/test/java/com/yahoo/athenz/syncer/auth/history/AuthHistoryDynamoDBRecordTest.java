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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AuthHistoryDynamoDBRecordTest {

    @Test
    public void testAuthHistoryDynamoDBRecord() {
        AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord = new AuthHistoryDynamoDBRecord();
        authHistoryDynamoDBRecord.setPrimaryKey("primaryKeyTest");
        authHistoryDynamoDBRecord.setUriDomain("uriDomainTest");
        authHistoryDynamoDBRecord.setPrincipalDomain("principalDomainTest");
        authHistoryDynamoDBRecord.setPrincipalName("principalNameTest");
        authHistoryDynamoDBRecord.setEndpoint("endpointTest");
        authHistoryDynamoDBRecord.setTimestamp("timestampTest");
        authHistoryDynamoDBRecord.setOperation("access-check");
        authHistoryDynamoDBRecord.setTtl(1000L);

        assertEquals(authHistoryDynamoDBRecord.getPrimaryKey(), "primaryKeyTest");
        assertEquals(authHistoryDynamoDBRecord.getUriDomain(), "uriDomainTest");
        assertEquals(authHistoryDynamoDBRecord.getPrincipalDomain(), "principalDomainTest");
        assertEquals(authHistoryDynamoDBRecord.getPrincipalName(), "principalNameTest");
        assertEquals(authHistoryDynamoDBRecord.getEndpoint(), "endpointTest");
        assertEquals(authHistoryDynamoDBRecord.getTimestamp(), "timestampTest");
        assertEquals(authHistoryDynamoDBRecord.getOperation(), "access-check");
        assertEquals(authHistoryDynamoDBRecord.getTtl(), 1000L);

        AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord2 = new AuthHistoryDynamoDBRecord("primaryKeyTest",
                "uriDomainTest", "principalDomainTest", "principalNameTest", "endpointTest",
                "timestampTest", "access-check", 1000L);
        assertEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord2);

        assertEquals(authHistoryDynamoDBRecord, authHistoryDynamoDBRecord);
        assertFalse(authHistoryDynamoDBRecord.equals(null));
        assertFalse(authHistoryDynamoDBRecord.equals("test"));

        assertEquals(authHistoryDynamoDBRecord.hashCode(), authHistoryDynamoDBRecord2.hashCode());
        assertEquals(authHistoryDynamoDBRecord.toString(),
                "AuthHistoryDynamoDBRecord{primaryKey='primaryKeyTest', uriDomain='uriDomainTest', principalDomain='principalDomainTest', principalName='principalNameTest', endpoint='endpointTest', timestamp='timestampTest', operation='access-check', ttl=1000}");

        // records equal with no primary key
        AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord3 = new AuthHistoryDynamoDBRecord();
        AuthHistoryDynamoDBRecord authHistoryDynamoDBRecord4 = new AuthHistoryDynamoDBRecord();
        assertTrue(authHistoryDynamoDBRecord3.equals(authHistoryDynamoDBRecord4));

        // same values - match
        authHistoryDynamoDBRecord3.setPrimaryKey("primaryKeyTest");
        authHistoryDynamoDBRecord4.setPrimaryKey("primaryKeyTest");
        assertTrue(authHistoryDynamoDBRecord3.equals(authHistoryDynamoDBRecord4));

        // different values - no match
        authHistoryDynamoDBRecord3.setPrimaryKey("primaryKeyTest");
        authHistoryDynamoDBRecord4.setPrimaryKey("primaryKeyTest2");
        assertFalse(authHistoryDynamoDBRecord3.equals(authHistoryDynamoDBRecord4));

        // one null value - no match
        authHistoryDynamoDBRecord3.setPrimaryKey(null);
        authHistoryDynamoDBRecord4.setPrimaryKey("primaryKeyTest2");
        assertFalse(authHistoryDynamoDBRecord3.equals(authHistoryDynamoDBRecord4));
    }
}
