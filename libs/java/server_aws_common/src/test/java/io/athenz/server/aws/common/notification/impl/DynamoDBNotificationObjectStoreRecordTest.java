/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.athenz.server.aws.common.notification.impl;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class DynamoDBNotificationObjectStoreRecordTest {

    @Test
    public void testDynamoDBNotificationObjectStoreRecord() {
        DynamoDBNotificationObjectStoreRecord record = new DynamoDBNotificationObjectStoreRecord();
        record.setPrincipalName("user.joe");
        record.setObjectArn("athenz:role.role1");
        record.setTtl(1234567890L);

        assertEquals(record.getPrincipalName(), "user.joe");
        assertEquals(record.getObjectArn(), "athenz:role.role1");
        assertEquals(record.getTtl(), 1234567890L);

        DynamoDBNotificationObjectStoreRecord record2 = new DynamoDBNotificationObjectStoreRecord();
        record2.setPrincipalName("user.joe");
        record2.setObjectArn("athenz:role.role1");
        record2.setTtl(1234567890L);

        assertEquals(record, record2);
        assertTrue(record.equals(record));
        assertFalse(record.equals(null));
        assertFalse(record.equals(new Object()));
        assertEquals(record.hashCode(), record2.hashCode());
        assertEquals(record.toString(), "DynamoDBNotificationObjectStoreRecord{principalName='user.joe', objectArn='athenz:role.role1', ttl=1234567890}");
    }
}
