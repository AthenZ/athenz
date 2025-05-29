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

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.notification.NotificationObjectStore;
import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

public class DynamoDBNotificationObjectStoreFactoryTest {

    @Test
    public void testCreateNoRegionException() {
        try {
            DynamoDBNotificationObjectStoreFactory dynamoDBNotificationObjectStoreFactory = new DynamoDBNotificationObjectStoreFactory();
            dynamoDBNotificationObjectStoreFactory.create(null);
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testCreateWithRegion() throws ServerResourceException {
        System.setProperty(DynamoDBNotificationObjectStoreFactory.PROP_DDB_NOTIFICATION_OBJECT_STORE_REGION, "us-west-2");
        DynamoDBNotificationObjectStoreFactory dynamoDBNotificationObjectStoreFactory = new DynamoDBNotificationObjectStoreFactory();
        NotificationObjectStore notificationObjectStore = dynamoDBNotificationObjectStoreFactory.create(null);
        assertNotNull(notificationObjectStore);
        System.clearProperty(DynamoDBNotificationObjectStoreFactory.PROP_DDB_NOTIFICATION_OBJECT_STORE_REGION);
    }
}
