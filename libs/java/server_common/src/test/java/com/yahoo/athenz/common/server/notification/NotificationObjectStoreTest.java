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

import com.yahoo.athenz.common.server.ServerResourceException;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;

public class NotificationObjectStoreTest {

    @Test
    public void testNotificationObjectStore() {
        NotificationObjectStoreFactory factory = privateKeyStore -> null;
        assertNotNull(factory);
        try {
            NotificationObjectStore store = factory.create(null);
            assertNull(store);
        } catch (ServerResourceException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testNotificationObjectStoreMethods() {

        NotificationObjectStore notificationObjectStore = new NotificationObjectStore() {

            final Map<String, List<String>> reviewObjectsMap = new HashMap<>();

            @Override
            public void registerReviewObjects(String principal, List<String> reviewObjects) throws ServerResourceException {
                reviewObjectsMap.put(principal, reviewObjects);
            }

            @Override
            public List<String> getReviewObjects(String principal) throws ServerResourceException {
                return reviewObjectsMap.get(principal);
            }

            @Override
            public void removePrincipal(String principal) throws ServerResourceException {
                reviewObjectsMap.remove(principal);
            }

            @Override
            public void deregisterReviewObject(String reviewObject) throws ServerResourceException {
                for (Map.Entry<String, List<String>> entry : reviewObjectsMap.entrySet()) {
                    List<String> reviewObjects = entry.getValue();
                    if (reviewObjects != null) {
                        reviewObjects.remove(reviewObject);
                    }
                }
            }
        };
        NotificationObjectStoreFactory factory = privateKeyStore -> notificationObjectStore;
        assertNotNull(factory);

        try {
            NotificationObjectStore store = factory.create(null);
            assertNotNull(store);

            List<String> reviewObjects = new ArrayList<>();
            reviewObjects.add("role1");
            reviewObjects.add("role2");

            store.registerReviewObjects("user.joe", reviewObjects);
            assertEquals(store.getReviewObjects("user.joe"), reviewObjects);

            store.deregisterReviewObject("role1");
            assertEquals(store.getReviewObjects("user.joe"), List.of("role2"));

            store.removePrincipal("user.joe");
            assertNull(store.getReviewObjects("user.joe"));
        } catch (ServerResourceException e) {
            throw new RuntimeException(e);
        }
    }
}
