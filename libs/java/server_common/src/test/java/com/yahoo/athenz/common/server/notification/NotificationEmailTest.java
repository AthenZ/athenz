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

package com.yahoo.athenz.common.server.notification;

import org.testng.annotations.Test;

import java.util.*;

import static org.testng.Assert.*;

public class NotificationEmailTest {

    @Test
    public void testNotificationEmail() {

        Set<String> emails = new HashSet<>();
        emails.add("email1@athenz.io");
        NotificationEmail email1 = new NotificationEmail("subject", "body", emails);
        NotificationEmail email2 = new NotificationEmail("subject", "body", emails);

        assertEquals(email1.hashCode(), email2.hashCode());
        assertEquals("subject", email1.getSubject());
        assertEquals("body", email1.getBody());
        assertEquals(emails, email1.getFullyQualifiedRecipientsEmail());

        assertEquals(email1, email2);
        assertEquals(email1, email1);

        assertFalse(email1.equals(null));
        assertFalse(email1.equals("null:"));

        email2 = new NotificationEmail("subject1", "body", emails);
        assertNotEquals(email1, email2);

        email2 = new NotificationEmail("subject", "body1", emails);
        assertNotEquals(email1, email2);

        Set<String> emails2 = new HashSet<>();
        emails2.add("emails2@athenz.io");
        email2 = new NotificationEmail("subject", "body", emails2);
        assertNotEquals(email1, email2);
    }
}