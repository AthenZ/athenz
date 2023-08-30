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

public class NotificationTest {

    @Test
    public void testNotificationMethods() {
        Notification obj = new Notification();

        Map<String, String> details = new HashMap<>();
        details.put("domain", "dom1");

        obj.setDetails(details);
        obj.addDetails("role", "role1");

        Set<String> recipients = new HashSet<>();
        recipients.add("user.user1");
        obj.setRecipients(recipients);

        Set<String> recipientsRes = new HashSet<>();
        recipientsRes.add("user.user1");

        Map<String, String> detailsRes = new HashMap<>();
        detailsRes.put("domain", "dom1");
        detailsRes.put("role", "role1");

        assertEquals(obj.getRecipients(), recipientsRes);
        assertEquals(obj.getDetails(), detailsRes);

        assertTrue(obj.toString().contains("recipients=[user.user1]"));
        assertTrue(obj.toString().contains("role=role1"));
        assertTrue(obj.toString().contains("domain=dom1"));

        Notification obj2 = new Notification();
        obj2.addDetails("role", "role2");
        obj2.addRecipient("user.user5");
        obj2.addRecipient("user.user6");

        assertFalse(obj.equals(obj2));
        assertTrue(obj2.getRecipients().contains("user.user5"));
        assertTrue(obj2.getRecipients().contains("user.user6"));

        Notification obj3 = new Notification();
        obj3.addDetails("domain", "dom1").addDetails("role", "role1");
        obj3.addRecipient("user.user1");

        assertTrue(obj.equals(obj));
        String a = "";
        assertFalse(obj.equals(a));
        assertTrue(obj.equals(obj3));

        assertEquals(obj.hashCode(), obj3.hashCode());

        Notification obj4 = new Notification();
        List<String> testlist = Arrays.asList("user.a", "user.a", "user.b");
        obj4.getRecipients().addAll(testlist);
        assertEquals(obj4.getRecipients().size(), 2);
    }
}