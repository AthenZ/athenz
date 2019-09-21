package com.yahoo.athenz.common.server.notification;

import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.testng.Assert.*;

public class NotificationTest {

    @Test
    public void testNotificationMethods() {
        Notification obj = new Notification("TEST_TYPE");

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

        assertEquals(obj.getType(), "TEST_TYPE");
        assertEquals(obj.getRecipients(), recipientsRes);
        assertEquals(obj.getDetails(), detailsRes);

        assertTrue(obj.toString().contains("type='TEST_TYPE'"));
        assertTrue(obj.toString().contains("recipients=[user.user1]"));
        assertTrue(obj.toString().contains("role=role1"));
        assertTrue(obj.toString().contains("domain=dom1"));

        Notification obj2 = new Notification("TEST_TYPE", null, null);
        obj2.addDetails("role", "role2");
        obj2.addRecipient("user.user5");
        obj2.addRecipient("user.user6");

        assertFalse(obj.equals(obj2));
        assertTrue(obj2.getRecipients().contains("user.user5"));
        assertTrue(obj2.getRecipients().contains("user.user6"));
    }
}