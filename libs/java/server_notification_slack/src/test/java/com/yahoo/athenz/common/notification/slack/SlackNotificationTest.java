package com.yahoo.athenz.common.notification.slack;

import org.testng.annotations.Test;

import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.*;
import static org.testng.Assert.assertNotEquals;

public class SlackNotificationTest {

    @Test
    public void testSlackNotification() {
        Set<String> recipients = new HashSet<>();
        recipients.add("U123456");

        SlackNotification slackNotification1 = new SlackNotification("blocks", recipients);
        SlackNotification slackNotification2 = new SlackNotification("blocks", recipients);

        assertEquals(slackNotification1.hashCode(), slackNotification1.hashCode());
        assertEquals(slackNotification1.getBlocks(), "blocks");
        assertEquals(slackNotification1.getFullyQualifiedRecipients(), recipients);

        assertEquals(slackNotification1, slackNotification2);
        assertEquals(slackNotification1, slackNotification1);

        assertFalse(slackNotification1.equals(null));
        assertFalse(slackNotification1.equals("null:"));

        slackNotification2 = new SlackNotification("blocks-1", recipients);
        assertNotEquals(slackNotification1, slackNotification2);

        slackNotification2 = new SlackNotification("blocks", recipients);
        assertEquals(slackNotification1, slackNotification2);

        Set<String> recipients2 = new HashSet<>();
        recipients2.add("U4567");
        slackNotification2 = new SlackNotification("subject", recipients2);
        assertNotEquals(slackNotification1, slackNotification2);
    }
}
