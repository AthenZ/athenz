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

public class NotificationSlackMessageTest {

    @Test
    public void testNotificationSlackMessage() {

        Set<String> recipients = new HashSet<>();
        recipients.add("email1@athenz.io");
        NotificationSlackMessage slackMessage1 = new NotificationSlackMessage("message1", recipients);
        NotificationSlackMessage slackMessage2 = new NotificationSlackMessage("message1", recipients);

        assertEquals(slackMessage1.hashCode(), slackMessage2.hashCode());
        assertEquals(slackMessage1.getMessage(), "message1");
        assertEquals(slackMessage1.getRecipients(), recipients);

        assertEquals(slackMessage1, slackMessage2);
        assertEquals(slackMessage1, slackMessage1);

        assertFalse(slackMessage1.equals(null));

        slackMessage2 = new NotificationSlackMessage("message2", recipients);
        assertNotEquals(slackMessage1, slackMessage2);

        slackMessage2 = new NotificationSlackMessage("message1", recipients);
        assertEquals(slackMessage1, slackMessage2);

        Set<String> recipients2 = new HashSet<>();
        recipients2.add("slack-channel");
        slackMessage2 = new NotificationSlackMessage("message1", recipients2);
        assertNotEquals(slackMessage1, slackMessage2);
    }
}