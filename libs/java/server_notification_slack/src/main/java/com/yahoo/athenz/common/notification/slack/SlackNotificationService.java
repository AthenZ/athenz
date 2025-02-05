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

package com.yahoo.athenz.common.notification.slack;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.notification.slack.client.AthenzSlackClient;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationSlackMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/*
 * Slack based notification service.
 */
public class SlackNotificationService implements NotificationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SlackNotificationService.class);
    private final AthenzSlackClient slackClient;

    public SlackNotificationService(PrivateKeyStore privateKeyStore) {
        this.slackClient = new AthenzSlackClient(privateKeyStore, false);
    }

    public SlackNotificationService(AthenzSlackClient slackClient) {
        this.slackClient = slackClient;
    }

    @Override
    public boolean notify(Notification notification) {
        if (notification == null || !Notification.ConsolidatedBy.DOMAIN.equals(notification.getConsolidatedBy())) {
            return false;
        }

        NotificationSlackMessage notificationSlackMessage = notification.getNotificationAsSlackMessage();
        if (notificationSlackMessage == null) {
            return false;
        }

        Set<String> recipients = notificationSlackMessage.getRecipients();
        final String message = notificationSlackMessage.getMessage();

        // if our list of recipients is empty then we have nothing to do,
        // but we want to log it for debugging purposes

        if (recipients.isEmpty()) {
            LOGGER.error("No recipients specified in the notification. notification type={}", notification.getType());
            return false;
        }

        if (sendSlackMessage(recipients, message)) {
            LOGGER.info("Successfully sent slack notification. Type={}, Recipients={}", notification.getType(), recipients);
            return true;
        } else {
            LOGGER.error("Failed sending slack notification. Type={}, Recipients={}", notification.getType(), recipients);
            return false;
        }
    }

    public boolean sendSlackMessage(Set<String> recipients, String message) {
        return slackClient.sendMessage(recipients, message);
    }

}
