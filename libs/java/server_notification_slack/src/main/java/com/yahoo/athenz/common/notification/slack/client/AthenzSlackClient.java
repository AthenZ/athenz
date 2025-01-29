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

package com.yahoo.athenz.common.notification.slack.client;

import com.slack.api.methods.response.users.UsersLookupByEmailResponse;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.slack.api.Slack;
import com.slack.api.methods.request.chat.ChatPostMessageRequest;
import com.slack.api.methods.response.chat.ChatPostMessageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.notification.slack.SlackNotificationConsts.*;

public class AthenzSlackClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(AthenzSlackClient.class);
    private Slack slackClient;
    private volatile String accessToken;
    private PrivateKeyStore privateKeyStore;
    private final int maxRetries;
    private final long rateLimitDelay;

    public AthenzSlackClient(PrivateKeyStore privateKeyStore) {
        this.privateKeyStore = privateKeyStore;
        this.slackClient = Slack.getInstance();
        this.maxRetries = Integer.parseInt(System.getProperty("athenz.slack.max_retries", "3"));
        this.rateLimitDelay = Long.parseLong(System.getProperty("athenz.slack.rate_limit_delay_ms", "1000"));
        refreshToken();
        refreshTokenTimerTask();
    }

    public AthenzSlackClient(PrivateKeyStore privateKeyStore, Slack slackClient) {
        this.slackClient = slackClient;
        this.privateKeyStore = privateKeyStore;
        this.maxRetries = Integer.parseInt(System.getProperty("athenz.slack.max_retries", "3"));
        this.rateLimitDelay = Long.parseLong(System.getProperty("athenz.slack.rate_limit_delay_ms", "1000"));
        refreshToken();
        refreshTokenTimerTask();
    }

    void refreshToken() {
        final String appName = System.getProperty(SLACK_BOT_TOKEN_APP_NAME, "");
        final String keygroupName = System.getProperty(SLACK_BOT_TOKEN_KEYGROUP_NAME, "");
        final String keyName = System.getProperty(SLACK_BOT_TOKEN_KEY_NAME, "");

        char[] newToken = privateKeyStore.getSecret(appName, keygroupName, keyName);
        if (newToken == null) {
            LOGGER.error("Error while refreshing slack token, token is null");
            return;
        }

        this.accessToken = String.valueOf(newToken);
    }

    private void refreshTokenTimerTask() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

        long periodBetweenExecutions = Long.parseLong(
                System.getProperty(PROP_SLACK_FETCH_TOKEN_PERIOD_BETWEEN_EXECUTIONS, DEFAULT_SLACK_FETCH_TOKEN_PERIOD_BETWEEN_EXECUTIONS));

        executor.scheduleAtFixedRate(this::refreshToken,
                periodBetweenExecutions, periodBetweenExecutions, TimeUnit.SECONDS);
    }

    public boolean sendMessage(Collection<String> recipients, String message) {
        boolean allSuccessful = true;
        for (String recipient : recipients) {
            String destination = recipient;

            // If recipient looks like an email address, fetch the user ID
            if (recipient.contains("@")) {
                destination = fetchUserIdFromEmail(recipient);
                if (destination == null) {
                    LOGGER.error("Failed to find user ID for email: {}", recipient);
                    allSuccessful = false;
                    continue;
                }
            }

            if (!sendMessageToDestination(destination, message, maxRetries)) {
                allSuccessful = false;
            }
        }
        return allSuccessful;
    }

    private boolean sendMessageToDestination(String destination, String message, int retriesLeft) {
        ChatPostMessageRequest request = ChatPostMessageRequest.builder()
                .channel(destination)
                .blocksAsString(message)
                .build();

        try {
            ChatPostMessageResponse response = slackClient.methods(accessToken).chatPostMessage(request);

            if (response.isOk()) {
                return true;
            }

            if (handleSlackResponse(response.getError(), retriesLeft, "send message")) {
                return sendMessageToDestination(destination, message, retriesLeft - 1);
            }

            LOGGER.error("Failed to send message to slack destination {}: {}", destination, response.getError());
            return false;

        } catch (Exception e) {
            LOGGER.error("Failed to send message to slack destination {}: {}", destination, e.getMessage());
            return false;
        }
    }

    private boolean handleSlackResponse(String error, int retriesLeft, String operation) {
        if (retriesLeft <= 0) {
            return false;
        }

        try {
            if ("invalid_auth".equals(error)) {
                LOGGER.warn("Token expired during {}, refreshing and retrying... ({} retries left)",
                        operation, retriesLeft - 1);
                refreshToken();
                return true;
            }

            if ("ratelimited".equals(error)) {
                LOGGER.warn("Rate limited during {}, retrying after {}ms delay... ({} retries left)",
                        operation, rateLimitDelay, retriesLeft - 1);
                Thread.sleep(rateLimitDelay);
                return true;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.error("Interrupted while handling retry for {}", operation);
        }
        return false;
    }

    public String fetchUserIdFromEmail(String email) {
        return fetchUserIdFromEmailWithRetry(email, maxRetries);
    }

    private String fetchUserIdFromEmailWithRetry(String email, int retriesLeft) {
        try {
            UsersLookupByEmailResponse response = slackClient.methods(accessToken)
                    .usersLookupByEmail(req -> req.email(email));

            if (response.isOk()) {
                return response.getUser().getId();
            }

            if (handleSlackResponse(response.getError(), retriesLeft, "fetch user ID")) {
                return fetchUserIdFromEmailWithRetry(email, retriesLeft - 1);
            }

            LOGGER.error("Unable to lookup slack user ID by email: {}", response.getError());
            return null;

        } catch (Exception e) {
            LOGGER.error("Unable to lookup user by email: {}", e.getMessage());
            return null;
        }
    }

}
