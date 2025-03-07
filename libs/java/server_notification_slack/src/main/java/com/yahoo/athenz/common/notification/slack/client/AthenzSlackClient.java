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

import com.slack.api.methods.SlackApiException;
import com.slack.api.methods.response.users.UsersLookupByEmailResponse;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.slack.api.Slack;
import com.slack.api.methods.request.chat.ChatPostMessageRequest;
import com.slack.api.methods.response.chat.ChatPostMessageResponse;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
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

    public AthenzSlackClient(PrivateKeyStore privateKeyStore, boolean skipTokenRefresh) {
        this.privateKeyStore = privateKeyStore;
        this.slackClient = Slack.getInstance();
        this.maxRetries = Integer.parseInt(System.getProperty(SLACK_CLIENT_MAX_RETRIES, "3"));
        this.rateLimitDelay = Long.parseLong(System.getProperty(SLACK_CLIENT_RATE_LIMIT_DELAY, "1000"));
        refreshToken();
        if (!skipTokenRefresh) {
            refreshTokenTimerTask();
        }
    }

    public AthenzSlackClient(PrivateKeyStore privateKeyStore, Slack slackClient) {
        this.slackClient = slackClient;
        this.privateKeyStore = privateKeyStore;
        this.maxRetries = Integer.parseInt(System.getProperty(SLACK_CLIENT_MAX_RETRIES, "3"));
        this.rateLimitDelay = Long.parseLong(System.getProperty(SLACK_CLIENT_RATE_LIMIT_DELAY, "1000"));
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

    /**
     * Sends a message to multiple recipients. If a recipient is an email address,
     * it first looks up the corresponding Slack user ID.
     *
     * @param recipients Collection of recipients (either Slack channel IDs or email addresses)
     * @param message The message to send in Slack blocks format
     * @return true if message was sent successfully to all recipients, false otherwise
     */
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

        } catch (SlackApiException e) {
            if (handleRateLimit(e, "send message", retriesLeft)) {
                return sendMessageToDestination(destination, message, retriesLeft - 1);
            }
            LOGGER.error("Failed to send message to slack destination {}: {}", destination, e.getMessage());
            return false;
        } catch (IOException e) {
            LOGGER.error("Failed to send message to slack destination {}: {}", destination, e);
            return false;
        }
    }

    /**
     * Looks up a Slack user ID by email address.
     *
     * @param email The email address to look up
     * @return The Slack user ID if found, null otherwise
     */
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

            LOGGER.error("Unable to lookup slack user ID by email for {} : {}", email, response.getError());
            return null;

        } catch (SlackApiException e) {
            if (handleRateLimit(e, "fetch user ID", retriesLeft)) {
                return fetchUserIdFromEmailWithRetry(email, retriesLeft - 1);
            }
            LOGGER.error("Unable to lookup user by email for {} : {}", email, e.getMessage());
            return null;
        } catch (Exception e) {
            LOGGER.error("Unable to lookup user by email for {} : {}", email, e);
            return null;
        }
    }

    private boolean handleSlackResponse(String error, int retriesLeft, String operation) {
        if (retriesLeft <= 0) {
            return false;
        }

        if (SLACK_API_INVALID_AUTH_ERROR.equals(error) || SLACK_API_TOKEN_EXPIRED_ERROR.equals(error)) {
            LOGGER.warn("Token expired during {}, refreshing and retrying... ({} retries left)",
                    operation, retriesLeft - 1);
            refreshToken();
            return true;
        }

        if (SLACK_API_RATE_LIMIT_ERROR.equals(error)) {
            try {
                LOGGER.warn("Rate limited during {}, retrying after {}ms delay... ({} retries left)",
                        operation, rateLimitDelay, retriesLeft - 1);
                Thread.sleep(rateLimitDelay);
                return true;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.error("Interrupted while handling rate limit retry for {}", operation);
                return false;
            }
        }

        // try refreshing token if error doesn't match but isn't empty
        if (!StringUtil.isEmpty(error)) {
            refreshToken();
            return true;
        }

        return false;
    }

    private boolean handleRateLimit(SlackApiException e, String operation, int retriesLeft) {
        if (retriesLeft <= 0 || e.getResponse().code() != SLACK_API_RATE_LIMIT_CODE) {
            return false;
        }

        String retryAfter = e.getResponse().header("Retry-After");
        if (retryAfter == null) {
            return false;
        }

        try {
            int retryDelaySeconds = Integer.parseInt(retryAfter);
            LOGGER.warn("Rate limited during {}, retrying after {}s delay... ({} retries left)",
                    operation, retryDelaySeconds, retriesLeft - 1);
            Thread.sleep(retryDelaySeconds * 1000);
            return true;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            LOGGER.error("Interrupted while handling rate limit retry for {}", operation);
            return false;
        } catch (NumberFormatException ne) {
            LOGGER.error("Invalid Retry-After header value: {}", retryAfter);
            return false;
        }
    }
}
