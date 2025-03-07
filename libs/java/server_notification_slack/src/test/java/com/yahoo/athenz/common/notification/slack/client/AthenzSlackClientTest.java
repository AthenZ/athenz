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

import com.slack.api.RequestConfigurator;
import com.slack.api.Slack;
import com.slack.api.methods.MethodsClient;
import com.slack.api.methods.SlackApiException;
import com.slack.api.methods.request.chat.ChatPostMessageRequest;
import com.slack.api.methods.request.users.UsersLookupByEmailRequest;
import com.slack.api.methods.response.chat.ChatPostMessageResponse;
import com.slack.api.methods.response.users.UsersLookupByEmailResponse;
import com.slack.api.model.User;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.notification.slack.SlackNotificationConsts;
import okhttp3.Headers;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class AthenzSlackClientTest {

    @Mock
    private PrivateKeyStore mockKeyStore;

    @Mock
    private Slack mockSlack;

    @Mock
    private MethodsClient mockMethods;

    private AthenzSlackClient slackClient;
    private static final String TEST_TOKEN = "test-token";

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        // Setup system properties
        System.setProperty("athenz.slack.max_retries", "3");
        System.setProperty("athenz.slack.rate_limit_delay_ms", "100");
        System.setProperty("slack.bot.token.app.name", "test-app");
        System.setProperty("slack.bot.token.keygroup.name", "test-group");
        System.setProperty("slack.bot.token.key.name", "test-key");

        when(mockKeyStore.getSecret(anyString(), anyString(), anyString()))
                .thenReturn(TEST_TOKEN.toCharArray());
        when(mockSlack.methods(anyString())).thenReturn(mockMethods);

        slackClient = new AthenzSlackClient(mockKeyStore, mockSlack);
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty("athenz.slack.max_retries");
        System.clearProperty("athenz.slack.rate_limit_delay_ms");
        System.clearProperty("slack.bot.token.app.name");
        System.clearProperty("slack.bot.token.keygroup.name");
        System.clearProperty("slack.bot.token.key.name");
    }

    @Test
    public void testSuccessfulMessageSend() throws IOException, SlackApiException {
        ChatPostMessageResponse mockResponse = new ChatPostMessageResponse();
        mockResponse.setOk(true);
        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(mockResponse);

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertTrue(result);
        verify(mockMethods, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testMultipleRecipientsMessageSend() throws IOException, SlackApiException {
        ChatPostMessageResponse mockResponse = new ChatPostMessageResponse();
        mockResponse.setOk(true);
        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(mockResponse);

        boolean result = slackClient.sendMessage(
                new HashSet<>(Arrays.asList("channel1", "channel2")), "test message");
        assertTrue(result);
        verify(mockMethods, times(2)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testRateLimitRetryWithHeader() throws IOException, SlackApiException {
        Headers headers = new Headers.Builder()
                .add("Retry-After", "1")
                .build();
        Response httpResponse = new Response.Builder()
                .request(new Request.Builder().url("http://test.com").build())
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .headers(headers)
                .build();
        SlackApiException rateLimitException = new SlackApiException(httpResponse, "Rate limited");

        // Setup success response
        ChatPostMessageResponse successResponse = new ChatPostMessageResponse();
        successResponse.setOk(true);

        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenThrow(rateLimitException)
                .thenReturn(successResponse);

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertTrue(result);
        verify(mockMethods, times(2)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testRateLimitRetryWithErrorString() throws IOException, SlackApiException {
        ChatPostMessageResponse rateLimitResponse = new ChatPostMessageResponse();
        rateLimitResponse.setOk(false);
        rateLimitResponse.setError(SlackNotificationConsts.SLACK_API_RATE_LIMIT_ERROR);

        ChatPostMessageResponse successResponse = new ChatPostMessageResponse();
        successResponse.setOk(true);

        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenReturn(rateLimitResponse)
                .thenReturn(successResponse);

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertTrue(result);
        verify(mockMethods, times(2)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testMaxRetriesExceeded() throws IOException, SlackApiException {
        ChatPostMessageResponse rateLimitResponse = new ChatPostMessageResponse();
        rateLimitResponse.setOk(false);
        rateLimitResponse.setError(SlackNotificationConsts.SLACK_API_RATE_LIMIT_ERROR);

        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(rateLimitResponse);

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertFalse(result);
        verify(mockMethods, times(4)).chatPostMessage(any(ChatPostMessageRequest.class)); // Initial + 3 retries
    }

    @Test
    public void testInvalidRetryAfterHeader() throws IOException, SlackApiException {
        Headers headers = new Headers.Builder()
                .add("Retry-After", "invalid")
                .build();
        Response httpResponse = new Response.Builder()
                .request(new Request.Builder().url("http://test.com").build())
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .headers(headers)
                .build();

        SlackApiException rateLimitException = new SlackApiException(httpResponse, "Rate limited");
        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenThrow(rateLimitException);

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertFalse(result);
        verify(mockMethods, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testTokenRefreshOnAuthError() throws IOException, SlackApiException {
        ChatPostMessageResponse authErrorResponse = new ChatPostMessageResponse();
        authErrorResponse.setOk(false);
        authErrorResponse.setError("invalid_auth");

        ChatPostMessageResponse successResponse = new ChatPostMessageResponse();
        successResponse.setOk(true);

        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenReturn(authErrorResponse)
                .thenReturn(successResponse);

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertTrue(result);
        verify(mockMethods, times(2)).chatPostMessage(any(ChatPostMessageRequest.class));
        verify(mockKeyStore, times(2)).getSecret(anyString(), anyString(), anyString());
    }

    @Test
    public void testTokenRefreshFailure() throws IOException, SlackApiException {
        when(mockKeyStore.getSecret(anyString(), anyString(), anyString()))
                .thenReturn(null);

        ChatPostMessageResponse authErrorResponse = new ChatPostMessageResponse();
        authErrorResponse.setOk(false);
        authErrorResponse.setError("invalid_auth");

        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(authErrorResponse);

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertFalse(result);
    }

    @Test
    public void testSuccessfulEmailLookup() throws IOException, SlackApiException {
        UsersLookupByEmailResponse mockEmailResponse = new UsersLookupByEmailResponse();
        mockEmailResponse.setOk(true);
        User mockUser = new User();
        mockUser.setId("U123456");
        mockEmailResponse.setUser(mockUser);
        when(mockMethods.usersLookupByEmail((RequestConfigurator<UsersLookupByEmailRequest.UsersLookupByEmailRequestBuilder>)any())).thenReturn(mockEmailResponse);

        ChatPostMessageResponse mockMessageResponse = new ChatPostMessageResponse();
        mockMessageResponse.setOk(true);
        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(mockMessageResponse);

        boolean result = slackClient.sendMessage(
                Collections.singleton("user@example.com"), "test message");
        assertTrue(result);
        verify(mockMethods, times(1)).usersLookupByEmail((RequestConfigurator<UsersLookupByEmailRequest.UsersLookupByEmailRequestBuilder>)any());
        verify(mockMethods, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testEmailLookupFailure() throws IOException, SlackApiException {
        UsersLookupByEmailResponse failResponse = new UsersLookupByEmailResponse();
        failResponse.setOk(false);
        failResponse.setError("users_not_found");

        when(mockMethods.usersLookupByEmail((RequestConfigurator<UsersLookupByEmailRequest.UsersLookupByEmailRequestBuilder>) any())).thenReturn(failResponse);

        boolean result = slackClient.sendMessage(
                Collections.singleton("invalid@example.com"), "test message");
        assertFalse(result);
        verify(mockMethods, times(4)).usersLookupByEmail((RequestConfigurator<UsersLookupByEmailRequest.UsersLookupByEmailRequestBuilder>) any());
        verify(mockMethods, never()).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testIOException() throws IOException, SlackApiException {
        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenThrow(new IOException("Network error"));

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertFalse(result);
        verify(mockMethods, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testGenericSlackApiException() throws IOException, SlackApiException {
        Response httpResponse = new Response.Builder()
                .request(new Request.Builder().url("http://test.com").build())
                .protocol(Protocol.HTTP_1_1)
                .code(500)
                .message("Internal Server Error")
                .build();

        SlackApiException apiException = new SlackApiException(httpResponse, "Internal error");
        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenThrow(apiException);

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertFalse(result);
        verify(mockMethods, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testEmptyMessage() throws IOException, SlackApiException {
        ChatPostMessageResponse mockResponse = new ChatPostMessageResponse();
        mockResponse.setOk(true);
        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(mockResponse);

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "");
        assertTrue(result);
        verify(mockMethods, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testVeryLongMessage() throws IOException, SlackApiException {
        StringBuilder longMessage = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longMessage.append("test message content ");
        }

        ChatPostMessageResponse mockResponse = new ChatPostMessageResponse();
        mockResponse.setOk(true);
        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(mockResponse);

        boolean result = slackClient.sendMessage(
                Collections.singleton("test-channel"), longMessage.toString());
        assertTrue(result);
        verify(mockMethods, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testSpecialCharactersInMessage() throws IOException, SlackApiException {
        ChatPostMessageResponse mockResponse = new ChatPostMessageResponse();
        mockResponse.setOk(true);
        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(mockResponse);

        boolean result = slackClient.sendMessage(
                Collections.singleton("test-channel"), "Special chars: !@#$%^&*()_+ \n\t");
        assertTrue(result);
        verify(mockMethods, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testInterruptedExceptionDuringRateLimitDelay() throws IOException, SlackApiException {
        ChatPostMessageResponse rateLimitResponse = new ChatPostMessageResponse();
        rateLimitResponse.setOk(false);
        rateLimitResponse.setError("ratelimited");

        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenReturn(rateLimitResponse);

        Thread.currentThread().interrupt();

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertFalse(result);
        verify(mockMethods, times(4)).chatPostMessage(any(ChatPostMessageRequest.class));

        assertTrue(Thread.interrupted()); // clears interrupted status
    }

    @Test
    public void testInterruptedExceptionDuring429RateLimit() throws IOException, SlackApiException {
        Headers headers = new Headers.Builder()
                .add("Retry-After", "1")
                .build();
        Response httpResponse = new Response.Builder()
                .request(new Request.Builder().url("http://test.com").build())
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .headers(headers)
                .build();
        SlackApiException rateLimitException = new SlackApiException(httpResponse, "Rate limited");

        when(mockMethods.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenThrow(rateLimitException);

        Thread.currentThread().interrupt();

        boolean result = slackClient.sendMessage(Collections.singleton("test-channel"), "test message");
        assertFalse(result);
        verify(mockMethods, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));

        assertTrue(Thread.interrupted()); // clears interrupted status
    }

    @Test
    public void testEmailLookupWithInterruption() throws IOException, SlackApiException {
        UsersLookupByEmailResponse rateLimitResponse = new UsersLookupByEmailResponse();
        rateLimitResponse.setOk(false);
        rateLimitResponse.setError("ratelimited");

        when(mockMethods.usersLookupByEmail((RequestConfigurator<UsersLookupByEmailRequest.UsersLookupByEmailRequestBuilder>) any()))
                .thenReturn(rateLimitResponse);

        // Create a thread that will interrupt our test thread
        Thread.currentThread().interrupt();

        boolean result = slackClient.sendMessage(
                Collections.singleton("user@example.com"), "test message");
        assertFalse(result);
        verify(mockMethods, times(4)).usersLookupByEmail((RequestConfigurator<UsersLookupByEmailRequest.UsersLookupByEmailRequestBuilder>) any());
        verify(mockMethods, never()).chatPostMessage(any(ChatPostMessageRequest.class));

        // Clear the interrupted status for other tests
        assertTrue(Thread.interrupted()); // clears interrupted status
    }

}
