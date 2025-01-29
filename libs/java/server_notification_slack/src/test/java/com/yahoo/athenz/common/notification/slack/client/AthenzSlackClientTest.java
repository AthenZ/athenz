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
import com.slack.api.methods.response.chat.ChatPostMessageResponse;
import com.slack.api.methods.response.users.UsersLookupByEmailResponse;
import com.slack.api.model.User;
import com.yahoo.athenz.auth.PrivateKeyStore;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertNotNull;

public class AthenzSlackClientTest {

    @Test
    public void testAthenzSlackClientNotNull() {
        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString())).thenReturn("access-token-1".toCharArray());
        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore);
        assertNotNull(athenzSlackClient);
    }

    @Test
    public void testSendMessageNullToken() throws SlackApiException, IOException {
        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        String message = "test slack message";

        ChatPostMessageResponse chatPostMessageResponse = mock(ChatPostMessageResponse.class);
        Mockito.when(chatPostMessageResponse.isOk()).thenReturn(false);

        Slack slackClient = mock(Slack.class);
        MethodsClient slackMethodClient = mock(MethodsClient.class);
        when(slackMethodClient.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(chatPostMessageResponse);
        when(slackClient.methods(null)).thenReturn(slackMethodClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString())).thenReturn(null);
        ArgumentCaptor<ChatPostMessageRequest> captor = ArgumentCaptor.forClass(ChatPostMessageRequest.class);

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertFalse(athenzSlackClient.sendMessage(recipients, message));
        Mockito.verify(slackMethodClient, atLeastOnce()).chatPostMessage(captor.capture());
    }

    @Test
    public void testSendMessageSuccess() throws SlackApiException, IOException {
        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        String message = "test slack message";

        ChatPostMessageResponse chatPostMessageResponse = mock(ChatPostMessageResponse.class);
        Mockito.when(chatPostMessageResponse.isOk()).thenReturn(true);

        Slack slackClient = mock(Slack.class);
        MethodsClient slackMethodClient = mock(MethodsClient.class);
        when(slackMethodClient.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(chatPostMessageResponse);
        when(slackClient.methods(anyString())).thenReturn(slackMethodClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString())).thenReturn("token-1".toCharArray());
        ArgumentCaptor<ChatPostMessageRequest> captor = ArgumentCaptor.forClass(ChatPostMessageRequest.class);

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertTrue(athenzSlackClient.sendMessage(recipients, message));
        Mockito.verify(slackMethodClient, atLeastOnce()).chatPostMessage(captor.capture());
    }

    @Test
    public void testSendMessageFailure() throws SlackApiException, IOException {
        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        String message = "test slack message";

        ChatPostMessageResponse chatPostMessageResponse = mock(ChatPostMessageResponse.class);
        Mockito.when(chatPostMessageResponse.isOk()).thenReturn(false);

        Slack slackClient = mock(Slack.class);
        MethodsClient slackMethodClient = mock(MethodsClient.class);
        when(slackMethodClient.chatPostMessage(any(ChatPostMessageRequest.class))).thenReturn(chatPostMessageResponse);
        when(slackClient.methods(anyString())).thenReturn(slackMethodClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString())).thenReturn("token-1".toCharArray());
        ArgumentCaptor<ChatPostMessageRequest> captor = ArgumentCaptor.forClass(ChatPostMessageRequest.class);

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertFalse(athenzSlackClient.sendMessage(recipients, message));
        Mockito.verify(slackMethodClient, atLeastOnce()).chatPostMessage(captor.capture());
    }

    @Test
    public void testSendMessageException() throws SlackApiException, IOException {
        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2", "user.user3"));
        String message = "test slack message";

        MethodsClient slackMethodsClient = mock(MethodsClient.class);
        when(slackMethodsClient.chatPostMessage(any(ChatPostMessageRequest.class))).thenThrow(new IOException());

        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodsClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString())).thenReturn("token-1".toCharArray());
        ArgumentCaptor<ChatPostMessageRequest> captor = ArgumentCaptor.forClass(ChatPostMessageRequest.class);

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertFalse(athenzSlackClient.sendMessage(recipients, message));
        Mockito.verify(slackMethodsClient, atLeastOnce()).chatPostMessage(captor.capture());
    }

    @Test
    public void testFetchUserIdFromEmail() throws SlackApiException, IOException {
        String message = "test slack message";

        UsersLookupByEmailResponse usersLookupByEmailResponse = mock(UsersLookupByEmailResponse.class);
        Mockito.when(usersLookupByEmailResponse.isOk()).thenReturn(true);
        User slackUser = new User();
        slackUser.setId("slackId");

        Mockito.when(usersLookupByEmailResponse.getUser()).thenReturn(slackUser);

        MethodsClient slackMethodsClient = mock(MethodsClient.class);

        when(slackMethodsClient.usersLookupByEmail(any(RequestConfigurator.class))).thenReturn(usersLookupByEmailResponse);
        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodsClient);
        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString())).thenReturn("token-1".toCharArray());

        ArgumentCaptor<RequestConfigurator> captor = ArgumentCaptor.forClass(RequestConfigurator.class);

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertEquals(athenzSlackClient.fetchUserIdFromEmail(message), "slackId");
        Mockito.verify(slackMethodsClient, atLeastOnce()).usersLookupByEmail(captor.capture());
    }

    @Test
    public void testFetchUserIdFromEmailNotOk() throws SlackApiException, IOException {
        String message = "test slack message";

        UsersLookupByEmailResponse usersLookupByEmailResponse = mock(UsersLookupByEmailResponse.class);
        Mockito.when(usersLookupByEmailResponse.isOk()).thenReturn(false);

        MethodsClient slackMethodsClient = mock(MethodsClient.class);

        when(slackMethodsClient.usersLookupByEmail(any(RequestConfigurator.class))).thenReturn(usersLookupByEmailResponse);
        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodsClient);

        ArgumentCaptor<RequestConfigurator> captor = ArgumentCaptor.forClass(RequestConfigurator.class);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString())).thenReturn("token-1".toCharArray());
        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertNull(athenzSlackClient.fetchUserIdFromEmail(message));
        Mockito.verify(slackMethodsClient, atLeastOnce()).usersLookupByEmail(captor.capture());
    }

    @Test
    public void testFetchUserIdFromEmailException() throws SlackApiException, IOException {
        String message = "test slack message";

        UsersLookupByEmailResponse usersLookupByEmailResponse = mock(UsersLookupByEmailResponse.class);
        Mockito.when(usersLookupByEmailResponse.isOk()).thenReturn(false);

        MethodsClient slackMethodsClient = mock(MethodsClient.class);

        when(slackMethodsClient.usersLookupByEmail(any(RequestConfigurator.class))).thenThrow(new IOException());
        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodsClient);

        ArgumentCaptor<RequestConfigurator> captor = ArgumentCaptor.forClass(RequestConfigurator.class);
        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString())).thenReturn("token-1".toCharArray());

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertNull(athenzSlackClient.fetchUserIdFromEmail(message));
        Mockito.verify(slackMethodsClient, atLeastOnce()).usersLookupByEmail(captor.capture());
    }

    @Test
    public void testSendMessageWithTokenExpiration() throws SlackApiException, IOException {
        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2"));
        String message = "test slack message";

        // First response with expired token
        ChatPostMessageResponse failedResponse = mock(ChatPostMessageResponse.class);
        when(failedResponse.isOk()).thenReturn(false);
        when(failedResponse.getError()).thenReturn("invalid_auth");

        // Second response after token refresh
        ChatPostMessageResponse successResponse = mock(ChatPostMessageResponse.class);
        when(successResponse.isOk()).thenReturn(true);

        MethodsClient slackMethodClient = mock(MethodsClient.class);
        when(slackMethodClient.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenReturn(failedResponse)  // First attempt fails
                .thenReturn(successResponse); // Second attempt succeeds

        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString()))
                .thenReturn("token-1".toCharArray())
                .thenReturn("token-2".toCharArray()); // New token after refresh

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertTrue(athenzSlackClient.sendMessage(recipients, message));

        // Verify that chatPostMessage was called thrice
        verify(slackMethodClient, times(3)).chatPostMessage(any(ChatPostMessageRequest.class));
        // Verify that token was refreshed
        verify(privateKeyStore, times(2)).getSecret(anyString(), anyString(), anyString());
    }

    @Test
    public void testSendMessageWithRateLimit() throws SlackApiException, IOException {
        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1", "user.user2"));
        String message = "test slack message";

        // First response with rate limit
        ChatPostMessageResponse rateLimitResponse = mock(ChatPostMessageResponse.class);
        when(rateLimitResponse.isOk()).thenReturn(false);
        when(rateLimitResponse.getError()).thenReturn("ratelimited");

        // Second response after delay
        ChatPostMessageResponse successResponse = mock(ChatPostMessageResponse.class);
        when(successResponse.isOk()).thenReturn(true);

        MethodsClient slackMethodClient = mock(MethodsClient.class);
        when(slackMethodClient.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenReturn(rateLimitResponse)  // First attempt fails
                .thenReturn(successResponse);   // Second attempt succeeds

        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString()))
                .thenReturn("token-1".toCharArray());

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertTrue(athenzSlackClient.sendMessage(recipients, message));

        // Verify that chatPostMessage was called twice
        verify(slackMethodClient, times(3)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testFetchUserIdFromEmailWithTokenExpiration() throws SlackApiException, IOException {
        String email = "test@example.com";

        // First response with expired token
        UsersLookupByEmailResponse failedResponse = mock(UsersLookupByEmailResponse.class);
        when(failedResponse.isOk()).thenReturn(false);
        when(failedResponse.getError()).thenReturn("invalid_auth");

        // Second response after token refresh
        UsersLookupByEmailResponse successResponse = mock(UsersLookupByEmailResponse.class);
        when(successResponse.isOk()).thenReturn(true);
        User user = new User();
        user.setId("U123456");
        when(successResponse.getUser()).thenReturn(user);

        MethodsClient slackMethodClient = mock(MethodsClient.class);
        when(slackMethodClient.usersLookupByEmail(any(RequestConfigurator.class)))
                .thenReturn(failedResponse)
                .thenReturn(successResponse);

        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString()))
                .thenReturn("token-1".toCharArray())
                .thenReturn("token-2".toCharArray());

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertEquals(athenzSlackClient.fetchUserIdFromEmail(email), "U123456");

        // Verify that usersLookupByEmail was called twice
        verify(slackMethodClient, times(2)).usersLookupByEmail(any(RequestConfigurator.class));
        // Verify that token was refreshed
        verify(privateKeyStore, times(2)).getSecret(anyString(), anyString(), anyString());
    }

    @Test
    public void testMaxRetriesExceeded() throws SlackApiException, IOException {
        Set<String> recipients = new HashSet<>(Arrays.asList("user.user1"));
        String message = "test slack message";

        // All responses fail with rate limit
        ChatPostMessageResponse rateLimitResponse = mock(ChatPostMessageResponse.class);
        when(rateLimitResponse.isOk()).thenReturn(false);
        when(rateLimitResponse.getError()).thenReturn("ratelimited");

        MethodsClient slackMethodClient = mock(MethodsClient.class);
        when(slackMethodClient.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenReturn(rateLimitResponse);

        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString()))
                .thenReturn("token-1".toCharArray());

        // Set max retries to 2 via system property
        System.setProperty("athenz.slack.max_retries", "2");
        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);

        assertFalse(athenzSlackClient.sendMessage(recipients, message));

        // Verify that chatPostMessage was called exactly 3 times (initial + 2 retries)
        verify(slackMethodClient, times(3)).chatPostMessage(any(ChatPostMessageRequest.class));
    }

    @Test
    public void testSendMessageToChannelsAndEmails() throws SlackApiException, IOException {
        Set<String> recipients = new HashSet<>(Arrays.asList("channel1", "test@example.com", "channel2"));
        String message = "test slack message";

        // Success response for channel messages
        ChatPostMessageResponse channelResponse = mock(ChatPostMessageResponse.class);
        when(channelResponse.isOk()).thenReturn(true);

        // Email lookup response
        UsersLookupByEmailResponse emailResponse = mock(UsersLookupByEmailResponse.class);
        when(emailResponse.isOk()).thenReturn(true);
        User user = new User();
        user.setId("U123456");
        when(emailResponse.getUser()).thenReturn(user);

        MethodsClient slackMethodClient = mock(MethodsClient.class);
        when(slackMethodClient.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenReturn(channelResponse);
        when(slackMethodClient.usersLookupByEmail(any(RequestConfigurator.class)))
                .thenReturn(emailResponse);

        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString()))
                .thenReturn("token-1".toCharArray());

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertTrue(athenzSlackClient.sendMessage(recipients, message));

        // Verify email lookup was called once
        verify(slackMethodClient, times(1)).usersLookupByEmail(any(RequestConfigurator.class));
        // Verify message was sent three times (2 channels + 1 user)
        verify(slackMethodClient, times(3)).chatPostMessage(any(ChatPostMessageRequest.class));

        // Verify the correct destinations were used
        ArgumentCaptor<ChatPostMessageRequest> requestCaptor = ArgumentCaptor.forClass(ChatPostMessageRequest.class);
        verify(slackMethodClient, times(3)).chatPostMessage(requestCaptor.capture());
        List<ChatPostMessageRequest> capturedRequests = requestCaptor.getAllValues();
        Set<String> destinations = capturedRequests.stream()
                .map(ChatPostMessageRequest::getChannel)
                .collect(Collectors.toSet());
        assertTrue(destinations.containsAll(Arrays.asList("channel1", "U123456", "channel2")));
    }

    @Test
    public void testSendMessageWithFailedEmailLookup() throws SlackApiException, IOException {
        Set<String> recipients = new HashSet<>(Arrays.asList("channel1", "invalid@example.com"));
        String message = "test slack message";

        // Success response for channel message
        ChatPostMessageResponse channelResponse = mock(ChatPostMessageResponse.class);
        when(channelResponse.isOk()).thenReturn(true);

        // Failed email lookup response
        UsersLookupByEmailResponse emailResponse = mock(UsersLookupByEmailResponse.class);
        when(emailResponse.isOk()).thenReturn(false);
        when(emailResponse.getError()).thenReturn("users_not_found");

        MethodsClient slackMethodClient = mock(MethodsClient.class);
        when(slackMethodClient.chatPostMessage(any(ChatPostMessageRequest.class)))
                .thenReturn(channelResponse);
        when(slackMethodClient.usersLookupByEmail(any(RequestConfigurator.class)))
                .thenReturn(emailResponse);

        Slack slackClient = mock(Slack.class);
        when(slackClient.methods(anyString())).thenReturn(slackMethodClient);

        PrivateKeyStore privateKeyStore = mock(PrivateKeyStore.class);
        when(privateKeyStore.getSecret(anyString(), anyString(), anyString()))
                .thenReturn("token-1".toCharArray());

        AthenzSlackClient athenzSlackClient = new AthenzSlackClient(privateKeyStore, slackClient);
        assertFalse(athenzSlackClient.sendMessage(recipients, message));

        // Verify email lookup was attempted
        verify(slackMethodClient, times(1)).usersLookupByEmail(any(RequestConfigurator.class));
        // Verify message was sent only to the channel
        verify(slackMethodClient, times(1)).chatPostMessage(any(ChatPostMessageRequest.class));

        // Verify the correct destination was used
        ArgumentCaptor<ChatPostMessageRequest> requestCaptor = ArgumentCaptor.forClass(ChatPostMessageRequest.class);
        verify(slackMethodClient, times(1)).chatPostMessage(requestCaptor.capture());
        assertEquals("channel1", requestCaptor.getValue().getChannel());
    }
}