/*
 *
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
 *
 */

package com.yahoo.athenz.common.messaging.pulsar;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.TlsConfig;
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Message;
import org.apache.pulsar.client.api.SubscriptionType;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static com.yahoo.athenz.common.messaging.pulsar.PulsarFactory.PROP_MESSAGING_CLI_SERVICE_URL;
import static com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.PROP_ATHENZ_PULSAR_CLIENT_CLASS;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.*;

public class PulsarChangeSubscriberTest {

    @BeforeMethod
    public void init() {
        System.setProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS, "com.yahoo.athenz.common.messaging.pulsar.client.MockAthenzPulsarClient");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS);
    }

    @Test
    public void test_validate_subscriber() {
        try {
            new PulsarChangeSubscriber<>("service-url",
                null,
                "subs",
                SubscriptionType.Exclusive,
                new TlsConfig("cert", "key", "trust"));
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid topic configured");
        }
        try {
            new PulsarChangeSubscriber<>(null,
                "topic",
                "subs",
                SubscriptionType.Exclusive,
                new TlsConfig("cert", "key", "trust"));
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid service configured");
        }
        try {
            new PulsarChangeSubscriber<>("service-url",
                "topic",
                null,
                SubscriptionType.Exclusive,
                new TlsConfig("cert", "key", "trust"));
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid subscription name configured");
        }
        try {
            new PulsarChangeSubscriber<>("service-url",
                "topic",
                "subs",
                null,
                new TlsConfig("cert", "key", "trust"));
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid subscription type configured");
        }
        try {
            new PulsarChangeSubscriber<>("service-url",
                "topic",
                "subs",
                SubscriptionType.Exclusive,
                null);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid tls configured");
        }
        try {
            new PulsarChangeSubscriber<>("service-url",
                "topic",
                "subs",
                SubscriptionType.Exclusive,
                new TlsConfig(null, "key", "trust"));
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid tls configured");
        }
    }

    @Test
    public void test_subscriber_creation() {
        System.setProperty(PROP_MESSAGING_CLI_SERVICE_URL, "some-service");
        PulsarChangeSubscriber<DomainChangeMessage> subscriber = new PulsarChangeSubscriber<>("service-url",
            "topic",
            "subs",
            SubscriptionType.Exclusive,
            new TlsConfig("cert", "key", "trust"));
        assertNotNull(getPulsarConsumer(subscriber));
    }

    @Test
    public void test_subscribe_to_mock_msg() throws IOException, InterruptedException {
        System.setProperty(PROP_MESSAGING_CLI_SERVICE_URL, "some-service");
        PulsarChangeSubscriber<DomainChangeMessage> subscriber = new PulsarChangeSubscriber<>("service-url",
            "topic",
            "subs",
            SubscriptionType.Exclusive,
            new TlsConfig("cert", "key", "trust"));
        
        // init subscriber
        subscriber.init(this::assertDomainMessage, DomainChangeMessage.class);

        ExecutorService service = Executors.newSingleThreadExecutor();
        service.submit(subscriber);
        
        Thread.sleep(500);
        subscriber.close();
        Consumer<byte[]> pulsarConsumer = getPulsarConsumer(subscriber);
        assertNotNull(pulsarConsumer);
        ArgumentCaptor<Message<DomainChangeMessage>> messageCapture = ArgumentCaptor.forClass(Message.class);
        verify(pulsarConsumer, Mockito.atLeastOnce()).acknowledge(messageCapture.capture());
        assertDomainMessage(new ObjectMapper().readValue(messageCapture.getValue().getData(), DomainChangeMessage.class));
        System.clearProperty(PROP_MESSAGING_CLI_SERVICE_URL);
    }
    
    private void assertDomainMessage(DomainChangeMessage msg) {
       assertEquals(msg.getDomainName(), "domain");
       assertEquals(msg.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
       assertEquals(msg.getApiName(), "putRole");
       assertEquals(msg.getObjectName(), "role1");
    }

    /**
     * Since pulsarConsumer is private member, and not exposes outside,
     * load it in reflection for better assertion.
     */
    static <T> Consumer<T> getPulsarConsumer(PulsarChangeSubscriber<DomainChangeMessage> subscriber) {
        final Field privateConsumer;
        try {
            privateConsumer = subscriber.getClass().getDeclaredField("consumer");
            privateConsumer.setAccessible(true);
            return (Consumer<T>) privateConsumer.get(subscriber);
        } catch (final NoSuchFieldException | IllegalAccessException ignored) { }
        throw new AssertionError("Failed to retrieve pulsarConsumer from PulsarChangeSubscriber<DomainChangeMessage>");
    }

}