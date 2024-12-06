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

package com.yahoo.athenz.common.messaging.pulsar.client;

import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Producer;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.api.SubscriptionType;
import org.apache.pulsar.client.impl.PulsarClientImpl;
import org.apache.pulsar.client.impl.conf.ClientConfigurationData;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;

import static com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.*;
import static org.testng.Assert.*;

public class AthenzPulsarClientTest {

    @BeforeMethod
    public void init() {
        System.setProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS, "com.yahoo.athenz.common.messaging.pulsar.client.MockAthenzPulsarClient");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS);
    }

    @Test
    public void testCreateProducer() {
        Producer<byte[]> producer = AthenzPulsarClient.createProducer("service", "topic", tlsConfig());
        assertNotNull(producer);
        PulsarClientImpl pulsarClient = AthenzPulsarClient.createPulsarClient("service", tlsConfig());
        producer = AthenzPulsarClient.createProducer(pulsarClient, defaultProducerConfig("topic"));
        assertNotNull(producer);
    }

    @Test
    public void testCreateProducerFailure() {
        PulsarClientImpl client = Mockito.mock(PulsarClientImpl.class);

        Mockito.when(client.createProducerAsync(Mockito.any(), Mockito.any()))
                .thenThrow(new IllegalArgumentException("invalid configuration"));
        try {
            AthenzPulsarClient.createProducer(client, defaultProducerConfig("topic"));
            fail();
        } catch (IllegalStateException ex) {
            assertTrue(ex.getMessage().contains("failed to create pulsar producer"));
        }
    }

    @Test
    public void testCreateConsumer() {
        Consumer<byte[]> consumer = AthenzPulsarClient.createConsumer("service", Collections.singleton("topic"),
                "subs", SubscriptionType.Exclusive, tlsConfig());
        assertNotNull(consumer);
        PulsarClientImpl pulsarClient = AthenzPulsarClient.createPulsarClient("service", tlsConfig());
        consumer = AthenzPulsarClient.createConsumer(pulsarClient, defaultConsumerConfig(Collections.singleton("topic"),
                "subs", SubscriptionType.Exclusive));
        assertNotNull(consumer);
    }

    @Test
    public void testCreateConsumerFailure() {
        PulsarClientImpl client = Mockito.mock(PulsarClientImpl.class);
        try {
            AthenzPulsarClient.createConsumer(client, defaultConsumerConfig(null,
                    "subs", SubscriptionType.Exclusive));
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("invalid topic configured"));
        }

        Mockito.when(client.subscribeAsync(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenThrow(new IllegalArgumentException("invalid configuration"));
        try {
            AthenzPulsarClient.createConsumer(client, defaultConsumerConfig(Collections.singleton("topic"),
                    "subs", SubscriptionType.Exclusive));
            fail();
        } catch (IllegalStateException ex) {
            assertTrue(ex.getMessage().contains("failed to create pulsar consumer"));
        }
    }

    private AthenzPulsarClient.TlsConfig tlsConfig() {
        return new AthenzPulsarClient.TlsConfig("cert", "key", "truststore");
    }

    @Test
    public void testGetPulsarClient() throws PulsarClientException {
        AthenzPulsarClient client = new AthenzPulsarClient();
        assertNotNull(client.getPulsarClient("https://athenz.io", new ClientConfigurationData()));
    }
}
