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
import org.apache.pulsar.client.api.SubscriptionType;
import org.apache.pulsar.client.impl.PulsarClientImpl;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;

import static com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.*;
import static org.testng.Assert.assertNotNull;

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
    public void test_producer_creation() {
        Producer<byte[]> producer = AthenzPulsarClient.createProducer("service", "topic", tlsConfig());
        assertNotNull(producer);
        PulsarClientImpl pulsarClient = AthenzPulsarClient.createPulsarClient("service", tlsConfig());
        producer = AthenzPulsarClient.createProducer(pulsarClient, defaultProducerConfig("topic"));
        assertNotNull(producer);
    }

    @Test
    public void test_consumer_creation() {
        Consumer<byte[]> consumer = AthenzPulsarClient.createConsumer("service", Collections.singleton("topic"), "subs", SubscriptionType.Exclusive, tlsConfig());
        assertNotNull(consumer);
        PulsarClientImpl pulsarClient = AthenzPulsarClient.createPulsarClient("service", tlsConfig());
        consumer = AthenzPulsarClient.createConsumer(pulsarClient, defaultConsumerConfig(Collections.singleton("topic"), "subs", SubscriptionType.Exclusive));
        assertNotNull(consumer);
    }

    private AthenzPulsarClient.TlsConfig tlsConfig() {
        return new AthenzPulsarClient.TlsConfig("cert", "key", "truststore");
    }
}
