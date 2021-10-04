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

import org.apache.pulsar.client.api.Schema;
import org.apache.pulsar.client.api.SubscriptionType;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;

import static com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.PROP_ATHENZ_PULSAR_CLIENT_CLASS;
import static com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.defaultConsumerConfig;
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
        ProducerWrapper<byte[]> producer = AthenzPulsarClient.createProducer("service", "topic", tlsConfig());
        assertNotNull(producer);

        producer = AthenzPulsarClient.createProducer("service", "topic", AthenzPulsarClient.defaultProducerConfig(null), tlsConfig(), Schema.BYTES);
        assertNotNull(producer);
    }

    @Test
    public void test_consumer_creation() {
        ConsumerWrapper<byte[]> consumer = AthenzPulsarClient.createConsumer("service", Collections.singleton("topic"), "subs", SubscriptionType.Exclusive, tlsConfig());
        assertNotNull(consumer);

        consumer = AthenzPulsarClient.createConsumer("service", Collections.singleton("topic"), defaultConsumerConfig(null, "subs", SubscriptionType.Exclusive), tlsConfig(), Schema.BYTES);
        assertNotNull(consumer);
    }

    private AthenzPulsarClient.TlsConfig tlsConfig() {
        return new AthenzPulsarClient.TlsConfig("cert", "key", "truststore");
    }
}
