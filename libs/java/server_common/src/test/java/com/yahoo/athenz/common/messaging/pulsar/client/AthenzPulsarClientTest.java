package com.yahoo.athenz.common.messaging.pulsar.client;

import java.util.Collections;

import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Producer;
import org.apache.pulsar.client.api.Schema;
import org.apache.pulsar.client.api.SubscriptionType;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

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
        Producer<byte[]> producer = AthenzPulsarClient.createProducer("service", "topic", tlsConfig());
        assertNotNull(producer);

        producer = AthenzPulsarClient.createProducer("service", "topic", AthenzPulsarClient.defaultProducerConfig(null), tlsConfig(), Schema.BYTES);
        assertNotNull(producer);
    }

    @Test
    public void test_consumer_creation() {
        Consumer<byte[]> consumer = AthenzPulsarClient.createConsumer("service", Collections.singleton("topic"), "subs", SubscriptionType.Exclusive, tlsConfig());
        assertNotNull(consumer);

        consumer = AthenzPulsarClient.createConsumer("service", Collections.singleton("topic"), defaultConsumerConfig(null, "subs", SubscriptionType.Exclusive), tlsConfig(), Schema.BYTES);
        assertNotNull(consumer);
    }

    private AthenzPulsarClient.TlsConfig tlsConfig() {
        return new AthenzPulsarClient.TlsConfig("cert", "key", "truststore");
    }
}
