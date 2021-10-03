package com.yahoo.athenz.common.messaging.pulsar;

import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.TlsConfig;
import org.apache.pulsar.client.api.Producer;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.lang.reflect.Field;

import static com.yahoo.athenz.common.messaging.pulsar.PulsarFactory.PROP_MESSAGING_CLI_SERVICE_URL;
import static com.yahoo.athenz.common.messaging.pulsar.PulsarFactory.serviceUrl;
import static com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.PROP_ATHENZ_PULSAR_CLIENT_CLASS;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class PulsarChangePublisherTest {

    @BeforeMethod
    public void init() {
        System.setProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS, "com.yahoo.athenz.common.messaging.pulsar.MockAthenzPulsarClient");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS);
    }

    @Test
    public void test_publisher_creation_no_topic_no_broker() {
        PulsarChangePublisher<DomainChangeMessage> publisher =
            new PulsarChangePublisher<>(null, null, new TlsConfig("cert", "key", "trust"));
        assertNull(getPulsarProducer(publisher));
        publisher = new PulsarChangePublisher<>(null, "topic", new TlsConfig("cert", "key", "trust"));
        assertNull(getPulsarProducer(publisher));

    }

    @Test
    public void test_publisher_creation_with_topic_and_broker() {
        System.setProperty(PROP_MESSAGING_CLI_SERVICE_URL, "some-broker");
        PulsarChangePublisher<DomainChangeMessage> publisher = new PulsarChangePublisher<>(serviceUrl(), "some-topic", new TlsConfig("cert", "key", "trust"));
        publisher.publish(new DomainChangeMessage());
        assertNotNull(getPulsarProducer(publisher));
        System.clearProperty(PROP_MESSAGING_CLI_SERVICE_URL);
    }

    /**
     * Since pulsarProducer is private member, and not exposes outside,
     * load it in reflection for better assertion.
     */
    static Producer getPulsarProducer(PulsarChangePublisher<DomainChangeMessage> publisher) {
        final Field privateProducer;
        try {
            privateProducer = publisher.getClass().getDeclaredField("producer");
            privateProducer.setAccessible(true);
            return (Producer) privateProducer.get(publisher);
        } catch (final NoSuchFieldException | IllegalAccessException ignored) { }
        throw new AssertionError("Failed to retrieve pulsarProducer from PulsarChangePublisher<DomainChangeMessage>");
    }

}