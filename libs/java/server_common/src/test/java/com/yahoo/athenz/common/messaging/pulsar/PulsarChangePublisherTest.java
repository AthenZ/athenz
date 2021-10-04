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
import static org.testng.Assert.*;

public class PulsarChangePublisherTest {

    @BeforeMethod
    public void init() {
        System.setProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS, "com.yahoo.athenz.common.messaging.pulsar.client.MockAthenzPulsarClient");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS);
    }

    @Test
    public void test_validate_publisher() {
        try {
            new PulsarChangePublisher<>(null,
                "topic",
                new TlsConfig("cert", "key", "trust"));
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid service configured");
        }
        try {
            new PulsarChangePublisher<>("service-url",
                null,
                new TlsConfig("cert", "key", "trust"));
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid topic configured");
        }
        try {
            new PulsarChangePublisher<>("service-url",
                "topic",
                new TlsConfig(null, "key", "trust"));
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid tls configured");
        }
        try {
            new PulsarChangePublisher<>("service-url",
                "topic",
                null);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid tls configured");
        }
    }

    @Test
    public void test_publisher_creation() {
        System.setProperty(PROP_MESSAGING_CLI_SERVICE_URL, "some-service");
        PulsarChangePublisher<DomainChangeMessage> publisher = new PulsarChangePublisher<>(serviceUrl(), "some-topic", new TlsConfig("cert", "key", "trust"));
        publisher.publish(new DomainChangeMessage());
        publisher.close();
        assertNotNull(getPulsarProducer(publisher));
        System.clearProperty(PROP_MESSAGING_CLI_SERVICE_URL);
    }

    /**
     * Since pulsarProducer is private member, and not exposes outside,
     * load it in reflection for better assertion.
     */
    static <T> Producer<T> getPulsarProducer(PulsarChangePublisher<DomainChangeMessage> publisher) {
        final Field privateProducer;
        try {
            privateProducer = publisher.getClass().getDeclaredField("producer");
            privateProducer.setAccessible(true);
            return (Producer<T>) privateProducer.get(publisher);
        } catch (final NoSuchFieldException | IllegalAccessException ignored) { }
        throw new AssertionError("Failed to retrieve pulsarProducer from PulsarChangePublisher<DomainChangeMessage>");
    }

}