package com.yahoo.athenz.common.messaging.pulsar;

import static com.yahoo.athenz.common.messaging.pulsar.PulsarChangePublisherTest.getPulsarProducer;
import static com.yahoo.athenz.common.messaging.pulsar.PulsarFactory.*;
import static com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.PROP_ATHENZ_PULSAR_CLIENT_CLASS;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class PulsarFactoryTest {

    @BeforeMethod
    public void init() {
        System.setProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS, "com.yahoo.athenz.common.messaging.pulsar.MockAthenzPulsarClient");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS);
    }

    @Test
    public void test_publisher_creation_no_service() {
        PulsarFactory<DomainChangeMessage> factory = new PulsarFactory<>();
        try {
            factory.create(null, null);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid pulsar service url");
        }
    }

    @Test
    public void test_publisher_creation_no_topic() {
        System.setProperty(PROP_MESSAGING_CLI_SERVICE_URL, "some-service");
        PulsarFactory<DomainChangeMessage> factory = new PulsarFactory<>();
        try {
            factory.create(null, null);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid settings configured");
        }
        System.clearProperty(PROP_MESSAGING_CLI_SERVICE_URL);
    }

    @Test
    public void test_publisher_creation_with_topic_and_service() {
        System.setProperty(PROP_MESSAGING_CLI_SERVICE_URL, "some-service");
        System.setProperty(PROP_MESSAGING_CLI_CERT_PATH, "cert");
        System.setProperty(PROP_MESSAGING_CLI_KEY_PATH, "key");
        System.setProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH, "trust");

        PulsarFactory<DomainChangeMessage> factory = new PulsarFactory<>();
        PulsarChangePublisher<DomainChangeMessage> publisher = (PulsarChangePublisher<DomainChangeMessage>) factory.create(null, "topic");
        publisher.publish(new DomainChangeMessage());
        assertNotNull(getPulsarProducer(publisher));

        System.clearProperty(PROP_MESSAGING_CLI_SERVICE_URL);
        System.clearProperty(PROP_MESSAGING_CLI_CERT_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_KEY_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH);
    }
}
