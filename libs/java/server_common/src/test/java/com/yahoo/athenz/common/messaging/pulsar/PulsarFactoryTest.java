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

import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.yahoo.athenz.common.messaging.pulsar.PulsarChangePublisherTest.getPulsarProducer;
import static com.yahoo.athenz.common.messaging.pulsar.PulsarChangeSubscriberTest.getPulsarConsumer;
import static com.yahoo.athenz.common.messaging.pulsar.PulsarFactory.*;
import static com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.PROP_ATHENZ_PULSAR_CLIENT_CLASS;
import static org.testng.Assert.*;

public class PulsarFactoryTest {

    @BeforeMethod
    public void init() {
        System.setProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS, "com.yahoo.athenz.common.messaging.pulsar.client.MockAthenzPulsarClient");
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS);
    }

    @Test
    public void test_publisher_creation_no_service() {
        System.setProperty(PROP_MESSAGING_CLI_CERT_PATH, "cert");
        System.setProperty(PROP_MESSAGING_CLI_KEY_PATH, "key");
        System.setProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH, "trust");

        PulsarFactory<DomainChangeMessage> factory = new PulsarFactory<>();
        try {
            factory.create(null, "topic");
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid pulsar service url");
        }

        System.clearProperty(PROP_MESSAGING_CLI_CERT_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_KEY_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH);
    }

    @Test
    public void test_publisher_creation_no_topic() {
        System.setProperty(PROP_MESSAGING_CLI_SERVICE_URL, "some-service");
        System.setProperty(PROP_MESSAGING_CLI_CERT_PATH, "cert");
        System.setProperty(PROP_MESSAGING_CLI_KEY_PATH, "key");
        System.setProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH, "trust");

        PulsarFactory<DomainChangeMessage> factory = new PulsarFactory<>();
        try {
            factory.create(null, null);
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "invalid topic configured");
        }

        System.clearProperty(PROP_MESSAGING_CLI_CERT_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_KEY_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_SERVICE_URL);
    }

    @Test
    public void test_publisher_creation() {
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

    @Test
    public void test_subscriber_creation_invalid_subscription_type() {
        System.setProperty(PROP_MESSAGING_CLI_SERVICE_URL, "some-service");
        System.setProperty(PROP_MESSAGING_CLI_CERT_PATH, "cert");
        System.setProperty(PROP_MESSAGING_CLI_KEY_PATH, "key");
        System.setProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH, "trust");
        
        try {
            PulsarFactory<DomainChangeMessage> factory = new PulsarFactory<>();
            factory.create(null, "topic", "subscription", "Invalid");
            fail();
        } catch (IllegalArgumentException e) {
            assertEquals(e.getMessage(), "No enum constant org.apache.pulsar.client.api.SubscriptionType.Invalid");
        }

        System.clearProperty(PROP_MESSAGING_CLI_SERVICE_URL);
        System.clearProperty(PROP_MESSAGING_CLI_CERT_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_KEY_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH);
    }

    @Test
    public void test_subscriber_creation() {
        System.setProperty(PROP_MESSAGING_CLI_SERVICE_URL, "some-service");
        System.setProperty(PROP_MESSAGING_CLI_CERT_PATH, "cert");
        System.setProperty(PROP_MESSAGING_CLI_KEY_PATH, "key");
        System.setProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH, "trust");

        PulsarFactory<DomainChangeMessage> factory = new PulsarFactory<>();
        PulsarChangeSubscriber<DomainChangeMessage> subscriber = (PulsarChangeSubscriber<DomainChangeMessage>) factory.create(null, "topic", "subscription", "Exclusive");
        assertNotNull(getPulsarConsumer(subscriber));

        System.clearProperty(PROP_MESSAGING_CLI_SERVICE_URL);
        System.clearProperty(PROP_MESSAGING_CLI_CERT_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_KEY_PATH);
        System.clearProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH);
    }
}
