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

import org.apache.pulsar.client.api.*;
import org.apache.pulsar.client.impl.PulsarClientImpl;
import org.apache.pulsar.client.impl.auth.AuthenticationTls;
import org.apache.pulsar.client.impl.conf.ClientConfigurationData;
import org.apache.pulsar.client.impl.conf.ConsumerConfigurationData;
import org.apache.pulsar.client.impl.conf.ProducerConfigurationData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.Set;
import java.util.concurrent.ExecutionException;

public class AthenzPulsarClient {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
  public static final String PROP_PULSAR_MAX_PENDING_MSGS = "athenz.pulsar.max_pending_msgs";
  public static final String PROP_ATHENZ_PULSAR_CLIENT_CLASS = "athenz.pulsar.pulsar_client_class";
  public static final String PROP_ATHENZ_PULSAR_CLIENT_CLASS_DEFAULT = "com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient";

  public static PulsarClientImpl createPulsarClient(String serviceUrl, TlsConfig tlsConfig) {
    if (tlsConfig == null || tlsConfig.tlsCertFilePath == null || tlsConfig.tlsKeyFilePath == null || tlsConfig.tlsTrustCertsFilePath == null) {
      throw new IllegalArgumentException("invalid tls configured");
    }
    if (serviceUrl == null || serviceUrl.isEmpty()) {
      throw new IllegalArgumentException("invalid service configured");
    }
    try {
      ClientConfigurationData config = getClientConfiguration(tlsConfig);
      AthenzPulsarClient athenzPulsarClient = createAthenzPulsarClientInstance();
      return athenzPulsarClient.getPulsarClient(serviceUrl, config);
    } catch (PulsarClientException e) {
      LOG.error("Failed to create pulsar client: {}", e.getMessage(), e);
    }
    throw new IllegalStateException("failed to create pulsar client");
  }

  public static ProducerConfigurationData defaultProducerConfig(String topicName) {
    int maxPendingMessages = Integer.parseInt(System.getProperty(PROP_PULSAR_MAX_PENDING_MSGS, "10000"));
    ProducerConfigurationData producerConfiguration = new ProducerConfigurationData();
    producerConfiguration.setBlockIfQueueFull(true);
    producerConfiguration.setMaxPendingMessages(maxPendingMessages);
    producerConfiguration.setTopicName(topicName);
    return producerConfiguration;
  }

  public static Producer<byte[]> createProducer(String serviceUrl, String topicName, TlsConfig tlsConfig) {
    ProducerConfigurationData producerConfiguration = defaultProducerConfig(topicName);
    PulsarClientImpl pulsarClient = createPulsarClient(serviceUrl, tlsConfig);
    return createProducer(pulsarClient, producerConfiguration);
  }
  
  public static Producer<byte[]> createProducer(PulsarClientImpl pulsarClient, ProducerConfigurationData producerConfiguration) {
    return createProducer(pulsarClient, producerConfiguration, Schema.BYTES);
  }
  
  public static <T> Producer<T> createProducer(PulsarClientImpl pulsarClient, ProducerConfigurationData producerConfiguration, Schema<T> schema) {
    if (producerConfiguration.getTopicName() == null || producerConfiguration.getTopicName().isEmpty()) {
      throw new IllegalArgumentException("invalid topic configured");
    }
    try {
      return pulsarClient.createProducerAsync(producerConfiguration, schema).get();
    } catch (ExecutionException e) {
      LOG.error("Failed to create pulsar producer: {}", e.getMessage(), e);
    } catch (InterruptedException e) {
      LOG.error("Failed to create pulsar producer, thread was interrupt: {}", e.getMessage(), e);
      Thread.currentThread().interrupt();
    }
    throw new IllegalStateException("failed to create pulsar producer");
  }
  
  private static ClientConfigurationData getClientConfiguration(TlsConfig tlsConfig) {
    ClientConfigurationData config = new ClientConfigurationData();
    AuthenticationTls authenticationTls = new AuthenticationTls(tlsConfig.tlsCertFilePath, tlsConfig.tlsKeyFilePath);
    config.setAuthentication(authenticationTls);
    config.setTlsAllowInsecureConnection(false);
    config.setTlsHostnameVerificationEnable(true);
    config.setTlsTrustCertsFilePath(tlsConfig.tlsTrustCertsFilePath);
    config.setUseTls(true);
    return config;
  }

  private static AthenzPulsarClient createAthenzPulsarClientInstance() {
    AthenzPulsarClient instance;
    String pulsarClientClassName = System.getProperty(PROP_ATHENZ_PULSAR_CLIENT_CLASS, PROP_ATHENZ_PULSAR_CLIENT_CLASS_DEFAULT);
    try {
      instance = (AthenzPulsarClient) Class.forName(pulsarClientClassName).getDeclaredConstructor().newInstance();
    } catch (Exception ex) {
      throw new ExceptionInInitializerError(ex);
    }
    return instance;
  }

  protected PulsarClientImpl getPulsarClient(String serviceUrl, ClientConfigurationData config) throws PulsarClientException {
    config.setServiceUrl(serviceUrl);
    return new PulsarClientImpl(config);
  }

  public static ConsumerConfigurationData<byte[]> defaultConsumerConfig(Set<String> topicNames, String subscriptionName, SubscriptionType subscriptionType) {
    if (subscriptionType == null) {
      throw new IllegalArgumentException("invalid subscription type configured");
    }
    ConsumerConfigurationData<byte[]> conf = new ConsumerConfigurationData<>();
    conf.setSubscriptionType(subscriptionType);
    conf.setSubscriptionName(subscriptionName);
    conf.setTopicNames(topicNames);
    conf.setPoolMessages(true);
    return conf;
  }
  
  public static Consumer<byte[]> createConsumer(String serviceUrl, Set<String> topicNames, String subscriptionName, SubscriptionType subscriptionType, TlsConfig tlsConfig) {
    ConsumerConfigurationData<byte[]> consumerConfiguration = defaultConsumerConfig(topicNames, subscriptionName, subscriptionType);
    PulsarClientImpl pulsarClient = createPulsarClient(serviceUrl, tlsConfig);
    return createConsumer(pulsarClient, consumerConfiguration);
  }

  public static Consumer<byte[]> createConsumer(PulsarClientImpl pulsarClient, ConsumerConfigurationData<byte[]> consumerConfiguration) {
    return createConsumer(pulsarClient, consumerConfiguration, Schema.BYTES);
  }

  public static <T> Consumer<T> createConsumer(PulsarClientImpl pulsarClient, ConsumerConfigurationData<T> consumerConfiguration, Schema<T> schema) {
    validateConsumerConfiguration(consumerConfiguration);
    try {
      return pulsarClient.subscribeAsync(consumerConfiguration, schema, null).get();
    } catch (ExecutionException e) {
      LOG.error("Failed to create pulsar consumer: {}", e.getMessage(), e);
    } catch (InterruptedException e) {
      LOG.error("Failed to create pulsar consumer, thread was interrupt: {}", e.getMessage(), e);
      Thread.currentThread().interrupt();
    }
    throw new IllegalStateException("failed to create pulsar consumer");
  }

  private static <T> void validateConsumerConfiguration(ConsumerConfigurationData<T> consumerConfiguration) {
    if (consumerConfiguration.getSubscriptionName() == null) {
      throw new IllegalArgumentException("invalid subscription name configured");
    }
    if (consumerConfiguration.getTopicNames() == null || consumerConfiguration.getTopicNames().isEmpty()) {
      throw new IllegalArgumentException("invalid topic configured");
    }
    for (String topic : consumerConfiguration.getTopicNames()) {
      if (topic == null) {
        throw new IllegalArgumentException("invalid topic configured");
      }
    }
  }

  public static class TlsConfig {
    String tlsCertFilePath;
    String tlsKeyFilePath;
    String tlsTrustCertsFilePath;

    public TlsConfig(String tlsCertFilePath, String tlsKeyFilePath, String tlsTrustCertsFilePath) {
      this.tlsCertFilePath = tlsCertFilePath;
      this.tlsKeyFilePath = tlsKeyFilePath;
      this.tlsTrustCertsFilePath = tlsTrustCertsFilePath;
    }
  }

}
