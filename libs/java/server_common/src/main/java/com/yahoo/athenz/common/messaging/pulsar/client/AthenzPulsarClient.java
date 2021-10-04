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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

public class AthenzPulsarClient {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
  public static final String PROP_PULSAR_MAX_PENDING_MSGS = "athenz.pulsar.max_pending_msgs";
  public static final String PROP_ATHENZ_PULSAR_CLIENT_CLASS = "athenz.pulsar.pulsar_client_class";
  public static final String PROP_ATHENZ_PULSAR_CLIENT_CLASS_DEFAULT = "com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient";

  public static Producer<byte[]> createProducer(String serviceUrl, String topicName, TlsConfig tlsConfig) {
    ProducerConfigurationData producerConfiguration = defaultProducerConfig(topicName);
    return createProducer(serviceUrl, topicName, producerConfiguration, tlsConfig, Schema.BYTES);
  }

  public static <T> Producer<T> createProducer(String serviceUrl, String topicName, ProducerConfigurationData producerConfiguration, TlsConfig tlsConfig, Schema<T> schema) {
    if (producerConfiguration.getTopicName() == null) {
      producerConfiguration.setTopicName(topicName);
    }
    validateProducer(serviceUrl, producerConfiguration, tlsConfig);
    try {
      ClientConfigurationData config = getClientConfiguration(tlsConfig);
      AthenzPulsarClient athenzPulsarClient = createAthenzPulsarClientInstance();
      PulsarClientImpl pulsarClient = athenzPulsarClient.getPulsarClient(serviceUrl, config);
      return pulsarClient.createProducerAsync(producerConfiguration, schema).get();
    } catch (ExecutionException | PulsarClientException e) {
      LOG.error("Failed to create pulsar producer: {}", e.getMessage());
    } catch (InterruptedException e) {
      LOG.error("Failed to create pulsar producer, thread was interrupt: {}", e.getMessage());
      Thread.currentThread().interrupt();
    }
    return null;
  }

  private static void validateProducer(String serviceUrl, ProducerConfigurationData producerConfiguration, TlsConfig tlsConfig) {
    if (tlsConfig == null || tlsConfig.tlsCertFilePath == null || tlsConfig.tlsKeyFilePath == null || tlsConfig.tlsTrustCertsFilePath == null) {
      throw new IllegalArgumentException("invalid tls configured");
    }
    if (serviceUrl == null || serviceUrl.isEmpty()) {
      throw new IllegalArgumentException("invalid service configured");
    }
    if (producerConfiguration.getTopicName() == null || producerConfiguration.getTopicName().isEmpty()) {
      throw new IllegalArgumentException("invalid topic configured");
    }
  }

  private static ClientConfigurationData getClientConfiguration(TlsConfig tlsConfig) {
    ClientConfigurationData config = new ClientConfigurationData();
    AuthenticationTls authenticationTls = new AuthenticationTls();
    Map<String, String> authParams = new HashMap<>();
    authParams.put("tlsKeyFile", tlsConfig.tlsKeyFilePath);
    authParams.put("tlsCertFile", tlsConfig.tlsCertFilePath);
    authenticationTls.configure(authParams);
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
      instance = (AthenzPulsarClient) Class.forName(pulsarClientClassName).newInstance();
    } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
      throw new ExceptionInInitializerError(e);
    }
    return instance;
  }

  protected PulsarClientImpl getPulsarClient(String serviceUrl, ClientConfigurationData config) throws PulsarClientException {
    config.setServiceUrl(serviceUrl);
    return new PulsarClientImpl(config);
  }

  public static ProducerConfigurationData defaultProducerConfig(String topicName) {
    int maxPendingMessages = Integer.parseInt(System.getProperty(PROP_PULSAR_MAX_PENDING_MSGS, "10000"));
    ProducerConfigurationData producerConfiguration = new ProducerConfigurationData();
    producerConfiguration.setBlockIfQueueFull(true);
    producerConfiguration.setMaxPendingMessages(maxPendingMessages);
    producerConfiguration.setTopicName(topicName);
    return producerConfiguration;
  }

  public static Consumer<byte[]> createConsumer(String serviceUrl, Set<String> topicNames, String subscriptionName, SubscriptionType subscriptionType, TlsConfig tlsConfig) {
    ConsumerConfigurationData<byte[]> consumerConfiguration = defaultConsumerConfig(topicNames, subscriptionName, subscriptionType);
    return createConsumer(serviceUrl, topicNames, consumerConfiguration, tlsConfig, Schema.BYTES);
  }

  public static <T> Consumer<T> createConsumer(String serviceUrl, Set<String> topicNames, ConsumerConfigurationData<T> consumerConfiguration, TlsConfig tlsConfig, Schema<T> schema) {
    if (consumerConfiguration.getTopicNames() == null || consumerConfiguration.getTopicNames().isEmpty()) {
      consumerConfiguration.setTopicNames(topicNames);
    }
    validateConsumer(serviceUrl, consumerConfiguration, tlsConfig);
    try {
      ClientConfigurationData config = getClientConfiguration(tlsConfig);
      AthenzPulsarClient athenzPulsarClient = createAthenzPulsarClientInstance();
      PulsarClientImpl pulsarClient = athenzPulsarClient.getPulsarClient(serviceUrl, config);
      return pulsarClient.subscribeAsync(consumerConfiguration, schema, null).get();
    } catch (ExecutionException | PulsarClientException e) {
      LOG.error("Failed to create pulsar consumer: {}", e.getMessage());
    } catch (InterruptedException e) {
      LOG.error("Failed to create pulsar consumer, thread was interrupt: {}", e.getMessage());
      Thread.currentThread().interrupt();
    }
    return null;
  }

  private static <T> void validateConsumer(String serviceUrl, ConsumerConfigurationData<T> consumerConfiguration, TlsConfig tlsConfig) {
    if (tlsConfig == null || tlsConfig.tlsCertFilePath == null || tlsConfig.tlsKeyFilePath == null || tlsConfig.tlsTrustCertsFilePath == null) {
      throw new IllegalArgumentException("invalid tls configured");
    }
    if (serviceUrl == null || serviceUrl.isEmpty()) {
      throw new IllegalArgumentException("invalid service configured");
    }
    if (consumerConfiguration == null || consumerConfiguration.getSubscriptionType() == null) {
      throw new IllegalArgumentException("invalid subscription type configured");
    }
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

  public static ConsumerConfigurationData<byte[]> defaultConsumerConfig(Set<String> topicNames, String subscriptionName, SubscriptionType subscriptionType) {
    ConsumerConfigurationData<byte[]> conf = new ConsumerConfigurationData<>();
    conf.setSubscriptionType(subscriptionType);
    conf.setSubscriptionName(subscriptionName);
    conf.setTopicNames(topicNames);
    conf.setPoolMessages(true);
    return conf;
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
