package com.yahoo.athenz.common.messaging.pulsar;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.messaging.ChangePublisher;
import com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient;
import org.apache.pulsar.client.api.Producer;
import org.apache.pulsar.client.api.PulsarClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;

public class PulsarChangePublisher<T> implements ChangePublisher<T> {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  private final Producer<byte[]> producer;

  public PulsarChangePublisher(String serviceUrl, String topicName, AthenzPulsarClient.TlsConfig tlsConfig) {
    producer = AthenzPulsarClient.createProducer(serviceUrl, topicName, tlsConfig);
    LOG.debug("created publisher: {}, producer: {}", this.getClass(), producer);
  }

  @Override
  public void publish(T message) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("producer: {}, publishing message: {}", producer, message);
    }
    try {
      producer.send(OBJECT_MAPPER.writeValueAsBytes(message));
    } catch (PulsarClientException | JsonProcessingException e) {
      LOG.error("Pulsar client was not able to publish message. error: {}", e.getMessage(), e);
    }
  }
}
