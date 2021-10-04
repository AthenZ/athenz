package com.yahoo.athenz.common.messaging.pulsar;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.messaging.ChangePublisher;
import com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient;
import com.yahoo.athenz.common.messaging.pulsar.client.ProducerWrapper;
import org.apache.pulsar.client.api.PulsarClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;

public class PulsarChangePublisher<T> implements ChangePublisher<T> {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  private final ProducerWrapper<byte[]> producerWrapper;

  public PulsarChangePublisher(String serviceUrl, String topicName, AthenzPulsarClient.TlsConfig tlsConfig) {
    producerWrapper = AthenzPulsarClient.createProducer(serviceUrl, topicName, tlsConfig);
    LOG.debug("created publisher: {}, producer: {}", this.getClass(), producerWrapper);
  }

  @Override
  public void publish(T message) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("producer: {}, publishing message: {}", producerWrapper, message);
    }
    try {
      producerWrapper.getProducer().send(OBJECT_MAPPER.writeValueAsBytes(message));
    } catch (PulsarClientException | JsonProcessingException e) {
      LOG.error("Pulsar client was not able to publish message. error: {}", e.getMessage(), e);
    }
  }

  @Override
  public void close() {
    try {
      producerWrapper.getProducer().close();
      producerWrapper.getPulsarClient().shutdown();
    } catch (PulsarClientException e) {
      LOG.error("Got exception while closing pulsar producer: {}", e.getMessage(), e);
    }
  }
}
