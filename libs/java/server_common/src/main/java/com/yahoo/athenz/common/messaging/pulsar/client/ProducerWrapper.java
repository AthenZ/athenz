package com.yahoo.athenz.common.messaging.pulsar.client;

import org.apache.pulsar.client.api.Producer;
import org.apache.pulsar.client.impl.PulsarClientImpl;

public class ProducerWrapper<T> {
  
  private final PulsarClientImpl pulsarClient;
  private final Producer<T> producer;

  public ProducerWrapper(Producer<T> producer, PulsarClientImpl pulsarClient) {
    this.producer = producer;
    this.pulsarClient = pulsarClient;
  }

  public Producer<T> getProducer() {
    return producer;
  }

  public PulsarClientImpl getPulsarClient() {
    return pulsarClient;
  }
}
