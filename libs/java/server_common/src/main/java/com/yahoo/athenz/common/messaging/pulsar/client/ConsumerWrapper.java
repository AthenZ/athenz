package com.yahoo.athenz.common.messaging.pulsar.client;

import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.PulsarClient;
import org.apache.pulsar.client.impl.PulsarClientImpl;

public class ConsumerWrapper<T> {
  private final Consumer<T> consumer;
  private final PulsarClient pulsarClient;

  public ConsumerWrapper(Consumer<T> consumer, PulsarClientImpl pulsarClient) {
    this.consumer = consumer;
    this.pulsarClient = pulsarClient;
  }

  public Consumer<T> getConsumer() {
    return consumer;
  }

  public PulsarClient getPulsarClient() {
    return pulsarClient;
  }
}
