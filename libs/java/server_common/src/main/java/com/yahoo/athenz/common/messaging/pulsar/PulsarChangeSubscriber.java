package com.yahoo.athenz.common.messaging.pulsar;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.messaging.ChangeSubscriber;
import com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient;
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Message;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.api.SubscriptionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

public class PulsarChangeSubscriber<T> implements ChangeSubscriber<T> {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  protected Consumer<byte[]> pulsarConsumer;
  protected java.util.function.Consumer<T> processor;
  protected Class<T> valueType;
  private boolean closed = false;
  private Thread subscriberThread;

  public PulsarChangeSubscriber(String serviceUrl,
                                String topicName,
                                String subscriptionName,
                                SubscriptionType subscriptionType,
                                AthenzPulsarClient.TlsConfig tlsConfig) {
    pulsarConsumer = AthenzPulsarClient.createConsumer(serviceUrl,
        Collections.singleton(topicName),
        subscriptionName,
        subscriptionType,
        tlsConfig
    );
    LOG.debug("created publisher: {}, pulsarConsumer: {}", this.getClass(), pulsarConsumer);
  }

  @Override
  public void init(java.util.function.Consumer<T> processor, Class<T> valueType) {
    this.processor = processor;
    this.valueType = valueType;

    subscriberThread = new Thread(this::subscriberTask);
    subscriberThread.setName("pulsar-" + pulsarConsumer.getTopic());
    subscriberThread.setDaemon(true);
    subscriberThread.start();
  }

  private void subscriberTask() {
    while (!closed) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("looping over the consumer receive method");
      }
      try {
        Message<byte[]> msg = this.pulsarConsumer.receive(1, TimeUnit.SECONDS);
        if (msg != null) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("received message: {}", new String(msg.getData()));
          }
          
          T message = OBJECT_MAPPER.readValue(msg.getData(), valueType);
          processor.accept(message);
          pulsarConsumer.acknowledge(msg);
        }
      } catch (Exception e) {
        LOG.error("exception in receiving the message: {}", e.getMessage(), e);
      }
    }
  }
  
  @Override
  public void close() {
    closed = true;
    subscriberThread.interrupt();
    try {
      pulsarConsumer.close();
    } catch (PulsarClientException e) {
      LOG.error("Got exception while closing pulsar consumer: {}", e.getMessage(), e);
    }
  }
}
