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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.messaging.ChangeSubscriber;
import com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient;
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Message;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.api.SubscriptionType;
import org.apache.pulsar.client.impl.PulsarClientImpl;
import org.apache.pulsar.client.impl.conf.ConsumerConfigurationData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient.defaultConsumerConfig;

public class PulsarChangeSubscriber<T> implements ChangeSubscriber<T> {

  public static final String PROP_MESSAGING_CLI_CONSUMER_TO_SEC = "athenz.messaging_cli.consumer.timeout_sec";

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  
  private final PulsarClientImpl pulsarClient;
  private final Consumer<byte[]> consumer;
  protected java.util.function.Consumer<T> processor;
  protected Class<T> valueType;
  private boolean closed = false;
  private Thread subscriberThread;
  private final int rcvMsgTimeout;

  public PulsarChangeSubscriber(String serviceUrl,
                                String topicName,
                                String subscriptionName,
                                SubscriptionType subscriptionType,
                                AthenzPulsarClient.TlsConfig tlsConfig) {

    ConsumerConfigurationData<byte[]> consumerConfiguration = defaultConsumerConfig(Collections.singleton(topicName), subscriptionName, subscriptionType);
    pulsarClient = AthenzPulsarClient.createPulsarClient(serviceUrl, tlsConfig);
    consumer = AthenzPulsarClient.createConsumer(pulsarClient, consumerConfiguration);
    rcvMsgTimeout = Integer.parseInt(System.getProperty(PROP_MESSAGING_CLI_CONSUMER_TO_SEC, "1"));

    LOG.debug("created publisher: {}, pulsarConsumer: {}", this.getClass(), consumer);
  }

  @Override
  public void init(java.util.function.Consumer<T> processor, Class<T> valueType) {
    this.processor = processor;
    this.valueType = valueType;
  }

  @Override
  public void run() {
    subscriberThread = Thread.currentThread();
    while (!closed) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("looping over the consumer receive method");
      }
      try {
        Message<byte[]> msg = consumer.receive(rcvMsgTimeout, TimeUnit.SECONDS);
        if (msg != null) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("received message: {}", new String(msg.getData()));
          }
          
          T message = OBJECT_MAPPER.readValue(msg.getData(), valueType);
          processor.accept(message);
          consumer.acknowledge(msg);
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
      consumer.close();
      pulsarClient.shutdown();
    } catch (PulsarClientException e) {
      LOG.error("Got exception while closing pulsar consumer: {}", e.getMessage(), e);
    }
  }
}
