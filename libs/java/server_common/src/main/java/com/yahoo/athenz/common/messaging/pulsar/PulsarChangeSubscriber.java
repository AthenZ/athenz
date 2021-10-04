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
import com.yahoo.athenz.common.messaging.pulsar.client.ConsumerWrapper;
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

  protected ConsumerWrapper<byte[]> consumerWrapper;
  protected java.util.function.Consumer<T> processor;
  protected Class<T> valueType;
  private boolean closed = false;
  private Thread subscriberThread;

  public PulsarChangeSubscriber(String serviceUrl,
                                String topicName,
                                String subscriptionName,
                                SubscriptionType subscriptionType,
                                AthenzPulsarClient.TlsConfig tlsConfig) {
    consumerWrapper = AthenzPulsarClient.createConsumer(serviceUrl,
        Collections.singleton(topicName),
        subscriptionName,
        subscriptionType,
        tlsConfig
    );
    LOG.debug("created publisher: {}, pulsarConsumer: {}", this.getClass(), consumerWrapper);
  }

  @Override
  public void init(java.util.function.Consumer<T> processor, Class<T> valueType) {
    this.processor = processor;
    this.valueType = valueType;

    subscriberThread = new Thread(this::subscriberTask);
    subscriberThread.setName("pulsar-" + consumerWrapper.getConsumer().getTopic());
    subscriberThread.setDaemon(true);
    subscriberThread.start();
  }

  private void subscriberTask() {
    while (!closed) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("looping over the consumer receive method");
      }
      try {
        Message<byte[]> msg = this.consumerWrapper.getConsumer().receive(1, TimeUnit.SECONDS);
        if (msg != null) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("received message: {}", new String(msg.getData()));
          }
          
          T message = OBJECT_MAPPER.readValue(msg.getData(), valueType);
          processor.accept(message);
          consumerWrapper.getConsumer().acknowledge(msg);
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
      consumerWrapper.getConsumer().close();
      consumerWrapper.getPulsarClient().shutdown();
    } catch (PulsarClientException e) {
      LOG.error("Got exception while closing pulsar consumer: {}", e.getMessage(), e);
    }
  }
}
