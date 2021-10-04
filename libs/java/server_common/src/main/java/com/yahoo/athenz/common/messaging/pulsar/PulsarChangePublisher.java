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
