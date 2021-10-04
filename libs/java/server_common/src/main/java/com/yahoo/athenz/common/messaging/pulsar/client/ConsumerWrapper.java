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
