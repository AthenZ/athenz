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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Producer;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.api.Schema;
import org.apache.pulsar.client.impl.MessageImpl;
import org.apache.pulsar.client.impl.PulsarClientImpl;
import org.apache.pulsar.client.impl.conf.ClientConfigurationData;
import org.apache.pulsar.client.impl.conf.ConsumerConfigurationData;
import org.apache.pulsar.client.impl.conf.ProducerConfigurationData;
import org.apache.pulsar.common.api.proto.MessageMetadata;
import org.apache.pulsar.common.util.FutureUtil;
import org.mockito.Mockito;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.fail;

public class MockAthenzPulsarClient extends AthenzPulsarClient {

    protected PulsarClientImpl getPulsarClient(String serviceUrl, ClientConfigurationData config) {
        try {
            CompletableFuture asyncProducerResult = null;
            if (serviceUrl == null || serviceUrl.isEmpty()) {
                asyncProducerResult = FutureUtil.failedFuture(new PulsarClientException.InvalidConfigurationException("Producer configuration undefined"));
            }
            PulsarClientImpl pulsarClient = Mockito.mock(PulsarClientImpl.class);
            Producer producer = Mockito.mock(Producer.class);
            Consumer consumer = Mockito.mock(Consumer.class);

            MessageMetadata meta = new MessageMetadata();
            DomainChangeMessage roleChange = new DomainChangeMessage()
                .setDomainName("domain")
                .setObjectType(DomainChangeMessage.ObjectType.ROLE)
                .setApiName("putRole")
                .setObjectName("role1");
            MessageImpl<byte[]> msg = MessageImpl.create(meta, ByteBuffer.wrap(new ObjectMapper().writeValueAsBytes(roleChange)), Schema.BYTES, null);

            Mockito.when(consumer.receive(1, TimeUnit.SECONDS))
                .thenReturn(msg);
            CompletableFuture finalAsyncProducerResult = asyncProducerResult;
            Mockito.when(pulsarClient.createProducerAsync(any(ProducerConfigurationData.class), any(Schema.class)))
                .thenAnswer(invocation -> {
                    if (serviceUrl != null) {
                        return ((ProducerConfigurationData) invocation.getArgument(0)).getTopicName() == null ? finalAsyncProducerResult : CompletableFuture.completedFuture(producer);
                    }
                    return finalAsyncProducerResult;
                });

            Mockito.when(pulsarClient.subscribeAsync(any(ConsumerConfigurationData.class), any(Schema.class), any()))
                .thenReturn(CompletableFuture.completedFuture(consumer));

            return pulsarClient;
        } catch (Exception e) {
            fail();
        }
        return null;
    }
    
}