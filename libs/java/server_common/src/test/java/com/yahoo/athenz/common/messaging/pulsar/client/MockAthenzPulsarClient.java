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

    protected PulsarClientImpl getPulsarClient(String serviceUrl, ClientConfigurationData config) throws PulsarClientException {
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
            MessageImpl<byte[]> msg = MessageImpl.create(meta, ByteBuffer.wrap(new ObjectMapper().writeValueAsBytes(roleChange)), Schema.BYTES);

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