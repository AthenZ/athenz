package com.yahoo.athenz.common.messaging.pulsar;

import com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient;
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Producer;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.api.Schema;
import org.apache.pulsar.client.impl.PulsarClientImpl;
import org.apache.pulsar.client.impl.conf.ClientConfigurationData;
import org.apache.pulsar.client.impl.conf.ConsumerConfigurationData;
import org.apache.pulsar.client.impl.conf.ProducerConfigurationData;
import org.apache.pulsar.common.util.FutureUtil;
import org.mockito.Mockito;

import java.util.concurrent.CompletableFuture;

import static org.mockito.ArgumentMatchers.any;

public class MockAthenzPulsarClient extends AthenzPulsarClient {

    protected PulsarClientImpl getPulsarClient(String serviceUrl, ClientConfigurationData config) throws PulsarClientException {
        CompletableFuture asyncProducerResult = null;
        if (serviceUrl == null || serviceUrl.isEmpty()) {
            asyncProducerResult = FutureUtil.failedFuture(new PulsarClientException.InvalidConfigurationException("Producer configuration undefined"));
        }
        PulsarClientImpl pulsarClient = Mockito.mock(PulsarClientImpl.class);
        Producer producer = Mockito.mock(Producer.class);
        Consumer consumer = Mockito.mock(Consumer.class);
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
    }
    
}