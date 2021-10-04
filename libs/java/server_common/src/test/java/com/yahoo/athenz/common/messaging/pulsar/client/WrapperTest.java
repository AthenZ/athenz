package com.yahoo.athenz.common.messaging.pulsar.client;

import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class WrapperTest {

  @Test
  public void test_producer_wrapper_creation() {
    ProducerWrapper<byte[]> wrapper = new ProducerWrapper<>(null, null);
    assertNotNull(wrapper);
    assertNull(wrapper.getProducer());
    assertNull(wrapper.getPulsarClient());
  }
  
  @Test
  public void test_consumer_wrapper_creation() {
    ConsumerWrapper<byte[]> wrapper = new ConsumerWrapper<>(null, null);
    assertNotNull(wrapper);
    assertNull(wrapper.getConsumer());
    assertNull(wrapper.getPulsarClient());
  }
}
