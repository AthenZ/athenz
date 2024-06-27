package com.yahoo.athenz.common.metrics.impl;
import static org.testng.Assert.*;
import com.yahoo.athenz.common.metrics.Metric;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
public class OpenTelemetryMetricFactoryTest {
  private OpenTelemetryMetricFactory factory;

  @BeforeMethod
  public void setUp() {
    factory = new OpenTelemetryMetricFactory();
  }

  @Test
  public void testCreate() {
    Metric metric = factory.create();
    assertNotNull(metric);
    assertTrue(metric instanceof OpenTelemetryMetric);
  }
}
