package com.yahoo.athenz.common.filter.impl;

import com.yahoo.athenz.common.metrics.Metric;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class NoOpRateLimitTest {

    @Test
    public void testNoOpRateLimitFactory() {
        NoOpRateLimitFactory noOpRateLimitFactory = new NoOpRateLimitFactory();
        assertTrue(noOpRateLimitFactory.create() instanceof NoOpRateLimit);
    }

    @Test
    public void testNoOpRateLimit() {
        NoOpRateLimitFactory noOpRateLimitFactory = new NoOpRateLimitFactory();
        Metric metric = Mockito.mock(Metric.class);
        assertFalse(noOpRateLimitFactory.create().filter(new MockHttpServletRequest(), new MockHttpServletResponse()));
        assertFalse(noOpRateLimitFactory.create().filter(new MockHttpServletRequest(), new MockHttpServletResponse(), metric));
    }
}
