package com.yahoo.athenz.common.filter.impl;

import com.yahoo.athenz.common.filter.RateLimit;
import com.yahoo.athenz.common.metrics.Metric;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
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

    @Test
    public void testRateLimit() {
        RateLimit rateLimit = (servletRequest, servletResponse) -> false;
        assertFalse(rateLimit.filter(new MockHttpServletRequest(), new MockHttpServletResponse()));
        assertFalse(rateLimit.filter(new MockHttpServletRequest(), new MockHttpServletResponse(), Mockito.mock(Metric.class)));
    }
}
