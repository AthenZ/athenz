package com.yahoo.athenz.common.filter.impl;

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
        assertFalse(noOpRateLimitFactory.create().filter(new MockHttpServletRequest(), new MockHttpServletResponse()));
    }
}
