/*
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
 */

package com.yahoo.athenz.container.filter;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

import com.yahoo.athenz.common.filter.RateLimit;
import com.yahoo.athenz.common.filter.RateLimitFactory;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.container.AthenzConsts;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

public class RateLimitFilterTest {

    @AfterMethod
    public void cleanup() {
        System.clearProperty(AthenzConsts.ATHENZ_PROP_RATE_LIMIT_FACTORY_CLASS);
    }

    @SuppressWarnings("RedundantThrows")
    private static class RateLimitFilterChain implements FilterChain {
        boolean invoked = false;

        @Override
        public void doFilter(ServletRequest request, ServletResponse servletResponse) throws IOException, ServletException {
            invoked = true;
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.setStatus(200);
        }
    }

    public static class BlockingRateLimit implements RateLimit {
        @Override
        public boolean filter(ServletRequest servletRequest, ServletResponse servletResponse) {
            return true;
        }

        @Override
        public boolean filter(ServletRequest servletRequest, ServletResponse servletResponse, Metric metric) {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.setStatus(429);
            return true;
        }
    }

    public static class BlockingRateLimitFactory implements RateLimitFactory {
        @Override
        public RateLimit create() {
            return new BlockingRateLimit();
        }
    }

    @Test
    public void testDefaultRateLimitFilter() {
        RateLimitFilter filter = new RateLimitFilter();
        assertNotNull(filter);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/");

        MockHttpServletResponse response = new MockHttpServletResponse();
        RateLimitFilterChain chain = new RateLimitFilterChain();

        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
        assertEquals(chain.invoked, true);
    }

    @Test
    public void testDoFilterRateLimited() {
        System.setProperty(AthenzConsts.ATHENZ_PROP_RATE_LIMIT_FACTORY_CLASS,
                "com.yahoo.athenz.container.filter.RateLimitFilterTest$BlockingRateLimitFactory");

        RateLimitFilter filter = new RateLimitFilter();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/");

        MockHttpServletResponse response = new MockHttpServletResponse();
        RateLimitFilterChain chain = new RateLimitFilterChain();

        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 429);
        assertEquals(chain.invoked, false);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Invalid RateLimitFactory class")
    public void testInvalidRateLimitFactoryClass() {
        System.setProperty(AthenzConsts.ATHENZ_PROP_RATE_LIMIT_FACTORY_CLASS,
                "com.yahoo.athenz.invalid.NonExistentFactory");
        new RateLimitFilter();
    }

    @Test
    public void testInitAndDestroy() {
        RateLimitFilter filter = new RateLimitFilter();
        filter.init(null);
        filter.destroy();
    }
}
