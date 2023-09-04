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

import org.testng.annotations.Test;

public class RateLimitFilterTest {

    @SuppressWarnings("RedundantThrows")
    private static class RateLimitFilterChain implements FilterChain {
        @Override
        public void doFilter(ServletRequest request, ServletResponse servletResponse) throws IOException, ServletException {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.setStatus(200);
        }
    }

    @Test
    public void testDefaultRateLimitFilter() {
        RateLimitFilter filter = new RateLimitFilter();
        assertNotNull(filter);

        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/");
        
        MockHttpServletResponse response =  new MockHttpServletResponse();
        RateLimitFilterChain chain = new RateLimitFilterChain();

        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
    }
}
