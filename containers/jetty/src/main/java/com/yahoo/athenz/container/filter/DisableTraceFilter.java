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

/*
 * Servlet filter that blocks HTTP TRACE and TRACK methods by returning
 * 405 Method Not Allowed.
 *
 * CVE-2004-2320, CVE-2010-0386, CVE-2003-1567: TRACE/TRACK methods can be
 * exploited for cross-site tracing (XST) attacks. This filter is registered
 * on the root ServletContextHandler in AthenzJettyContainer so it covers all
 * paths, including those outside any webapp context.
 *
 * Enabled via system property {@code athenz.disable_trace_track=true}
 */

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class DisableTraceFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(DisableTraceFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        LOGGER.info("DisableTraceFilter initialized - TRACE/TRACK methods will be blocked");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String method = request.getMethod();
        if ("TRACE".equalsIgnoreCase(method) || "TRACK".equalsIgnoreCase(method)) {
            LOGGER.debug("Blocked {} request to {}", method, request.getRequestURI());
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }
}
