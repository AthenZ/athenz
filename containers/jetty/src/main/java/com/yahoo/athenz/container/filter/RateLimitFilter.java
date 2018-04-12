/*
 * Copyright 2017 Yahoo Holdings Inc.
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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.common.filter.RateLimit;
import com.yahoo.athenz.common.filter.RateLimitFactory;
import com.yahoo.athenz.container.AthenzConsts;

public class RateLimitFilter implements javax.servlet.Filter {
    private static final Logger LOGGER = LoggerFactory.getLogger(RateLimitFilter.class);

    private RateLimit rateLimit;
    
    public RateLimitFilter() {
        registerRateLimitFilter();
    }
    
    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
        if (rateLimit.filter(servletRequest, servletResponse)) {
            return;
        }
        chain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void init(FilterConfig config) throws ServletException {
    }

    private void registerRateLimitFilter() {
        String ratelimitFactoryClass = System.getProperty(AthenzConsts.ATHENZ_PROP_RATE_LIMIT_FACTORY_CLASS,
                AthenzConsts.ATHENZ_RATE_LIMIT_FACTORY_CLASS);
        RateLimitFactory rateLimitFactory;
        try {
            rateLimitFactory = (RateLimitFactory) Class.forName(ratelimitFactoryClass).newInstance();
            this.rateLimit = rateLimitFactory.create();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Registered rate limit filter: {}", ratelimitFactoryClass);
            }
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid RateLimitFactory class: " + ratelimitFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid RateLimitFactory class");
        }
    }
}
