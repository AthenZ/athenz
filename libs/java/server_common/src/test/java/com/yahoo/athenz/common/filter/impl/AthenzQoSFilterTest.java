/*
 * Copyright 2018 Oath, Inc.
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
package com.yahoo.athenz.common.filter.impl;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.*;


public class AthenzQoSFilterTest {

    @SuppressWarnings("RedundantThrows")
    private class QosfilterChain implements FilterChain {
        @Override
        public void doFilter(ServletRequest request, ServletResponse servletResponse) throws IOException, ServletException {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.setStatus(200);
        }
    }

    @Test
    public void testDefaultQosFilter() {
        
        String maxRequest = "100";
        String maxRequestParamName = "zts.maxRequests";
        String war = "zts";
        System.setProperty(AthenzQoSFilter.ATHENZ_PROP_QOS_PREFIX + maxRequestParamName, maxRequest);
        System.setProperty(AthenzQoSFilter.ATHENZ_PROP_QOS_PREFIX + war + ".enabled", "true");
        AthenzQoSFilter filter = new AthenzQoSFilter();
        assertNotNull(filter);

        FilterConfig filterConfig = Mockito.mock(FilterConfig.class);
        Mockito.when(filterConfig.getInitParameter(maxRequestParamName)).thenReturn(maxRequest);
        Mockito.when(filterConfig.getInitParameter(AthenzQoSFilter.ATHENZ_PROP_QOS_WAR)).thenReturn(war);
        filter.init(filterConfig);
        

        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/");
        
        MockHttpServletResponse response =  new MockHttpServletResponse();

        QosfilterChain chain = new QosfilterChain();

        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
        
        assertEquals(filter.getMaxRequests(), Integer.valueOf(maxRequest).intValue());
        
        System.setProperty(AthenzQoSFilter.ATHENZ_PROP_QOS_PREFIX + maxRequestParamName, "");

    }

    @Test
    public void testAthenzQoSFilter() {
        String maxRequest = "100";
        String maxRequestParamName = "zts.maxRequests";
        String war = "zts";
        System.setProperty(AthenzQoSFilter.ATHENZ_PROP_QOS_PREFIX + maxRequestParamName, maxRequest);
        System.clearProperty(AthenzQoSFilter.ATHENZ_PROP_QOS_PREFIX + war + ".enabled");
        AthenzQoSFilter filter = new AthenzQoSFilter();
        assertNotNull(filter);

        FilterConfig filterConfig = Mockito.mock(FilterConfig.class);
        Mockito.when(filterConfig.getInitParameter(maxRequestParamName)).thenReturn(maxRequest);
        Mockito.when(filterConfig.getInitParameter(AthenzQoSFilter.ATHENZ_PROP_QOS_WAR)).thenReturn(war);
        filter.init(filterConfig);


        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/");

        MockHttpServletResponse response =  new MockHttpServletResponse();

        QosfilterChain chain = new QosfilterChain();

        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }

        assertEquals(filter.getMaxRequests(), Integer.valueOf(maxRequest).intValue());

        System.setProperty(AthenzQoSFilter.ATHENZ_PROP_QOS_PREFIX + maxRequestParamName, "");
    }

    @Test
    public void testPropertyFilterConfig() {
        AthenzQoSFilter temp = new AthenzQoSFilter();
        AthenzQoSFilter.PropertyFilterConfig propertyFilterConfig = temp.new PropertyFilterConfig(null);
        assertNull(propertyFilterConfig.getFilterName());
        String name  = "test";
        System.setProperty(AthenzQoSFilter.ATHENZ_PROP_QOS_PREFIX + name, "testResult");
        assertEquals(propertyFilterConfig.getInitParameter(name), "testResult");

        assertNull(propertyFilterConfig.getInitParameterNames());
    }
}
