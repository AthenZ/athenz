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
package com.yahoo.athenz.common.filter.impl;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AthenzZTSQoSFilterTest {

    private static class QoSFilterChain implements FilterChain {
        @Override
        public void doFilter(ServletRequest request, ServletResponse servletResponse) {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.setStatus(200);
        }
    }

    @Test
    public void testAthenzQoSFilterInitCerts() {

        final String maxRequest = "100";

        AthenzZTSQoSFilter filter = new AthenzZTSQoSFilter();
        assertNotNull(filter);

        FilterConfig filterConfig = Mockito.mock(FilterConfig.class);
        Mockito.when(filterConfig.getInitParameter("maxRequests")).thenReturn(maxRequest);
        Mockito.when(filterConfig.getInitParameter("certRequests")).thenReturn("true");
        filter.init(filterConfig);
        assertTrue(filter.getCertRequestConfig());

        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI("/zts/v1/instance");

        MockHttpServletResponse response =  new MockHttpServletResponse();
        QoSFilterChain chain = new QoSFilterChain();

        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
        assertEquals(filter.getMaxRequests(), Integer.valueOf(maxRequest).intValue());
    }

    @Test
    public void testAthenzQoSFilterInitNonCerts() {

        final String maxRequest = "100";

        AthenzZTSQoSFilter filter = new AthenzZTSQoSFilter();
        assertNotNull(filter);

        FilterConfig filterConfig = Mockito.mock(FilterConfig.class);
        Mockito.when(filterConfig.getInitParameter("maxRequests")).thenReturn(maxRequest);
        Mockito.when(filterConfig.getInitParameter("certRequests")).thenReturn("false");
        filter.init(filterConfig);
        assertFalse(filter.getCertRequestConfig());

        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI("/zts/v1/oauth2/token");

        MockHttpServletResponse response =  new MockHttpServletResponse();
        QoSFilterChain chain = new QoSFilterChain();

        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
        assertEquals(filter.getMaxRequests(), Integer.valueOf(maxRequest).intValue());
    }

    @Test
    public void testAthenzQoSFilterInitCertRequestNonCertConfig() {

        final String maxRequest = "100";

        AthenzZTSQoSFilter filter = new AthenzZTSQoSFilter();
        assertNotNull(filter);

        FilterConfig filterConfig = Mockito.mock(FilterConfig.class);
        Mockito.when(filterConfig.getInitParameter("maxRequests")).thenReturn(maxRequest);
        Mockito.when(filterConfig.getInitParameter("certRequests")).thenReturn("false");
        filter.init(filterConfig);
        assertFalse(filter.getCertRequestConfig());

        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI("/zts/v1/instance");

        MockHttpServletResponse response =  new MockHttpServletResponse();
        QoSFilterChain chain = new QoSFilterChain();

        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
        assertEquals(filter.getMaxRequests(), Integer.valueOf(maxRequest).intValue());
    }

    @Test
    public void testAthenzQoSFilterInitNoAttr() {

        final String maxRequest = "100";

        AthenzZTSQoSFilter filter = new AthenzZTSQoSFilter();
        assertNotNull(filter);

        FilterConfig filterConfig = Mockito.mock(FilterConfig.class);
        Mockito.when(filterConfig.getInitParameter("maxRequests")).thenReturn(maxRequest);
        filter.init(filterConfig);
        assertFalse(filter.getCertRequestConfig());
    }

    @DataProvider
    public Object[][] httpRequests() {

        //  @Path("/instance/{provider}/{domain}/{service}/{instanceId}")
        //  @Path("/instance/{domain}/{service}/refresh")
        //  @Path("/instance")
        //  @Path("/domain/{domainName}/role/{roleName}/token") (deprecated rolecert api)
        //  @Path("/rolecert")
        //  @Path("/sshcert")

        return new Object[][]{
                {"GET", "/zts/v1/token", false},
                {"POST", "/zts/v1/instance", true},
                {"POST", "/zts/v1/instance/aws/athenz/api/001", true},
                {"POST", "/zts/v1/instance/athenz/api/refresh", true},
                {"POST", "/zts/v1/instance/something/new", true},
                {"GET", "/zts/v1/instance", false},
                {"GET", "/zts/v1/instance/aws/athenz/api/001", false},
                {"POST", "/zts/v1/rolecert", true},
                {"POST", "/zts/v1/rolecert/new", true},
                {"GET", "/zts/v1/rolecert", false},
                {"POST", "/zts/v1/sshcert", true},
                {"POST", "/zts/v1/sshcert/new", true},
                {"POST", "/zts/v1/newcert", false},
                {"GET", "/zts/v1/sshcert", false},
                {"POST", "/zts/v1/domain/athenz/role/admin/token", true},
                {"POST", "/zts/v1/domain/athenz/role/admin/creds", false},
                {"POST", "/zts/v1/access/athenz/role/admin/token", false},
                {"GET", "/zts/v1/domain/athenz/role/admin/token", false},
        };
    }

    @Test(dataProvider = "httpRequests")
    public void testIsCertRequest(final String method, final String uri, boolean certRequest) {

        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod(method);
        request.setRequestURI(uri);

        AthenzZTSQoSFilter filter = new AthenzZTSQoSFilter();
        assertEquals(filter.isCertRequest(request), certRequest);
    }
}
