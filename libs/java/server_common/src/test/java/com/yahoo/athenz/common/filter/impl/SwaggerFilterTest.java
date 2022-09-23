/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.filter.impl;

import com.yahoo.athenz.common.server.rest.Http;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;

import static com.yahoo.athenz.common.filter.impl.SwaggerFilter.ATHENZ_SWAGGER_REQUIRE_CERT_AUTH;
import static org.mockito.Mockito.times;

public class SwaggerFilterTest {

    @Mock
    private HttpServletRequest mockServletRequest;

    @Mock
    private HttpServletResponse mockServletResponse;

    @Mock
    private FilterChain filterChain;

    @Mock
    private FilterConfig filterConfig;

    @Test
    public void testDoFilterCertAuthEnabledCertNotPresent() throws IOException, ServletException {
        MockitoAnnotations.openMocks(this);

        SwaggerFilter swaggerFilter = new SwaggerFilter();
        Mockito.when(filterConfig.getInitParameter(ATHENZ_SWAGGER_REQUIRE_CERT_AUTH)).thenReturn("true");
        swaggerFilter.init(filterConfig);
        swaggerFilter.doFilter(mockServletRequest, mockServletResponse, filterChain);
        Mockito.verify(mockServletResponse, times(1)).sendError(401);
        swaggerFilter.destroy();
    }

    @Test
    public void testDoFilterCertAuthEnabledCertPresent() throws IOException, ServletException {
        MockitoAnnotations.openMocks(this);

        SwaggerFilter swaggerFilter = new SwaggerFilter();
        Mockito.when(filterConfig.getInitParameter(ATHENZ_SWAGGER_REQUIRE_CERT_AUTH)).thenReturn("true");
        X509Certificate[] certs = new X509Certificate[1];
        certs[0] = Mockito.mock(X509Certificate.class);
        Mockito.when(mockServletRequest.getAttribute(Http.JAVAX_CERT_ATTR)).thenReturn(certs);
        swaggerFilter.init(filterConfig);
        swaggerFilter.doFilter(mockServletRequest, mockServletResponse, filterChain);
        Mockito.verify(mockServletResponse, times(0)).sendError(401);
        swaggerFilter.destroy();
    }

    @Test
    public void testDoFilterCertAuthDisabled() throws IOException, ServletException {
        MockitoAnnotations.openMocks(this);

        SwaggerFilter swaggerFilter = new SwaggerFilter();
        Mockito.when(filterConfig.getInitParameter(ATHENZ_SWAGGER_REQUIRE_CERT_AUTH)).thenReturn("false");
        swaggerFilter.init(filterConfig);
        swaggerFilter.doFilter(mockServletRequest, mockServletResponse, filterChain);
        Mockito.verify(mockServletResponse, times(0)).sendError(401);
        swaggerFilter.destroy();
    }
}
