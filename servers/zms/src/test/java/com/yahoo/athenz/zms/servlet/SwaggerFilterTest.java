/*
 *
 *  * Copyright 2020 Verizon Media
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

package com.yahoo.athenz.zms.servlet;

import com.yahoo.athenz.zms.ResourceContext;
import com.yahoo.athenz.zms.ResourceError;
import com.yahoo.athenz.zms.ZMSHandler;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.Mockito.times;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

public class SwaggerFilterTest {

    private static final String MOCKCLIENTADDR = "10.11.12.13";

    @Mock
    private HttpServletRequest mockServletRequest;

    @Mock
    private HttpServletResponse mockServletResponse;

    @Mock
    private FilterChain filterChain;

    @Mock
    private FilterConfig filterConfig;

    @Mock
    private ZMSHandler zmsHandler;

    @Mock
    private ResourceContext resourceContext;

    @BeforeClass
    public void setupClass() {
        MockitoAnnotations.openMocks(this);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        Mockito.when(mockServletRequest.getMethod()).thenReturn("GET");
        Mockito.when(mockServletRequest.getRequestURI()).thenReturn("/v1/api/openapi.yaml");
        Mockito.when(zmsHandler.newResourceContext(any(), any(), anyString())).thenReturn(resourceContext);
    }

    @Test
    public void testDoFilter() throws IOException, ServletException {
        SwaggerFilter swaggerFilter = new SwaggerFilter(zmsHandler);
        swaggerFilter.init(filterConfig);
        swaggerFilter.doFilter(mockServletRequest, mockServletResponse, filterChain);
    }

    @Test
    public void testDoFilterFailAuth() throws IOException, ServletException {
        Mockito.doThrow(new com.yahoo.athenz.zms.ResourceException(401,
                new ResourceError().code(401).message("Unauthenticated"))).when(resourceContext).authenticate();

        SwaggerFilter swaggerFilter = new SwaggerFilter(zmsHandler);
        swaggerFilter.init(filterConfig);
        swaggerFilter.doFilter(mockServletRequest, mockServletResponse, filterChain);
        Mockito.verify(mockServletResponse, times(1)).sendError(401);
    }
}
