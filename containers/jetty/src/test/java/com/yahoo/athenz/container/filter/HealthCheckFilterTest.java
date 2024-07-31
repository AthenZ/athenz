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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.container.AthenzConsts;

public class HealthCheckFilterTest {

    FilterConfig filterConfig = null;
    
    @BeforeClass
    public void setupFilterConfig () {
        
        filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_PATH))
            .thenReturn("/tmp/var/athenz_test");
    }
    
    private static class HealthcheckFilterChain implements FilterChain {

        @Override
        public void doFilter(ServletRequest arg0, ServletResponse arg1) {
        }
    }

    @Test
    public void testNoFilterPath() {
        FilterConfig filterConfig1 = mock(FilterConfig.class);
        when(filterConfig1.getInitParameter(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_PATH))
            .thenReturn(null);

        HealthCheckFilter filter = new HealthCheckFilter();
        assertNotNull(filter);
        filter.init(filterConfig1);
        filter.destroy();
    }

    @Test
    public void testEmptyCheckUriList() {

        HealthCheckFilter filter = new HealthCheckFilter();
        assertNotNull(filter);

        System.setProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST, "");

        filter.init(filterConfig);
        filter.destroy();
    }

    @Test
    public void testEmptyCheckUriListChainFilter() {

        HealthCheckFilter filter = new HealthCheckFilter();
        assertNotNull(filter);

        System.setProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST, "");

        filter.init(filterConfig);

        HealthcheckFilterChain chain = new HealthcheckFilterChain();
        try {
            filter.doFilter(null, null, chain);
        } catch (Exception ex) {
            fail();
        }

        filter.destroy();
    }

    @Test
    public void testCheckEnabledSingleUri() {
        
        HealthCheckFilter filter = new HealthCheckFilter();
        assertNotNull(filter);
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST, "/status.html");

        filter.init(filterConfig);

        createFile("/tmp/var/athenz_test/status.html");
        
        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/status.html");
        
        MockHttpServletResponse response =  new MockHttpServletResponse();
        
        HealthcheckFilterChain chain = new HealthcheckFilterChain();
        
        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
        
        filter.destroy();
        deleteFile("/tmp/var/athenz_test/status.html");
    }
    
    @Test
    public void testCheckEnabledMultipleUri() {
        
        HealthCheckFilter filter = new HealthCheckFilter();
        assertNotNull(filter);
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST, "/status.html,/status");

        filter.init(filterConfig);

        createFile("/tmp/var/athenz_test/status");
        
        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/status");
        
        MockHttpServletResponse response =  new MockHttpServletResponse();
        
        HealthcheckFilterChain chain = new HealthcheckFilterChain();
        
        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
        
        filter.destroy();
        deleteFile("/tmp/var/athenz_test/status");
    }
    
    @Test
    public void testCheckEnabledNoFile() {
        
        HealthCheckFilter filter = new HealthCheckFilter();
        assertNotNull(filter);
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST, "/status.html");

        filter.init(filterConfig);

        deleteFile("/tmp/var/athenz_test/status.html");
        
        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/status.html");
        
        MockHttpServletResponse response =  new MockHttpServletResponse();
        
        HealthcheckFilterChain chain = new HealthcheckFilterChain();
        
        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 404);
        
        filter.destroy();
    }
    
    private void createFile(String filename) {
        try {
            Path pathToFile = Paths.get(filename);
            Files.createDirectories(pathToFile.getParent());
            Files.createFile(pathToFile);
        } catch (IOException ignored) {
        }
    }

    private void deleteFile(String filename) {
        try {
            Path pathToFile = Paths.get(filename);
            Files.delete(pathToFile);
        } catch (IOException ignored) {
        }
    }
}